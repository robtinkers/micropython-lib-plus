# http/client_ish.py

import micropython, socket, select, time

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

OK = const(200)
responses = {OK: "OK"}

_CS_IDLE = const(0)
_CS_REQ_STARTED = const(1)
_CS_REQ_SENT = const(2)

_METHODS_EXPECTING_BODY = ("PATCH", "POST", "PUT")

_IMPORTANT_HEADERS = (
    b"connection",  # required
    b"content-encoding",
    b"content-length",  # required
    b"content-type",
    b"etag",
    b"keep-alive",  # required
    b"location",  # required
    b"retry-after",
    b"transfer-encoding",  # required
    b"www-authenticate",
)

_DECODE_HEAD = const("utf-8")  # micropython doesn't support iso-8859-1
_ENCODE_HEAD = const("utf-8")  # micropython doesn't support iso-8859-1
_DECODE_BODY = const("utf-8")
_ENCODE_BODY = const("utf-8")

_BLANK = const(b"")
_CRLF = const(b"\r\n")

_MISSING = object()  # sentinel

class NormalizedDict(dict):
    
    @classmethod
    def normalize_key(cls, key):
        return key
    
    @classmethod
    def normalize_val(cls, val):
        return val
    
    def __contains__(self, key):
        key = self.normalize_key(key)
        return super().__contains__(key)
    
    def __setitem__(self, key, val):
        key = self.normalize_key(key)
        super().__setitem__(key, val)
    
    def __getitem__(self, key):
        key = self.normalize_key(key)
        val = super().__getitem__(key)
        return self.normalize_val(val)
    
    def __delitem__(self, key):
        key = self.normalize_key(key)
        super().__delitem__(key)

    def set(self, key, val):
        key = self.normalize_key(key)
        super().__setitem__(key, val)
        return key
    
    def set_raw(self, key, val):
        super().__setitem__(key, val)
        return key
    
    def get_raw(self, key, default=None):
        return super().get(key, default)
    
    def get_raw_bytes(self, key, default=None):
        val = self.get_raw(key, _MISSING)
        if val is _MISSING:
            return default
        if isinstance(val, bytes):
            return val
        if isinstance(val, str):
            return val.encode(_ENCODE_HEAD)
        return bytes(val)
    
    def get(self, key, default=None):
        key = self.normalize_key(key)
        val = self.get_raw(key, _MISSING)
        if val is _MISSING:
            return default
        return self.normalize_val(val)
    
    def pop_raw(self, key, default=None):
        return super().pop(key, default)
    
    def pop(self, key, default=None):
        key = self.normalize_key(key)
        val = self.pop_raw(key, _MISSING)
        if val is _MISSING:
            return default
        return self.normalize_val(val)
    
    def values(self):
        for val in super().values():
            yield self.normalize_val(val)
    
    def items(self):
        for key, val in super().items():
            yield key, self.normalize_val(val)

class HTTPMessage(NormalizedDict):
    _lower_key = 1  # Header names are case-insensitive
    
    @classmethod
    def normalize_key(cls, key):
        if isinstance(key, str):
            key = key.encode(_ENCODE_HEAD)
        elif isinstance(key, memoryview):
            key = bytes(key)
        if isinstance(key, (bytes, bytearray)):
            if key:
                if key[0] <= 32 or key[-1] <= 32:
                    key = key.strip()
            if key and cls._lower_key:
                key = key.lower()
        return key
    
    @classmethod
    def normalize_val(cls, val):
        if isinstance(val, memoryview):
            val = bytes(val)
        if isinstance(val, (bytes, bytearray)):
            val = val.decode(_DECODE_HEAD)
        if isinstance(val, str):
            if val:
                if val[0].isspace() or val[-1].isspace():
                    val = val.strip()
        return val

class HTTPCookies(HTTPMessage):  # Extension
    _lower_key = 0  # Cookie names are case-sensitive
    
    @classmethod
    def normalize_val(cls, val):
        if isinstance(val, memoryview):
            val = bytes(val)
        if isinstance(val, (bytes, bytearray)):
            val = val.decode(_DECODE_HEAD)
        if not isinstance(val, str) or val == "":
            return val
        
        if val[0].isspace() or val[-1].isspace():
            val = val.strip()
        if val.startswith('"'):
            sep = val.find('"', 1)
            if sep != -1:
                val = val[1:sep]
        else:
            sep = val.find(";")
            if sep != -1:
                val = val[0:sep]
            val = val.strip()
        
        return val
    
    def attributes(self, key):
        key = self.normalize_key(key)
        val = self.get_raw_bytes(key, _MISSING)
        if val is _MISSING:
            raise KeyError(key)
        attrs = {}

        if isinstance(val, memoryview):
            val = bytes(val)
        if isinstance(val, (bytes, bytearray)):
            val = val.decode(_DECODE_HEAD)
        if not isinstance(val, str) or val == "":
            return attrs
        
        if val[0].isspace() or val[-1].isspace():
            val = val.strip()
        if val.startswith('"'):
            sep = val.find('"', 1)
            if sep != -1:
                val = val[sep+1:]
        else:
            sep = val.find(";")
            if sep != -1:
                val = val[sep:]
        
        for attr in val.split(";"):
            sep = attr.find("=")
            if sep != -1:
                k, v = attr[:sep], attr[sep+1:]
                k, v = k.strip(), v.strip()
            else:
                k, v = attr.strip(), True
                if not k:
                    continue
            attrs[k] = v
        return attrs

class HTTPException(Exception): pass
class NotConnected(HTTPException): pass
class ImproperConnectionState(HTTPException): pass
class CannotSendRequest(ImproperConnectionState): pass
class CannotSendHeader(ImproperConnectionState): pass
class ResponseNotReady(ImproperConnectionState): pass
class BadStatusLine(HTTPException): pass
class RemoteDisconnected(BadStatusLine): pass

def isiterator(x):
    try:
        iter(x)
        return True
    except TypeError:
        return False

@micropython.viper
def _validate_ascii(buf:ptr8, buflen:int, allow_space:int) -> int:
    i = 0
    while i < buflen:
        b = buf[i]
        if b < 32 or b >= 127:
            return 0
        if b == 32 and allow_space == 0:
            return 0
        i += 1
    return 1

def _encode_and_validate(b, charset, *, allow_space=1, force_bytes=False):
    if isinstance(b, (bytes, bytearray, memoryview)):
        pass
    elif isinstance(b, str):
        b = b.encode(charset)
    elif isinstance(b, int):
        return str(b).encode(charset)
    else:
        raise TypeError("must be bytes-like or int")
    if _validate_ascii(b, len(b), allow_space) == 0:
        raise ValueError("can't contain special characters")
    if not force_bytes or isinstance(b, bytes):
        return b
    return bytes(b)

def _create_connection(address, timeout):
    host, port = address
    for f, t, p, n, a in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        sock = None
        try:
            sock = socket.socket(f, t, p)
            try:
                if timeout != 0:  # 0 would be a non-blocking socket
                    sock.settimeout(timeout)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (AttributeError, OSError):
                pass
            sock.connect(a)
            return sock
        except OSError:
            if sock is not None:
                sock.close()
    raise OSError(128)  # ENOTCONN

def create_connection(address, timeout=None):
    return _create_connection(address, timeout)

# derived from CPython (all bugs are mine)
def parse_host_port(host, port, default_port=None):
    if port is None:
        i = host.rfind(':')
        j = host.rfind(']')
        if i > j:
            port_str = host[i+1:]
            try:
                port = int(port_str, 10)
                if port <= 0:
                    raise ValueError("port must be > 0")
            except ValueError:
                if port_str == "":
                    port = default_port
                else:
                    raise
            host = host[:i]
        else:
            port = default_port
    if host and host[0] == '[' and host[-1] == ']':
        host = host[1:-1]
    return (host, port)

def parse_headers(sock, *, extra_headers=True, parse_cookies=None):  # returns dict/s {bytes:bytes, ...}
    # parse_cookies is tri-state:
    # parse_cookies is True? parse set-cookie headers and return as an HTTPCookies object
    # parse_cookies is False? don't parse set-cookie headers but return an empty HTTPCookies object
    # parse_cookies is None? don't parse set-cookie headers and don't even return an HTTPCookies object
    
    headers = HTTPMessage()
    if parse_cookies is not None:
        cookies = HTTPCookies()
    last_header = None
    
    while True:
        line = sock.readline()
        if not line or line == _CRLF or line == b"\n":
            if parse_cookies is not None:
                return headers, cookies
            else:
                return headers
        
        if line.startswith((b' ', b'\t')):
            if last_header is not None:
                old_val = headers.get_raw_bytes(last_header, _MISSING)
                if old_val is not _MISSING:
                    headers.set_raw(last_header, old_val + b" " + line.strip())
            continue
        
        sep = line.find(b':')
        if sep == -1:
            last_header = None
            continue
        key, val = line[:sep], line[sep+1:]
        key = headers.normalize_key(key)
        
        if key == b"set-cookie":
            if parse_cookies:
                val = val.strip()
                sep = val.find(b'=')
                if sep != -1:
                    key, val = val[:sep], val[sep+1:]
                    cookies.set(key, val)  # includes any quotes and parameters
            last_header = None
        elif extra_headers is True or (extra_headers and key in extra_headers) or key in _IMPORTANT_HEADERS:
            val = val.strip()
            old_val = headers.get_raw_bytes(key, _MISSING)
            if old_val is not _MISSING:
                headers.set_raw(key, old_val + b", " + val)
            else:
                headers.set_raw(key, val)
            last_header = key
        else:
            last_header = None

class HTTPResponse:
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
    
    # derived from CPython (all bugs are mine)
    def __init__(self, sock, debuglevel=0, method=None, url=None):
        self._sock = sock
        self.debuglevel = debuglevel
        self._method = method
        self._url = url
        self.complete = False
        #
        self.version = None
        self.status = None
        self.reason = None
        self.headers = None
        self.cookies = None
        self.chunked = False
        self.chunk_left = None
        self.will_close = True
        self.content_length = None
        self.content_read = 0
    
    def begin(self, *, extra_headers=True, parse_cookies=False):
        self.version, self.status, self.reason = self._read_status()
        if self.debuglevel > 0:
            print("status:", repr(self.version), repr(self.status), repr(self.reason))
        
        self.headers, self.cookies = parse_headers(self._sock, extra_headers=extra_headers, parse_cookies=bool(parse_cookies))
        if self.debuglevel > 0:
            for key, val in self.headers.items():
                print("header:", repr(key), "=", repr(val))
            for key, val in self.cookies.items():
                print("cookie:", repr(key), "=", repr(val))
        
        # are we using the chunked-style of transfer encoding?
        self.chunked = (self.headers.get_raw_bytes(b"transfer-encoding") == b"chunked")
        self.chunk_left = None
        
        # will the connection close at the end of the response?
        conn = self.headers.get_raw_bytes(b"connection")
        conn = conn.lower() if conn else b""
        if self.version == 10:
            if b"keep-alive" in conn:
                self.will_close = False
            else:
                self.will_close = (self.headers.get_raw_bytes(b"keep-alive") is None)
        else:
            self.will_close = b"close" in conn
        
        # do we have a Content-Length?
        # NOTE: RFC 2616, S4.4, #3 says we ignore this if chunked
        self.content_length = None
        length = self.headers.get_raw_bytes(b"content-length")
        if length and not self.chunked:
            try:
                self.content_length = int(length, 10)
            except ValueError:
                pass  # self.content_length is already None
            else:
                if self.content_length < 0:  # ignore nonsensical negative lengths
                    self.content_length = None
        self.content_read = 0
        
        # does the body have a fixed length? (of zero)
        if (100 <= self.status < 200
            or self.status == 204 or self.status == 304
            or self._method == "HEAD"):
            self.content_length = 0
            self.chunked = False
            self.chunk_left = None
        
        # if the connection remains open, and we aren't using chunked, and
        # a content-length was not provided, then assume that the connection
        # WILL close.
        if (not self.will_close and
            not self.chunked and
            self.content_length is None):
            self.will_close = True
    
    def _read_status(self):
        # read until we get a non-100 response
        while True:
            line = self._sock.readline()
            if self.debuglevel > 0:
                print("status:", repr(line))
            if not line or not line.endswith(b'\n'):
                raise RemoteDisconnected()
            if not line.startswith(b"HTTP/"):
                raise BadStatusLine()
            
            try:
                line = line.decode(_DECODE_HEAD).strip()  # line always ends with CRLF
                line = line.split(None, 2)
                if len(line) == 3:
                    version, status, reason = line
                elif len(line) == 2:
                    version, status = line
                    reason = ""
                else:
                    raise BadStatusLine()
                status = int(status, 10)
            except (UnicodeError, ValueError):
                raise BadStatusLine()
            
            # the status code is a three-digit number
            if status < 100 or status > 999:
                raise BadStatusLine()
            
            if status != 100:
                break
            # skip the header from the 100 response
            while True:
                line = self._sock.readline()
                if not line or line == _CRLF or line == b"\n":
                    break
                if self.debuglevel > 0:
                    print("header:", repr(line))
        
        if version == "HTTP/1.0":
            version = 10
        elif version.startswith("HTTP/1."):
            version = 11  # use HTTP/1.1 code for HTTP/1.x where x>0
        else:
            raise BadStatusLine()  # no support for HTTP/0.9 or HTTP/2+
        
        return version, status, reason
    
    def close(self):
        self._close(False)
    
    def _close(self, hard):
        incomplete = (
            hard
            or self.chunk_left is not None
            or (self.content_length is not None and self.content_read < self.content_length)
        )
        if not incomplete:
            self.complete = True
        
        sock = self._sock
        self._sock = None
        
        if sock is not None and (incomplete or self.will_close):
            try:
                sock.close()
            except OSError:
                pass
    
    def isclosed(self):
        return self._sock is None
    
    @property
    def closed(self):
        return self.isclosed()
    
    @property
    def length(self):
        return self.content_length
    
    def readinto(self, buf):
        if not isinstance(buf, memoryview):
            buf = memoryview(buf)
        return self._read(buf)
    
    def read(self, amt=None):
        if amt is not None:
            amt = int(amt)
            if amt < 0:
                amt = None
        return self._read(amt)
    
    def _read(self, arg):
        if not self.chunked:
            return self.read_raw(arg)
        
        chunked = self.read_chunked(arg)
        if isinstance(chunked, list):
            len_chunked = len(chunked)
            if len_chunked > 1:
                return _BLANK.join(chunked)
            elif len_chunked == 1:
                return chunked[0]
            else:
                return _BLANK
        elif isinstance(chunked, memoryview):
            return bytes(chunked)
        else:  # bytearray or int
            return chunked
    
    def read_chunked(self, arg=None):
        arg_is_memoryview = isinstance(arg, memoryview)
        res_is_memoryview = False
        if arg_is_memoryview:
            if len(arg) == 0:
                return 0
            res = arg
        elif arg is None:
            res = []
        else:
            assert isinstance(arg, int)
            if arg <= 0:
                return []
            buf = bytearray(arg)
            res = memoryview(buf)
            res_is_memoryview = True
        total = 0
        
        while not self.isclosed():
            
            if self.chunk_left is None:
                # Need to read a new chunk header
                line = self._sock.readline()
                if not line.endswith(b'\n'):
                    # Malformed data: invalid chunk header
                    self._close(True)
                    break
                
                # Strip chunk extensions
                try:
                    self.chunk_left = int(line.split(b';')[0].strip(), 16)
                except ValueError:
                    # Malformed data: invalid chunk size
                    self._close(True)
                    break
                
                if self.chunk_left < 0:
                    # Malformed data: negative chunk size
                    self._close(True)
                    break
                
                if self.chunk_left == 0:
                    # Final chunk: consume trailers until blank line, then done
                    while True:
                        line = self._sock.readline()
                        if not line:
                            # Malformed data: missing CRLF after final chunk (premature EOF)
                            self._close(True)
                            break
                        if line == _CRLF or line == b"\n":
                            # End of Content
                            self.chunk_left = None
                            self.close()
                            break
            
            nread = 0
            
            if arg_is_memoryview or res_is_memoryview:
                to_read = min(self.chunk_left, len(res) - total)
                if to_read <= 0:
                    break # buffer full, not EOF
                nread = self._sock.readinto(res[total:total+to_read])
                if nread is None or nread < 0:
                    break  # ???
            else:
                to_read = self.chunk_left
                if to_read > 0:
                    chunk = self._sock.read(to_read)
                    if chunk is None:
                        break  # ???
                    if chunk:
                        res.append(chunk)
                        nread = len(chunk)
            
            if nread == 0:
                # EOF
                self._close(True)  # ???
                break
            
            self.content_read += nread
            total += nread
            self.chunk_left -= nread
            
            if self.chunk_left == 0:
                # We finished the chunk: validate trailing LF/CRLF immediately.
                if (cr := self._sock.read(1)) == b"\n" or (cr == b"\r" and self._sock.read(1) == b"\n"):
                    self.chunk_left = None  # ready for next chunk header
                else:
                    # Malformed data: missing LF/CRLF after this chunk
                    self._close(True)
                    break
        
        if arg_is_memoryview:
            return total # an integer
        elif res_is_memoryview:
            if total == len(res):
                # optimisation so that the caller doesn't have to do bytes() on the return value
                return buf # a bytearray
            else:
                return res[:total] # a memoryview
        else:
            return res # a list of bytes objects
    
    def read_raw(self, arg=None):
        arg_is_memoryview = isinstance(arg, memoryview)
        
        if arg is None:
            pass
        elif arg_is_memoryview:
            if len(arg) == 0:
                return 0
        else:
            assert isinstance(arg, int)
            if arg <= 0:
                return _BLANK
        
        if self.isclosed():
            # End of File
            if arg_is_memoryview:
                return 0
            return _BLANK
        
        if self.content_length is None:
            # no Content-Length header
            if arg is None:
                res = self._sock.read()
                if res is None:
                    return _BLANK
                self.content_read += len(res)
                self.close()
                return res
            elif arg_is_memoryview:
                to_read = len(arg)
            else:
                to_read = arg
        else:
            if arg is None:
                to_read = self.content_length - self.content_read
            elif arg_is_memoryview:
                to_read = min(self.content_length - self.content_read, len(arg))
            else:
                to_read = min(self.content_length - self.content_read, arg)
        
        if to_read < 0:
            # Malformed data: read more than Content-Length
            self._close(True)
            if arg_is_memoryview:
                return 0
            return _BLANK
        
        if arg_is_memoryview:
            nread = self._sock.readinto(arg[:to_read])
            if nread is None or nread < 0:
                nread = 0
            elif nread == 0:
                # End of Content
                self.close()
            else:
                self.content_read += nread
        else:
            res = self._sock.read(to_read)
            nread = None if res is None else len(res)
            if nread is None:
                nread = 0
            elif nread == 0:
                # End of Content
                self.close()
            else:
                self.content_read += nread
        
        if self.content_length is not None:
            if self.content_read == self.content_length:
                # End of Content
                self.close()
            elif self.content_read > self.content_length:
                # Malformed data: read more than Content-Length
                self._close(True)
        
        if arg_is_memoryview:
            return nread
        return res
    
    def geturl(self):
        return self._url
    
    def getcode(self):
        return self.status
    
    def getheaders(self):
        return self.headers.items()
    
    def getheader(self, name, default=None):
        return self.headers.get(name, default)
    
    # Extension
    def getcookies(self):
        return self.cookies.items()
    
    # Extension
    def getcookie(self, name, default=None):
        return self.cookies.get(name, default)
    
    # Extension
    def iter_content(self, chunk_size=1024):
        chunk_size = int(chunk_size)
        if chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")
        buf = memoryview(bytearray(chunk_size))
        
        poller = select.poll()
        poller.register(self._sock, select.POLLIN)  #TODO: check that this works with SSL-wrapped sockets
        try:
            while True:
                if not poller.poll(-1):
                    continue
                n = self.readinto(buf)
                if n is None:
                    continue
                if not n:
                    break
                yield bytes(buf[:n])
        finally:
            if self._sock is not None:
                poller.unregister(self._sock)
    
    # Extension
    def iter_content_into(self, buf):
        poller = select.poll()
        poller.register(self._sock, select.POLLIN)  #TODO: check that this works with SSL-wrapped sockets
        try:
            while True:
                if not poller.poll(-1):
                    continue
                n = self.readinto(buf)
                if n is None:
                    continue
                if not n:
                    break
                yield n
        finally:
            if self._sock is not None:
                poller.unregister(self._sock)
    
    def readable(self):
        return True

class HTTPConnection:
    _buffer_size = 1024  # for the request line and headers only (in bytes)
    default_port = HTTP_PORT
    auto_open = True
    debuglevel = 0
    
    # Extension
    def __enter__(self):
        return self
    
    # Extension
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
    
    def __init__(self, host, port=None, timeout=None, source_address=None, blocksize=1024):
        self.host, self.port = parse_host_port(host, port, self.default_port)
        if not self.host:
            raise ValueError("invalid host")
        self.timeout = timeout
#        self.source_address = source_address  # not used
        self.blocksize = blocksize
        self.sock = None
        self.__response = None
        self.__state = _CS_IDLE
        self._auto_open = False
        self._sent_data = False
        if self._buffer_size:
            self._buffer = memoryview(bytearray(self._buffer_size))
        else:
            self._buffer = None
        self._filled = 0
        self._method = None
        self._url = None
    
    def set_debuglevel(self, level):
        self.debuglevel = level
    
    def connect(self):
        self.sock = create_connection((self.host, self.port), self.timeout)
    
    def close(self):
        self.__state = _CS_IDLE
        try:
            if self.__response is not None:
                self.__response._close(True)
                self.__response = None
                self.sock = None
        finally:
            self._filled = 0
            if self.sock is not None:
                self.sock.close()
                self.sock = None
    
    # derived from CPython (all bugs are mine)
    def request(self, method, url, body=None, headers=None, cookies=None,
                *, encode_chunked=False):
        if isinstance(body, str):
            body = body.encode(_ENCODE_BODY)
        
        have_accept_encoding = False
        have_content_length = False
        have_host = False
        have_transfer_encoding = False
        
        if headers is not None:
            if hasattr(headers, "keys") and callable(headers.keys):
                keys = headers.keys()
            else:
                keys = (header[0] for header in headers)  # generator
            for key in keys:
                if not isinstance(headers, HTTPMessage):
                    key = HTTPMessage.normalize_key(key)  # class method
                if key == b"accept-encoding":
                    have_accept_encoding = True
                elif key == b"content-length":
                    have_content_length = True
                elif key == b"host":
                    have_host = True
                elif key == b"transfer-encoding":
                    have_transfer_encoding = True
        
        self.putrequest(method, url, skip_accept_encoding=have_accept_encoding, skip_host=have_host)
        
        # chunked encoding will happen if HTTP/1.1 is used and either
        # the caller passes encode_chunked=True or the following
        # conditions hold:
        # 1. content-length has not been explicitly set
        # 2. the body is a file or iterable, but not a str or bytes-like
        # 3. Transfer-Encoding has NOT been explicitly set by the caller
        
        if not have_content_length:
            # only chunk body if not explicitly set for backwards
            # compatibility, assuming the client code is already handling the
            # chunking
            if not have_transfer_encoding:
                # if content-length cannot be automatically determined, fall
                # back to chunked encoding
                encode_chunked = False
                
                if body is None:
                    # do an explicit check for not None here to distinguish
                    # between unset and set but empty
                    if self._method in _METHODS_EXPECTING_BODY:
                        content_length = 0
                    else:
                        content_length = None
                elif isinstance(body, (bytes, bytearray, memoryview)):
                    content_length = len(body)
                else:
                    content_length = None
                
                if content_length is None:
                    if body is not None:
                        encode_chunked = True
                        self.putheader(b"Transfer-Encoding", b"chunked")
                else:
                    self.putheader(b"Content-Length", content_length)
        else:
            encode_chunked = False
        
        self.putheaders(headers, cookies)
        
        self.endheaders(body, encode_chunked=encode_chunked)
    
    # derived from CPython (all bugs are mine)
    def putrequest(self, method, url, skip_host=False, skip_accept_encoding=False):
        if self.__response is not None:
            if not self.__response.isclosed():
                raise CannotSendRequest()
            self.__response = None
        if self.__state != _CS_IDLE:
            raise CannotSendRequest()
        self.__state = _CS_REQ_STARTED

        self._auto_open = self.auto_open
        self._sent_data = False
        self._filled = 0
        
        # Trust the method name from the caller
        method = _encode_and_validate(method, "ascii", allow_space=0, force_bytes=True)
        if method == b"GET":
            self._method = "GET"
        else:
            self._method = method.upper().decode("ascii")
        self._url = url
        url = _encode_and_validate(url, _ENCODE_HEAD, allow_space=0) if url else b"/"
        
        self._putheaderparts(method, b" ", url, b" HTTP/1.1\r\n")
        
        # Issue some standard headers for better HTTP/1.1 compliance
        if not skip_host:
            host = self.host
            if ':' in host and not host.startswith('['):
                host = "[%s]" % (host,)
            if self.port == self.default_port:
                self.putheader(b"Host", host)
            else:
                self.putheader(b"Host", "%s:%d" % (host, self.port))
        if not skip_accept_encoding:
            self._putheaderparts(b"Accept-Encoding: identity\r\n")
    
    # Extension
    def putheaders(self, headers, cookies=None):
        if headers is not None:
            for key, val in headers.items():
                self.putheader(key, val)
        
        if cookies is not None:
            # Trust the cookie names and values from the caller
            values = []
            for key, val in cookies.items():
                values.append(b"%s=%s" % (_encode_and_validate(key, _ENCODE_HEAD, force_bytes=True), _encode_and_validate(val, _ENCODE_HEAD, force_bytes=True)))
            if len(values) == 1:
                self.putheader(b"Cookie", values[0])
            elif len(values):
                self.putheader(b"Cookie", b"; ".join(values))
    
    def putheader(self, header, *values):
        if self.__state != _CS_REQ_STARTED or self.__response is not None:
            raise CannotSendHeader()
        
        # Trust the header names from the caller, but check the header values
        if isinstance(header, str):
            header = header.encode(_ENCODE_HEAD)
        parts = [header, b": "]
        for i in range(len(values)):
            if i > 0:
                parts.append(b", ")
            parts.append(_encode_and_validate(values[i], _ENCODE_HEAD))
        parts.append(_CRLF)
        self._putheaderparts(*parts)
    
    def _putheaderparts(self, *parts, last=False):
        if self._buffer is None:
            if len(parts) == 1:
                self.send_raw(parts[0])
            else:
                self.send_raw(_BLANK.join(parts))
        else:
            for part in parts:
                len_part = len(part)
                if self._filled + len_part <= self._buffer_size:
                    self._buffer[self._filled:self._filled+len_part] = part
                    self._filled += len_part
                else:
                    self.send_raw(self._buffer[:self._filled])
                    self._filled = 0
                    if len_part >= self._buffer_size:
                        self.send_raw(part)
                    else:
                        self._buffer[:len_part] = part
                        self._filled = len_part
        
        if last:
            if self._buffer is not None:
                was_filled = self._filled
                self._filled = 0
                if was_filled:
                    self.send_raw(self._buffer[:was_filled])
    
    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self.__state != _CS_REQ_STARTED or self.__response is not None:
            raise CannotSendHeader()
        
        self._putheaderparts(_CRLF, last=True)
        self._auto_open = False
        self.__state = _CS_REQ_SENT
        if message_body is not None:
            self.send(message_body, encode_chunked=encode_chunked)
    
    def send_raw(self, data):
        if data is None:
            data = _BLANK
        
        if self._auto_open and not self._sent_data:
            try:
                if self.sock is not None:
                    if self.sock.sendall(data):
                        self._sent_data = True
                    return
            except OSError:
                try: self.sock.close()
                except: pass
                self.sock = None
            try:
                self.connect()
            except OSError:
                raise NotConnected()
            if self.sock.sendall(data):
                self._sent_data = True
            return
        
        if self.sock is None:
            raise NotConnected()
        if self.sock.sendall(data):
            self._sent_data = True
    
    def send_chunk(self, data):
        if data is None:
            self.send_raw(b"0\r\n\r\n")
            return
        self.send_raw(b"%X\r\n" % (len(data),))
        self.send_raw(data)
        self.send_raw(_CRLF)
    
    def send(self, data, *, encode_chunked=False, final_chunk=True):  # encode_chunked and final_chunk are extensions
        if isinstance(data, str):
            data = data.encode(_ENCODE_BODY)
        
        send = self.send_chunk if encode_chunked else self.send_raw
        
        if data is None:
            if self.debuglevel > 0:
                print("send: None")
            pass
        elif isinstance(data, (bytes, bytearray, memoryview)):
            if self.debuglevel > 0:
                print("send:", type(data).__name__, len(data))
            if data:
                send(data)
        elif hasattr(data, "readinto"):
            buf = memoryview(bytearray(self.blocksize))
            while True:
                n = data.readinto(buf)
                if self.debuglevel > 0:
                    print("send:", type(data).__name__, None if n is None else n)
                if n is None or n < 0:
                    time.sleep_ms(1)
                    continue
                if not n:
                    break
                send(buf[:n])
        elif hasattr(data, "read"):
            while True:
                d = data.read(self.blocksize)
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if self.debuglevel > 0:
                    print("send:", type(d).__name__, None if d is None else len(d))
                if d is None:
                    time.sleep_ms(1)
                    continue
                if not d:
                    break
                send(d)
        elif isiterator(data):  # includes generators (bytes-like was handled earlier)
            for d in data:
                if isinstance(d, str):
                    d = d.encode(_ENCODE_BODY)
                if d is None:
                    if self.debuglevel > 0:
                        print("send: None")
                    continue
                if isinstance(d, (bytes, bytearray, memoryview)):
                    if self.debuglevel > 0:
                        print("send:", type(d).__name__, len(d))
                    if not d:
                        continue
                else:
                    raise TypeError("unexpected data")
                send(d)
        else:
            raise TypeError("unexpected data")
        
        if encode_chunked and final_chunk:
            if self.debuglevel > 0:
                print("send: terminating chunk")
            send(None)
    
    def getresponse(self, **kwargs):
        if self.__response is not None and self.__response.isclosed():
            self.__response = None
        if self.__state != _CS_REQ_SENT or self.__response is not None:
            raise ResponseNotReady()
        
        try:
            response = HTTPResponse(self.sock, self.debuglevel, self._method, self._url)
            response.begin(**kwargs)
            self.__state = _CS_IDLE
            if response.will_close:
                self.sock = None
                self.__response = None
            else:
                self.__response = response
            return response
        except Exception:
            self.close()
            raise
    
    def detach(self):
        if self.__response is not None:
            sock = self.__response._sock
            self.__response._sock = None
            self.__response = None
        else:
            sock = self.sock
        self.sock = None
        self.__state = _CS_IDLE
        return sock

try:
    import ssl
except ImportError:
    pass
else:
    class HTTPSConnection(HTTPConnection):
        default_port = HTTPS_PORT
        
        def __init__(self, *args, context=None, **kwargs):
            super().__init__(*args, **kwargs)
            if context is None:
                if hasattr(ssl, "SSLContext"):
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.verify_mode = ssl.CERT_NONE
                else:
                    context = None
            self._context = context
        
        def connect(self):
            super().connect()
            if self._context is None:
                try:
                    self.sock = ssl.wrap_socket(self.sock, server_hostname=self.host)
                except TypeError:
                    self.sock = ssl.wrap_socket(self.sock)
            else:
                self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)
