# http/client_ish.py

import micropython, socket, time

HTTP_PORT = const(80)
HTTPS_PORT = const(443)

OK = const(200)
responses = {OK: "OK"}

_CS_IDLE = const(0)
_CS_REQ_STARTED = const(1)
_CS_REQ_SENT = const(2)

# Reasons for HTTPResponse.close(). The reason controls whether the underlying
# socket is actually closed and whether the response is flagged as incomplete.
#   _CR_DONE      - body was fully consumed, or the user called .close() at an
#                   arbitrary point. The underlying socket is closed only if
#                   will_close is True or the body framing indicates the
#                   connection can't be safely reused (partial read).
#   _CR_EOF       - unexpected EOF on the wire. The socket is always closed,
#                   and (when a body length is known and wasn't reached) the
#                   response is marked incomplete.
#   _CR_MALFORMED - protocol violation (bad chunk header, Content-Length
#                   overrun, etc.). The socket is always closed and the
#                   response is marked incomplete: the body can't be trusted.
# After close() returns, whether the underlying OS socket was actually closed
# is derivable from other observable state (will_close, _incomplete, chunk_left,
# and the content-length/read pair).
_CR_DONE = const(0)
_CR_EOF = const(1)
_CR_MALFORMED = const(2)

# We always set the Content-Length header for these methods because some
# servers will otherwise respond with a 411
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

@micropython.viper
def _lower_helper(buf:ptr8, buflen:int, inplace:bool) -> int:
    retval = 0
    i = 0
    while i < buflen:
        b = buf[i]
        if 65 <= b <= 90:
            if inplace:
                buf[i] = b + 32
            else:
                retval = 1
                break
        i += 1
    return retval

def _lower(s):
    if isinstance(s, (str, bytes)):
        if _lower_helper(s, len(s), 0):
            s = s.lower()
    elif isinstance(s, bytearray):
        _lower_helper(s, len(s), 1)
    elif isinstance(s, memoryview):
        if _lower_helper(s, len(s), 0):
            s = bytes(s).lower()
    else:
        s = s.lower()
    return s

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
    
    def __delitem__(self, key):
        key = self.normalize_key(key)
        super().__delitem__(key)

    def __getitem__(self, key):
        key = self.normalize_key(key)
        val = super().__getitem__(key)
        return self.normalize_val(val)
    
    def __setitem__(self, key, val):
        key = self.normalize_key(key)
        super().__setitem__(key, val)
    
#    def clear(self):
#        super().clear()
    
    def copy(self):
        raise NotImplementedError()
    
    def get_raw(self, key, default=None):
        return super().get(key, default)
    
    def get(self, key, default=None, as_type=None):
        key = self.normalize_key(key)
        val = super().get(key, _MISSING)
        if val is _MISSING:
            return default
        if as_type is None:
            return self.normalize_val(val)
        if val is None:
            return as_type()
        if isinstance(val, str):
            if as_type is str:
                return val
            if as_type is bytes:
                return val.encode()
            return as_type(val)
        if isinstance(val, memoryview):
            val = bytes(val)
        if isinstance(val, (bytes, bytearray)):
            if as_type is str:
                return val.decode()
            if as_type is bytes:
                return val
        return as_type(val)
    
    def items(self):
        for key, val in super().items():
            yield key, self.normalize_val(val)
    
#    def keys(self):
#        return super().keys()
    
    def pop(self, key, default=_MISSING):
        raise NotImplementedError()
    
    def popitem(self):
        raise NotImplementedError()
    
    def set(self, key, val):
        key = self.normalize_key(key)
        super().__setitem__(key, val)
    
    def set_raw(self, key, val):
        super().__setitem__(key, val)
    
    def setdefault(self, key, default=_MISSING):
        raise NotImplementedError()
    
    def update(self, iterable):
        raise NotImplementedError()
    
    def values(self):
        for val in super().values():
            yield self.normalize_val(val)
    
    @classmethod
    def fromkeys(self):
        raise NotImplementedError()

class HTTPMessage(NormalizedDict):
    _lower_key = 1  # Header names are case-insensitive
    
    @classmethod
    def normalize_key(cls, key):
        if isinstance(key, memoryview):
            key = bytes(key)
        elif isinstance(key, str):
            key = key.encode(_ENCODE_HEAD)
        if isinstance(key, (bytes, bytearray)):
            if key:
                if key[0] <= 32 or key[-1] <= 32:
                    key = key.strip()
            if key and cls._lower_key:
                key = _lower(key)
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
        val = self.get(key, _MISSING, str)
        if val is _MISSING:
            raise KeyError(key)
        if val == "":
            return {}
        
        if val[0].isspace() or val[-1].isspace():
            val = val.strip()
        if val.startswith('"'):
            sep = val.find('"', 1)
            if sep != -1:
                sep = val.find(";", sep+1)
        else:
            sep = val.find(";")
        if sep == -1:
            return {}
        val = val[sep:]
        
        attrs = {}
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
class RemoteDisconnected(ConnectionResetError, BadStatusLine): pass

@micropython.viper
def _validate_ascii(buf:ptr8, buflen:int, deny_flags:int) -> int:
    deny_space = (deny_flags & 1)
    deny_comma = (deny_flags & 2)
    deny_equal = (deny_flags & 4)
    deny_semicolon = (deny_flags & 8)
    deny_quote = (deny_flags & 16)
    i = 0
    while i < buflen:
        b = buf[i]
        if b < 32 or b >= 127:
            return 0
        if b == 32 and deny_space:
            return 0
        if b == 44 and deny_comma:
            return 0
        if b == 61 and deny_equal:
            return 0
        if b == 59 and deny_semicolon:
            return 0
        if b == 34 and deny_quote:
            return 0
        i += 1
    return 1

def _encode_and_validate(b, charset, *, deny_flags=0, force_bytes=False, and_quote=False):
    valid = False
    if isinstance(b, (bytes, bytearray, memoryview)):
        pass
    elif isinstance(b, str):
        b = b.encode(charset)
    elif isinstance(b, int):
        b = str(b).encode(charset)
        valid = True
    else:
        raise TypeError("must be bytes-like or int")
    if (not valid) and _validate_ascii(b, len(b), deny_flags) == 0:
        raise ValueError("can't contain special characters")
    if (force_bytes or and_quote) and isinstance(b, memoryview):
        b = bytes(b)
    if and_quote:
        b = b'"' + b + b'"'
    return b

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
        except Exception as e:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            if not isinstance(e, OSError):
                raise e
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
            if port_str == "":
                port = default_port
            elif not port_str[0].isdigit():
                raise ValueError("invalid port")
            else:
                port = int(port_str, 10)
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
                old_val = headers.get_raw(last_header, _MISSING)
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
                sep = val.find(b'=')
                if sep != -1:
                    key, val = val[:sep], val[sep+1:]
                    cookies.set(key, val)  # includes any quotes and parameters
            last_header = None
        elif extra_headers is True or (extra_headers and key in extra_headers) or key in _IMPORTANT_HEADERS:
            old_val = headers.get_raw(key, _MISSING)
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
        self._incomplete = False
    
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
        self.chunked = (b"chunked" in _lower(self.headers.get(b"transfer-encoding", b"", bytes)))
        self.chunk_left = None
        
        # will the connection close at the end of the response?
        conn = _lower(self.headers.get(b"connection", b"", bytes))
        if self.version == 10:
            if b"keep-alive" in conn:
                self.will_close = False
            else:
                self.will_close = (self.headers.get(b"keep-alive", _MISSING, bytes) is _MISSING)
        else:
            self.will_close = b"close" in conn
        
        # do we have a Content-Length?
        # NOTE: RFC 2616, S4.4, #3 says we ignore this if chunked
        self.content_length = None
        length = self.headers.get(b"content-length", None)
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
    
    def close(self, reason=_CR_DONE):
        sock = self._sock
        self._sock = None
        
        partial_body = (
            self.chunk_left is not None
            or (self.content_length is not None and self.content_read < self.content_length)
        )
        
        if reason == _CR_EOF:
            if partial_body:
                self._incomplete = True
            force_close = True
        elif reason == _CR_MALFORMED:
            self._incomplete = True
            force_close = True
        else:  # _CR_DONE
            force_close = partial_body
        
        if sock is not None and (force_close or self.will_close):
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
    
    @property
    def incomplete(self):
        return self._incomplete
    
    def readinto(self, buf):
        if isinstance(buf, memoryview):
            return self._readinto(buf)
        else:
            return self._readinto(memoryview(buf))
    
    def _readinto(self, bmv):
        if self.chunked:
            return self._read_chunked(bmv)
        else:
            return self._read_raw(bmv)
    
    def read(self, amt=None):
        res = self._read(amt)
        if res is None:
            return _BLANK
        if isinstance(res, memoryview):
            return bytes(res)
        if not isinstance(res, list):
            return res # int, bytes, bytearray
        if len(res) == 0:
            return _BLANK
        if len(res) == 1:
            return res[0]
        return _BLANK.join(res)
    
    def _read(self, amt=None):
        if self.chunked:
            return self._read_chunked(amt)
        else:
            return self._read_raw(amt)
    
    def _read_chunked(self, arg=None):
        # NOTE: requires a blocking socket
        
        arg_is_memoryview = isinstance(arg, memoryview)
        if arg_is_memoryview:
            if len(arg) == 0:
                return 0
            res = arg
        else:
            parts = []
            if arg is not None:
                arg = int(arg)
                if arg < 0:
                    arg = None
                elif arg == 0:
                    return None
        total = 0
        
        while True:
            if self.isclosed():
                break
            
            # Read a new chunk header if we don't have an open chunk already.
            if self.chunk_left is None:
                line = self._sock.readline()
                sep = line.find(b';')
                if sep >= 0:
                    line = line[:sep]
                try:
                    chunk_size = int(line, 16)
                except ValueError:
                    # Malformed chunk size.
                    self.close(_CR_MALFORMED)
                    break
                if chunk_size < 0:
                    # Negative chunk size.
                    self.close(_CR_MALFORMED)
                    break
                self.chunk_left = chunk_size
                if chunk_size == 0:
                    # Final chunk: consume trailers until blank line, then done.
                    while True:
                        line = self._sock.readline()
                        if not line:
                            self.close(_CR_EOF)
                            break
                        if line == _CRLF or line == b"\n":
                            self.chunk_left = None
                            self.close(_CR_DONE)
                            break
                    break
            
            # We have self.chunk_left > 0 here (== 0 was handled above).
            if arg_is_memoryview:
                space = len(res) - total
                if space <= 0:
                    break  # output buffer full; leave chunk_left for next call
                to_read = self.chunk_left
                if to_read > space:
                    to_read = space
                # When total == 0 we can hand sock.readinto() the whole
                # destination buffer plus an nbytes cap, skipping the slice
                # allocation. MicroPython's socket.readinto(buf[, nbytes])
                # supports this; the slice form is kept for the offset case.
                if total == 0:
                    nread = self._sock.readinto(res, to_read)
                else:
                    nread = self._sock.readinto(res[total:total+to_read])
                if not nread:
                    # EOF mid-chunk.
                    self.close(_CR_EOF)
                    break
                self.content_read += nread
                total += nread
                self.chunk_left -= nread
            else:
                # bytes-return path
                if arg is None:
                    to_read = self.chunk_left
                else:
                    remaining_req = arg - total
                    if remaining_req <= 0:
                        break
                    to_read = self.chunk_left
                    if to_read > remaining_req:
                        to_read = remaining_req
                chunk = self._sock.read(to_read)
                if not chunk:
                    # EOF mid-chunk.
                    self.close(_CR_EOF)
                    break
                nread = len(chunk)
                self.content_read += nread
                total += nread
                self.chunk_left -= nread
                parts.append(chunk)
            
            # Consume the CRLF that terminates the chunk data, only when we
            # actually finished the chunk. A partial read leaves chunk_left > 0
            # for the next call.
            if self.chunk_left == 0:
                if self.isclosed():
                    break
                line = self._sock.readline()
                if not line:
                    # Premature EOF.
                    self.close(_CR_EOF)
                    break
                if line != _CRLF and line != b"\n":
                    # Garbage instead of CRLF.
                    self.close(_CR_MALFORMED)
                    break
                self.chunk_left = None
            
            # Stop when caller-supplied buffer or byte-count is satisfied.
            if arg_is_memoryview:
                if total >= len(res):
                    break
            elif arg is not None:
                if total >= arg:
                    break
            # else: arg is None -> keep draining until final 0-size chunk.
        
        if arg_is_memoryview:
            return total
        else:
            return parts
    
    def _read_raw(self, arg=None):
        # NOTE: requires a blocking socket
        
        arg_is_memoryview = isinstance(arg, memoryview)
        res_is_memoryview = False
        if arg_is_memoryview:
            if len(arg) == 0:
                return 0
            res = arg
        elif arg is not None:
            arg = int(arg)
            if arg < 0:
                arg = None
            elif arg == 0:
                return None
            else:
                if self.content_length is not None:
                    remaining = self.content_length - self.content_read
                    if arg > remaining:
                        arg = remaining
                buf = bytearray(arg)
                res = memoryview(buf)
                res_is_memoryview = True
        total = 0
        
        if self.isclosed():
            if arg_is_memoryview:
                return 0
            elif res_is_memoryview:
                return res[:0]
            else:
                return None
        
        # Read the whole body in one go when no size was given
        # and the length is unknown (read-until-EOF framing).
        if arg is None and self.content_length is None:
            chunk = self._sock.read()
            self.content_read += len(chunk)
            self.close(_CR_DONE)
            return chunk
        
        # Compute how much to try to read this call.
        if self.content_length is None:
            # arg is an int or memoryview; no content-length to bound against
            if arg_is_memoryview or res_is_memoryview:
                to_read = len(res)
            else:
                to_read = arg
        else:
            remaining = self.content_length - self.content_read
            if arg is None:
                to_read = remaining
            elif arg_is_memoryview or res_is_memoryview:
                to_read = min(remaining, len(res))
            else:
                to_read = min(remaining, arg)
        
        if to_read < 0:
            # Malformed data: already read more than Content-Length
            self.close(_CR_MALFORMED)
            if arg_is_memoryview:
                return 0
            elif res_is_memoryview:
                return res[:0]
            else:
                return None
        
        chunk = None  # for the bytes-return path
        got_eof = False
        
        if to_read > 0:
            if arg_is_memoryview or res_is_memoryview:
                nread = self._sock.readinto(res, to_read)
                if not nread:
                    got_eof = True
                else:
                    self.content_read += nread
                    total += nread
            else:
                chunk = self._sock.read(to_read)
                if not chunk:
                    got_eof = True
                    chunk = None
                else:
                    self.content_read += len(chunk)
                    total += len(chunk)
        
        if got_eof:
            # Short/empty read means EOF on a blocking socket. Whether this is
            # unexpected depends on framing: if we have a Content-Length and
            # haven't reached it, it's an incomplete body. Otherwise (no
            # Content-Length, or CL already satisfied above) it's just end of
            # stream and we close cleanly.
            if self.content_length is not None and self.content_read < self.content_length:
                self.close(_CR_EOF)
            else:
                self.close(_CR_DONE)
        
        if self.content_length is not None:
            if self.content_read == self.content_length:
                self.close(_CR_DONE)
            elif self.content_read > self.content_length:
                # Malformed data: read more than Content-Length
                self.close(_CR_MALFORMED)
            elif arg is None:
                # Unbounded read() against a Content-Length-framed response
                # that didn't deliver all the bytes this call. On a blocking
                # socket with "no short reads" this shouldn't happen unless
                # readinto/read returned short without EOF, which MicroPython
                # doesn't do for blocking sockets -- but if it does, treat as
                # incomplete.
                self.close(_CR_EOF)
        
        if arg_is_memoryview:
            return total
        elif res_is_memoryview:
            return res[:total]
        else:
            return chunk
    
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
        if self.content_length is not None:
            remaining = self.content_length - self.content_read
            if chunk_size > remaining:
                chunk_size = remaining
        buf = bytearray(chunk_size)
        bmv = memoryview(buf)
        
        while True:
            n = self._readinto(bmv)
            if n <= 0:
                break
            if n == chunk_size:
                yield bytes(buf)
            else:
                yield bytes(bmv[:n])
    
    # Extension
    def iter_content_into(self, bmv):
        if not isinstance(bmv, memoryview):
            bmv = memoryview(bmv)
        while True:
            n = self._readinto(bmv)
            if n <= 0:
                break
            yield n
    
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
        self._filled = 0
        try:
            sock = self.sock
            self.sock = None
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        finally:
            response = self.__response
            self.__response = None
            if response is not None:
                response.close(_CR_EOF)
    
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
                if not isinstance(headers, (list, tuple)):
                    headers = list(headers)
                keys = (header[0] for header in headers)
            for key in keys:
                if not isinstance(headers, HTTPMessage):
                    key = HTTPMessage.normalize_key(key)
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
        
        if headers is not None:
            self.putheaders(headers)
        if cookies is not None:
            self.putcookies(cookies)
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
        method = _encode_and_validate(method, "ascii", deny_flags=1, force_bytes=True)
        if method == b"GET":
            self._method = "GET"
        else:
            self._method = method.upper().decode("ascii")
        self._url = url
        url = _encode_and_validate(url, _ENCODE_HEAD, deny_flags=1) if url else b"/"
        
        self._putheaderparts(False, method, b" ", url, b" HTTP/1.1\r\n")
        
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
            self._putheaderparts(False, b"Accept-Encoding: identity\r\n")
    
    # Extension
    def putheaders(self, headers):
        if hasattr(headers, "items") and callable(headers.items):
            headers = headers.items()
        for key, val in headers:
            self.putheader(key, val)
    
    # Extension
    def putcookies(self, cookies):
        if hasattr(cookies, "items") and callable(cookies.items):
            cookies = cookies.items()
        values = []
        for params in cookies:
            values.append(b"=".join(_encode_and_validate(params[i], _ENCODE_HEAD, deny_flags=(29 if i == 0 else 25), force_bytes=True, and_quote=(i > 0)) for i in range(len(params))))
        if len(values) == 1:
            self._putheaderparts(False, b"Cookie: ", values[0], _CRLF)
        elif len(values) == 0:
            self._putheaderparts(False, b"Cookie: ", _CRLF)
        else:
            for i in range(len(values)):
                self._putheaderparts(False, b"Cookie: " if (i == 0) else b"; ", values[i])
            self._putheaderparts(False, _CRLF)
    
    def putheader(self, header, *values):
        if isinstance(header, str):
            header = header.encode(_ENCODE_HEAD)
        if len(values) == 1:
            self._putheaderparts(False, header, b": ", _encode_and_validate(values[0], _ENCODE_HEAD), _CRLF)
        else:
            self._putheaderparts(False, header, b": ", b", ".join(_encode_and_validate(v, _ENCODE_HEAD, deny_flags=2) for v in values), _CRLF)
    
    def _putheaderparts(self, last, *parts):
        if self.__state != _CS_REQ_STARTED or self.__response is not None:
            raise CannotSendHeader()
        
        if self._buffer is None:
            self.send_raw(_BLANK.join(parts))
        else:
            for part in parts:
                len_part = len(part)
                if len_part >= self._buffer_size:
                    if self._filled:
                        self.send_raw(self._buffer[:self._filled])
                        self._filled = 0
                    self.send_raw(part)
                elif self._filled + len_part <= self._buffer_size:
                    self._buffer[self._filled:self._filled+len_part] = part
                    self._filled += len_part
                else:
                    self.send_raw(self._buffer[:self._filled])
                    self._buffer[:len_part] = part
                    self._filled = len_part
        
        if last and self._filled:
            self.send_raw(self._buffer[:self._filled])
            self._filled = 0
    
    def endheaders(self, message_body=None, *, encode_chunked=False):
        if self.__state != _CS_REQ_STARTED or self.__response is not None:
            raise CannotSendHeader()
        
        self._putheaderparts(True, _CRLF)
        self._auto_open = False
        self.__state = _CS_REQ_SENT
        if message_body is not None:
            self.send(message_body, encode_chunked=encode_chunked)
    
    def send_raw(self, data):
        # NOTE: requires a blocking socket
        
        if data is None:
            data = _BLANK
        
        if self._auto_open and not self._sent_data:
            try:
                if self.sock is not None:
                    self.sock.sendall(data)
                    if data:
                        self._sent_data = True
                    return
            except OSError:
                try: self.sock.close()
                except Exception: pass
                self.sock = None
            try:
                self.connect()
            except OSError:
                raise NotConnected()
            self.sock.sendall(data)
            if data:
                self._sent_data = True
            return
        
        if self.sock is None:
            raise NotConnected()
        self.sock.sendall(data)
        if data:
            self._sent_data = True
    
    def send_chunk(self, data):
        if data is None:
            self.send_raw(b"0\r\n\r\n")
            return
        self.send_raw(b"%X\r\n" % (len(data),))
        self.send_raw(data)
        self.send_raw(_CRLF)
    
    def send(self, data, *, encode_chunked=False, final_chunk=True, _descend=True, _buf=None):  # encode_chunked and final_chunk are extensions
        
        send = self.send_chunk if encode_chunked else self.send_raw
        
        if isinstance(data, str):
            data = data.encode(_ENCODE_BODY)
        
        if data is None:
            if self.debuglevel > 0:
                print("send: None")
        
        elif isinstance(data, (bytes, bytearray, memoryview)):
            if self.debuglevel > 0:
                print("send:", type(data).__name__, len(data))
            if data:
                send(data)
        
        elif hasattr(data, "readinto"):
            while True:
                n = data.readinto(_buf)
                if self.debuglevel > 0:
                    print("send:", type(data).__name__, None if n is None else n)
                if n is None or n < 0:
                    time.sleep_ms(1)
                    continue
                if not n:
                    break
                send(_buf[:n])
        
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
        
        elif _descend:
            for d in data:
                if _buf is None and hasattr(d, "readinto"):
                    _buf = memoryview(bytearray(self.blocksize))
                self.send(d, encode_chunked=encode_chunked, final_chunk=False, _descend=False, _buf=_buf)
        
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
            self._context = context
        
        def connect(self):
            super().connect()
            raw = self.sock

            hostname = None
            if not isinstance(self.host, str):
                pass
            elif all(c.isdigit() or c == '.' for c in self.host):
                pass
            elif ':' in self.host:
                pass
            else:
                hostname = self.host
            
            try:
                if self._context is None:
                    self.sock = ssl.wrap_socket(raw, server_hostname=hostname)
                else:
                    self.sock = self._context.wrap_socket(raw, server_hostname=hostname)
            except Exception:
                self.sock = None
                try:
                    raw.close()
                except OSError:
                    pass
                raise
