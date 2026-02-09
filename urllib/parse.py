# urllib/parse.py

import micropython
from array import array
from uctypes import addressof

__all__ = [
    "quote", "quote_plus", "quote_from_bytes",
    "unquote", "unquote_plus", "unquote_to_bytes",
    "urlencode", "parse_qs", "parse_qsl", "urldecode", 
    "urlsplit", "urlunsplit", "urljoin",
]

_USES_RELATIVE = frozenset([
    "", "file", "ftp", "http", "https", "rtsp", "rtsps", "sftp", "ws", "wss",
])

#_USES_NETLOC = frozenset([
#    "", "file", "ftp", "http", "https", "rtsp", "rtsps", "sftp", "ws", "wss",
#])
_USES_NETLOC = _USES_RELATIVE

_HEX_DIGITS = b"0123456789ABCDEF"

# Standard safeblob for ASCII 32-127
# 0-31:   not used
# 32-63:  0-9, -, .
_SAFEBLOB_BASE_1 = const(0x03FF6000)
# 64-95:  A-Z, _
_SAFEBLOB_BASE_2 = const(0x87FFFFFE)
# 96-127: a-z, ~
_SAFEBLOB_BASE_3 = const(0x47FFFFFE)

_SAFEBLOB_QUOTE = array('I', [
    0,
    _SAFEBLOB_BASE_1 | (1 << 15), # /
    _SAFEBLOB_BASE_2, 
    _SAFEBLOB_BASE_3
])

_SAFEBLOB_QUOTE_PLUS = array('I', [
    1, # plus mode
    _SAFEBLOB_BASE_1, 
    _SAFEBLOB_BASE_2, 
    _SAFEBLOB_BASE_3
])

@micropython.viper
def _quote_helper(src: ptr8, srclen: int, safeblob_obj: object, res: ptr8) -> int:
    safeblob = ptr32(addressof(safeblob_obj))
    write = int(res) != 0
    modified = 0
    reslen = 0
    b = 0
    
    # Unpack safeblob into local variables for speed
    flags = safeblob[0]
    safe1 = safeblob[1] # 32-63
    safe2 = safeblob[2] # 64-95
    safe3 = safeblob[3] # 96-127
    
    hex_digits = ptr8(addressof(_HEX_DIGITS))
    
    i = 0
    while i < srclen:
        b = src[i]
        i += 1
        
        if b == 32 and flags == 1: # space and quote_plus
            modified = 1
            if write: res[reslen] = 43 # '+'
            reslen += 1
            continue
        
        if b < 32:
            is_safe = 0
        elif b < 64:
            is_safe = (safe1 >> (b & 31)) & 1
        elif b < 96:
            is_safe = (safe2 >> (b & 31)) & 1
        elif b < 128:
            is_safe = (safe3 >> (b & 31)) & 1
        else:
            is_safe = 0
        
        if is_safe:
            if write: res[reslen] = b
            reslen += 1
        else:
            modified = 1
            if write:
                res[reslen] = 37 # '%'
                res[reslen + 1] = hex_digits[b >> 4]
                res[reslen + 2] = hex_digits[b & 0xF]
            reslen += 3
    
    return reslen if modified else 0

def compile_safe(safe, flags=0):
    safeblob = array('I', [flags, _SAFEBLOB_BASE_1, _SAFEBLOB_BASE_2, _SAFEBLOB_BASE_3])
    for c in safe:
        if isinstance(c, str):
            c = ord(c)
        if 32 <= c <= 127:
            safeblob[(c >> 5)] |= (1 << (c & 31))
    return safeblob

def _quote(s, safeblob):
    if isinstance(s, (memoryview, bytes, bytearray)):
        src = s
#    elif isinstance(s, str):
#        src = s.encode("utf-8")
    else:
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        # if this doesn't work for some reason, enable the 'elif' code above
        src = memoryview(s)
    
    srclen = len(src)
    if srclen == 0:
        return ""
    
    reslen = _quote_helper(src, srclen, safeblob, 0)
    if reslen <= 0:
        if isinstance(s, str):
            return s
        elif isinstance(s, (bytes, bytearray)):
            return s.decode("ascii")
        else:
            return bytes(s).decode("ascii")
    
    res = bytearray(reslen)
    _quote_helper(src, srclen, safeblob, addressof(res))
    return res.decode("ascii")

def quote(string, safe="/", encoding=None, errors=None): # encoding and errors are unused
    if safe == "/":
        return _quote(string, _SAFEBLOB_QUOTE)
    else:
        return _quote(string, compile_safe(safe, 0))

def quote_plus(string, safe="", encoding=None, errors=None): # encoding and errors are unused
    if safe == "":
        return _quote(string, _SAFEBLOB_QUOTE_PLUS)
    else:
        return _quote(string, compile_safe(safe, 1))

def quote_from_bytes(string, safe="/"):
    if safe == "/":
        return _quote(string, _SAFEBLOB_QUOTE)
    else:
        return _quote(string, compile_safe(safe, 0))



_HEX_TO_INT = const(b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")

@micropython.viper
def _unquote_helper(src: ptr8, srclen: int, flags: int, res: ptr8) -> int:
    write = int(res) != 0
    modified = 0
    reslen = 0
    n1 = n2 = b = 0
    
    hex_to_int = ptr8(addressof(_HEX_TO_INT))
    
    i = 0
    while (i < srclen):
        b = src[i]
        i += 1
        
        if b == 37: # '%'
            if (i + 1 < srclen):
#                n1 = src[i+0]
#                if   48 <= n1 <= 57: n1 -= 48
#                elif 65 <= n1 <= 70: n1 -= 55
#                elif 97 <= n1 <=102: n1 -= 87
#                else: n1 = 255
                n1 = hex_to_int[src[i+0]]
                
#                n2 = src[i+1]
#                if   48 <= n2 <= 57: n2 -= 48
#                elif 65 <= n2 <= 70: n2 -= 55
#                elif 97 <= n2 <=102: n2 -= 87
#                else: n2 = 255
                n2 = hex_to_int[src[i+1]]
            else:
                n1 = 255
                n2 = 255
            
            if n1 != 255 and n2 != 255:
                modified = 1
                b = (n1 << 4) | (n2 << 0)
                i += 2
        
        elif b == 43 and flags == 1: # '+'
            modified = 1
            b = 32 # space
        
        if write:
            res[reslen] = b
        reslen += 1
    
    return reslen if modified else 0

def _unquote(s, start, end, flags: int) -> bytes:
    # if s is a string, then start and end should be 0 and None
    # otherwise you're going to have a very bad time
    if isinstance(s, (memoryview, bytes, bytearray)):
        src = s
#    elif isinstance(s, str):
#        src = s.encode("utf-8")
    else:
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        # if this doesn't work for some reason, enable the 'elif' code above
        src = memoryview(s)
    
    srclen = len(src)
    if srclen == 0:
        return b""
    
    noslice = (start == 0 and end is None)
    if end is None or end > srclen:
        end = srclen
    if start < 0:
        start = 0
    if start >= end:
        return b""
    
    adr = addressof(src)
    reslen = _unquote_helper(adr + start, end - start, flags, 0)
    if reslen <= 0:
        if isinstance(s, str):
            res = s.encode("utf-8")
        elif isinstance(s, bytes):
            res = s
        elif not noslice and isinstance(s, (bytearray, memoryview)):
            # slight peak memory saving over the default code path
            return bytes(s[start:end])
        else:
            res = bytes(s)
        if noslice:
            return res
        else:
            return res[start:end]
    
    res = bytearray(reslen)
    _unquote_helper(adr + start, end - start, flags, addressof(res))
    return bytes(res)

def unquote(s, encoding="utf-8", errors="replace"):
    return _unquote(s, 0, None, 0).decode(encoding) # errors is not supported on micropython

def unquote_plus(s, encoding="utf-8", errors="replace"):
    return _unquote(s, 0, None, 1).decode(encoding) # errors is not supported on micropython

def unquote_to_bytes(s) -> bytes:
    return _unquote(s, 0, None, 0)



def _urlencode_generator(query, doseq=False, safe="", encoding=None, errors=None, quote_via=quote_plus):
    if isinstance(query, dict):
        query = query.items()
    for key, val in query:
        if not isinstance(key, (str, bytes, bytearray, memoryview)):
            key = str(key)
        key = quote_via(key, safe, encoding, errors)
        if isinstance(val, (str, bytes, bytearray, memoryview)):
            pass
        elif doseq:
            for v in val:
                if not isinstance(v, (str, bytes, bytearray, memoryview)):
                    v = str(v)
                yield key + "=" + quote_via(v, safe, encoding, errors)
            continue
        else:
            val = str(val)
        yield key + "=" + quote_via(val, safe, encoding, errors)

def urlencode(query, *args, **kwargs) -> str:
    return "&".join(_urlencode_generator(query, *args, **kwargs))



@micropython.viper
def _mv_find(mv: ptr8, b: int, start: int, end: int) -> int:
    i = start
    while i < end:
        if mv[i] == b:
            return i
        i += 1
    return -1

def _parse_generator(qs, keep_blank_values=False, strict_parsing=False,
                     encoding="utf-8", errors="replace",
                     max_num_fields=None, separator='&'):
    if isinstance(qs, (memoryview, bytes, bytearray)):
        src = qs
#    elif isinstance(qs, str):
#        src = qs.encode("utf-8")
    else:
        # on micropython, memoryview(str) gives you direct access to the underlying bytes
        # if this doesn't work for some reason, enable the 'elif' code above
        src = memoryview(qs)
    n = len(src)
    if n == 0:
        return
    
    sep = ord(separator)  # works if separator is string-like length 1; otherwise error
    i = 0
    num_fields = 0
    
    while i <= n:
        num_fields += 1
        if max_num_fields is not None and num_fields > max_num_fields:
            raise ValueError("max_num_fields exceeded")
        
        j = _mv_find(src, sep, i, n)
        if j < 0:
            j = n
        eq = _mv_find(src, 61, i, j) # '='
        
        try:
            if eq >= 0:
                # key=value
                if keep_blank_values or (eq + 1 < j):
                    key = _unquote(src, i, eq, 1).decode(encoding)
                    val = _unquote(src, eq + 1, j, 1).decode(encoding)
                    yield key, val
            else:
                # key (no '=')
                if strict_parsing:
                    raise ValueError("bad query field")
                if keep_blank_values:
                    key = _unquote(src, i, j, 1).decode(encoding)
                    yield key, ""
        except UnicodeError:
            if errors == "strict":
                raise
        
        if j == n:
            break
        i = j + 1

def parse_qs(qs, *args, **kwargs) -> dict:
    res = {}
    for key, val in _parse_generator(qs, *args, **kwargs):
        if key in res:
            res[key].append(val)
        else:
            res[key] = [val]
    return res

def parse_qsl(qs, *args, **kwargs) -> list:
    return list(_parse_generator(qs, *args, **kwargs))

def urldecode(qs, *args, **kwargs) -> dict:
    res = {}
    for key, val in _parse_generator(qs, *args, **kwargs):
        res[key] = val
    return res



def locsplit_as_tuple(netloc: str) -> tuple: # extension
    if (sep := netloc.rfind('@')) >= 0:
        userpass, hostport = netloc[:sep], netloc[sep+1:]
        if (sep := userpass.find(':')) >= 0:
            username, password = userpass[:sep], userpass[sep+1:]
        else:
            username, password = userpass, None
    else:
        hostport = netloc
        username, password = None, None
    
    if hostport and hostport[0] == '[': # Handle IPv6 (simple check)
        if (sep := hostport.find(']')) >= 0:
            host, port = hostport[1:sep], hostport[sep+1:]
        else: # *shrug*
            host, port = hostport, ""
    else:
        if (sep := hostport.rfind(':')) >= 0:
            host, port = hostport[:sep], hostport[sep:]
        else:
            host, port = hostport, ""
    
    if host:
        # Preserve zone ID case for IPv6 scoped addresses
        if (sep := host.find('%')) >= 0:
            host = host[:sep].lower() + host[sep:]
        else:
            host = host.lower()
    else:
        host = None
    
    if port == "":
        port = None
    elif port.startswith(":"):
        try:
            n = int(port[1:], 10)
            if 0 <= n <= 65535:
                port = n
        except ValueError:
            pass
    
    return (username, password, host, port)

def locsplit(netloc: str) -> tuple: # extension
    return dict(zip(('username', 'password', 'hostname', 'port'), locsplit_as_tuple(netloc)))

# derived from CPython (all bugs are mine)
def urlsplit_as_tuple(url: str, scheme, allow_fragments: bool) -> tuple:
#    assert (isinstance(url, str))
    
    if url and ord(url[0]) <= 32:
        url = url.lstrip()
    if scheme: # and (ord(scheme[0]) <= 32 or ord(scheme[-1]) <= 32):
        scheme = scheme.strip()
    
    netloc = query = fragment = None
    if (colon := url.find(':')) > 0 and url[0].isalpha():
        if (slash := url.find('/')) < 0 or colon < slash:
            scheme, url = url[:colon].lower(), url[colon+1:]
    if url.startswith("//"):
        delim = len(url)
        for c in "/?#":
            if 0 <= (x := url.find(c, 2)) < delim:
                delim = x
        netloc, url = url[2:delim], url[delim:]
    
    if allow_fragments and (i := url.find('#')) >= 0:
        url, fragment = url[:i], url[i+1:]
    
    if (i := url.find('?')) >= 0:
        url, query = url[:i], url[i+1:]
    
    return (scheme, netloc, url, query, fragment)

class SplitResult(tuple):
    
    def __init__(self, scheme, netloc, path, query, fragment):
        super().__init__((scheme or "", netloc or "", path or "", query or "", fragment or ""))
        self.username, self.password, self.hostname, self._port = locsplit_as_tuple(self[1])
#        self._args = (scheme, netloc, path, query, fragment)
    
    @property
    def scheme(self): return self[0]
    
    @property
    def netloc(self): return self[1]
    
    @property
    def path(self): return self[2]
    
    @property
    def query(self): return self[3]
    
    @property
    def fragment(self): return self[4]
    
    @property
    def port(self):
        if self._port == ":":
            return None
        if self._port is None or isinstance(self._port, int):
            return self._port
        raise ValueError("bad port number")
    
    def geturl(self):
#        return urlunsplit(self._args)
        return urlunsplit(self)

def urlsplit(url: str, scheme="", allow_fragments=True) -> SplitResult:
    return SplitResult(*urlsplit_as_tuple(url, scheme, allow_fragments))



# derived from CPython (all bugs are mine)
def _urlunsplit(scheme, netloc, path, query, fragment) -> str:
    parts = []
    
    if scheme is not None:
        parts.append(scheme)
        parts.append(":")
    
    if netloc is not None:
        parts.append("//")
        parts.append(netloc)
        if not path.startswith("/"):
            parts.append("/")
        parts.append(path)
    else:
        if path.startswith("//"):
            parts.append("//")
        parts.append(path)
    
    if query is not None:
        parts.append("?")
        parts.append(query)
    
    if fragment is not None:
        parts.append("#")
        parts.append(fragment)
    
    return "".join(parts)

def urlunsplit(components: tuple) -> str:
    scheme, netloc, path, query, fragment = components
    if not netloc:
        if scheme and scheme in _USES_NETLOC and (not path or path[0] == '/'):
            netloc = ""
        else:
            netloc = None
    return _urlunsplit(scheme or None, netloc, path or "", query or None, fragment or None)



# derived from CPython (all bugs are mine)
def urljoin(base: str, url: str, allow_fragments: bool=True) -> str:
    if not base:
        return url
    if not url:
        return base
    
    bscheme, bnetloc, bpath, bquery, bfragment = urlsplit_as_tuple(base, None, allow_fragments)
    scheme, netloc, path, query, fragment = urlsplit_as_tuple(url, None, allow_fragments)
    
    if scheme is None:
        scheme = bscheme
    if scheme != bscheme or (scheme and scheme not in _USES_RELATIVE):
        return url
    if not scheme or scheme in _USES_NETLOC:
        if netloc:
            return urlunsplit((scheme, netloc, path, query, fragment))
        netloc = bnetloc
    
    if not path:
        path = bpath
        if query is None:
            query = bquery
            if fragment is None:
                fragment = bfragment
        return _urlunsplit(scheme, netloc, path, query, fragment)
    
    base_parts = bpath.split('/')
    if base_parts[-1] != "":
        # the last item is not a directory, so will not be taken into account
        # in resolving the relative path
        del base_parts[-1]
    
    # for rfc3986, ignore all base path should the first character be root.
    if path[0] == '/': # `not path` was already checked earlier
        segments = path.split('/')
    else:
        segments = base_parts + path.split('/')
        # Remove empty segments in the middle (keep first and last as-is)
        w = 1
        for r in range(1, len(segments) - 1):
            seg = segments[r]
            if seg:
                segments[w] = seg
                w += 1
        # delete the now-unused tail (but preserve the last element)
        del segments[w:len(segments) - 1]
    
    resolved_path = []
    for seg in segments:
        if seg == "..":
            if resolved_path:
                resolved_path.pop()
        elif seg != ".":
            resolved_path.append(seg)
    
    if segments[-1] in (".", ".."):
        # do some post-processing here. if the last segment was a relative dir,
        # then we need to append the trailing '/'
        resolved_path.append("")
    
    return _urlunsplit(scheme, netloc, "/".join(resolved_path) or "/", query, fragment)
