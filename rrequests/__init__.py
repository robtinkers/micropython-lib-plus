import json as json_lib

# Robust imports to handle both package-based and root-based file placement
try:
    from urllib.parse import urlsplit, urljoin, urlencode
except ImportError:
    from parse import urlsplit, urljoin, urlencode

try:
    import http.client_ish as http_client
except ImportError:
    import client_ish as http_client

# --- Exceptions ---

class RequestException(Exception): pass
class HTTPError(RequestException): pass
class ConnectionError(RequestException): pass
class Timeout(RequestException): pass
class TooManyRedirects(RequestException): pass

# --- Status Codes ---

class Codes:
    def __init__(self):
        self.ok = 200
        self.created = 201
        self.accepted = 202
        self.no_content = 204
        self.moved_permanently = 301
        self.found = 302
        self.bad_request = 400
        self.unauthorized = 401
        self.forbidden = 403
        self.not_found = 404
        self.internal_server_error = 500
codes = Codes()

# --- Helper Functions ---

def _encode_files(files, data):
    """
    Multipart-encoded file uploader.
    Returns (content_type, body_bytes)
    """
    try:
        import urandom as random
    except ImportError:
        import random
    
    boundary = "==" + "".join([str(random.getrandbits(4)) for _ in range(30)]) + "=="
    lines = []
    
    if data:
        for key, value in data.items():
            lines.append("--" + boundary)
            lines.append("Content-Disposition: form-data; name=\"{}\"".format(key))
            lines.append("")
            lines.append(str(value))
    
    if files:
        for key, value in files.items():
            filename = ""
            fn_content = None
            content_type = "application/octet-stream"
            
            if isinstance(value, (tuple, list)):
                filename = value[0]
                fn_content = value[1]
                if len(value) > 2:
                    content_type = value[2]
            else:
                try:
                    filename = value.name
                except AttributeError:
                    filename = key
                fn_content = value
            
            if hasattr(fn_content, "read"):
                file_data = fn_content.read()
            else:
                file_data = fn_content
            
            lines.append("--" + boundary)
            lines.append("Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"".format(key, filename))
            lines.append("Content-Type: {}".format(content_type))
            lines.append("")
            lines.append(file_data)
    
    lines.append("--" + boundary + "--")
    lines.append("")
    
    body = bytearray()
    for line in lines:
        if isinstance(line, str):
            body.extend(line.encode("utf-8"))
        else:
            body.extend(line)
        body.extend(b"\r\n")
    
    content_type = "multipart/form-data; boundary={}".format(boundary)
    return content_type, body

# --- Core Classes ---

class Response:
    def __init__(self, connection, raw_response, stream=False):
        self._connection = connection
        self._response = raw_response
        
        self.status_code = self._response.status
        self.reason = self._response.reason
        self.url = None
        
        self._headers = None
        self._cookies = None
        self._content = None
        
        self.encoding = "utf-8"
        for part in self._response.getheader("content-type", "").split(";"):
            part = part.lstrip()
            if part.startswith("charset="):
                self.encoding = part[8:].strip().strip('"')
        
        if not stream:
            _ = self.headers
            _ = self.cookies
            _ = self.content
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
    
    def __del__(self):
        self.close()
    
    def __bool__(self):
        return (self.status_code < 400)
    
    def close(self):
        if self._response:
            self._response.close()
            self._response = None
        if self._connection:
            self._connection.close()
            self._connection = None
    
    @property
    def headers(self):
        if self._headers is None:
            self._headers = dict(self._response.getheaders())
        return self._headers
    
    @property
    def cookies(self):
        if self._cookies is None:
            self._cookies = dict(self._response.getcookies())
        return self._cookies
    
    @property
    def content(self):
        if self._content is None:
            if self._response:
                try:
                    self._content = self._response.read()
                finally:
                    self.close()
            else:
                self._content = b""
        return self._content
    
    @property
    def text(self):
        content = self.content
        if not content:
            return ""
        try:
            return content.decode(self.encoding, "strict")
        except UnicodeError:
            return content.decode("utf-8", "ignore")
    
    def json(self):
        return json_lib.loads(self.content)
    
    def json_partial(self, chunk_size, *args):
        stop_markers = [arg.encode(self.encoding) if isinstance(arg, str) else arg for arg in args]
        suffix = stop_markers.pop() if stop_markers else None
        
        if self._content is None:
            content = self._response.read(chunk_size)
            self.close()
        else:
            content = self._content
        
        first_marker_pos = len(content)
        for marker in stop_markers:
            pos = content.find(marker)
            if pos != -1 and pos < first_marker_pos:
                first_marker_pos = pos
        if suffix is None:
            return json_lib.loads(content[:first_marker_pos])
        else:
            return json_lib.loads(content[:first_marker_pos] + suffix)
    
    def raise_for_status(self):
        if 400 <= self.status_code < 500:
            raise HTTPError(f"{self.status_code} Client Error: {self.reason} for url: {self.url}")
        elif 500 <= self.status_code < 600:
            raise HTTPError(f"{self.status_code} Server Error: {self.reason} for url: {self.url}")
    
    def iter_content(self, chunk_size=1024):
        if self._content is not None:
            yield self._content
            return
        if self._response is None:
            return
        try:
            while True:
                chunk = self._response.read(chunk_size)
                if not chunk:
                    break
                yield chunk
        finally:
            self.close()

class Session:
    def __init__(self):
        self.headers = {}
        self.cookies = {} 
        self.auth = None
        self.params = {}
        self.verify = True 
        self.max_redirects = 30
    
    def request(self, method, url, 
                params=None, 
                data=None, 
                headers=None, 
                cookies=None, 
                files=None, 
                auth=None,
                timeout=None, 
                allow_redirects=True, 
                proxies=None, 
                hooks=None, 
                stream=False, 
                verify=None, 
                cert=None, 
                json=None,
                extra_headers=True,
                parse_cookies=True
            ):
        
        req_headers = self.headers.copy()
        if headers:
            req_headers.update(headers)
        
        req_auth = auth if auth is not None else self.auth
        
        if params:
            qs = urlencode(params)
            if "?" in url:
                url += "&" + qs
            else:
                url += "?" + qs
        
        body = None
        if json is not None:
            body = json_lib.dumps(json)
            req_headers["Content-Type"] = "application/json"
        elif files:
            content_type, body = _encode_files(files, data)
            req_headers["Content-Type"] = content_type
        elif data:
            if isinstance(data, dict):
                body = urlencode(data)
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body = data
        
        if callable(req_auth):
            req_headers.update(req_auth())
        elif isinstance(req_auth, tuple):
            import ubinascii
            token = ubinascii.b2a_base64(":".join(req_auth).encode("utf-8")).strip()
            req_headers["Authorization"] = b"Basic " + token
        
        history = []
        _redirects = 0

        q = urlsplit(url)
        while True:
            p = q
            
            scheme = p.scheme
            host = p.hostname
            port = p.port
            path = p.path or "/"
            if p.query:
                path += "?" + p.query
            
            if scheme == "https":
                connection_class = http_client.HTTPSConnection
            else:
                connection_class = http_client.HTTPConnection
            
            req_cookies = self.cookies.copy()
            if cookies:
                req_cookies.update(cookies)
            
            connection = None
            try:
                connection = connection_class(host, port=port, timeout=timeout)
                connection.request(method.upper(), path, body=body, headers=req_headers, cookies=req_cookies)
                
                raw_response = connection.getresponse(extra_headers=extra_headers, parse_cookies=parse_cookies)
                
                resp = Response(connection, raw_response, stream=stream)
                resp.url = url
                connection = None  # Response owns it now
                
                if resp.cookies:
                    self.cookies.update(resp.cookies)
                
                if allow_redirects and resp.status_code in [301, 302, 303, 307, 308]:
                    if _redirects >= self.max_redirects:
                        raise TooManyRedirects("Exceeded {} redirects.".format(self.max_redirects))
                    
                    history.append(resp)
                    _redirects += 1
                    
                    resp.close() 
                    
                    location = resp.headers.get("location")
                    if not location:
                        resp.history = history
                        return resp
                    
                    url = urljoin(url, location)
                    
                    q = urlsplit(url)
                    if p.hostname != q.hostname or p.port != q.port:
                        for key in list(req_headers.keys()):
                            if key.lower() in ["authorization"]:
                                del req_headers[key]
                    
                    if resp.status_code in [301, 302, 303]:
                        for key in list(req_headers.keys()):
                            if key.lower() in ["content-type", "content-length", "transfer-encoding"]:
                                del req_headers[key]
                        if resp.status_code == 303 or method.upper() == "POST":
                            method = "GET"
                        body = None
                    
                    continue
                
                return resp
            
            except OSError as e:
                raise ConnectionError(e)
            
            finally:
                if connection is not None:
                    connection.close()
    
    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)
    
    def options(self, url, **kwargs):
        return self.request("OPTIONS", url, **kwargs)
    
    def head(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", False)
        return self.request("HEAD", url, **kwargs)
    
    def post(self, url, data=None, json=None, **kwargs):
        return self.request("POST", url, data=data, json=json, **kwargs)
    
    def put(self, url, data=None, **kwargs):
        return self.request("PUT", url, data=data, **kwargs)
    
    def patch(self, url, data=None, **kwargs):
        return self.request("PATCH", url, data=data, **kwargs)
    
    def delete(self, url, **kwargs):
        return self.request("DELETE", url, **kwargs)
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass

# --- Module Level API ---

def request(method, url, **kwargs):
    with Session() as session:
        return session.request(method, url, **kwargs)

def get(url, params=None, **kwargs):
    return request("GET", url, params=params, **kwargs)

def options(url, **kwargs):
    return request("OPTIONS", url, **kwargs)

def head(url, **kwargs):
    return request("HEAD", url, **kwargs)

def post(url, data=None, json=None, **kwargs):
    return request("POST", url, data=data, json=json, **kwargs)

def put(url, data=None, **kwargs):
    return request("PUT", url, data=data, **kwargs)

def patch(url, data=None, **kwargs):
    return request("PATCH", url, data=data, **kwargs)

def delete(url, **kwargs):
    return request("DELETE", url, **kwargs)
