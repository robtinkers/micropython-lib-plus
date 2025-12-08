import http.client
import json as ujson
from ubinascii import b2a_base64
from urllib.parse import netlocsplit, urlsplit, urljoin, urlencode

class Response:
    def __init__(self, raw):
        self.raw = raw
        self._content = None
        self.encoding = 'utf-8'
    
    @property
    def status_code(self):
        return self.raw.status
    
    @property
    def reason(self):
        return self.raw.reason
    
    @property
    def headers(self):
        return self.raw.headers
    
    @property
    def cookies(self):
        return self.raw.cookies
    
    @property
    def content(self):
        if self._content is None:
            self._content = self.raw.read()
        return self._content
    
    @property
    def text(self):
        return str(self.content, self.encoding)
    
    def json(self):
        return ujson.loads(self.content)
    
    def close(self):
        self.raw.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

def request(method, url, data=None, *, json=None, params=None, headers=None, cookies=None, auth=None, stream=False, timeout=None, redirects=True):
    if headers is None:
        headers = {}
    else:
        headers = headers.copy() # Copy headers to avoid mutating caller's dict
    
    if cookies is None:
        cookies = {}
    else:
        cookies = cookies.copy() # Copy cookies to avoid mutating caller's dict
    
    # Normalize redirects
    if redirects is True:
        redirects = 5
    elif not redirects:
        redirects = 0
    else:
        redirects = int(redirects)
    
    # Handle json
    if data is None and json is not None:
        data = ujson.dumps(json)
        if 'Content-Type' not in headers:
            headers = headers.copy()
            headers['Content-Type'] = 'application/json'
    
    # Update url (strip fragment and add params)
    url = url.split('#', 1)[0]
    if params:
        url += ('&' if '?' in url else '?') + urlencode(params)
    
    while True:
        # Prepare headers for this specific loop iteration
        req_headers = headers.copy()
        
        # Parse url
        scheme, netloc, path, query, _ = urlsplit(url)
        username, password, host, port = netlocsplit(netloc)
        
        # Determine Protocol and Port
        if scheme == 'https':
            conn_class = http.client.HTTPSConnection
        elif scheme == 'http':
            conn_class = http.client.HTTPConnection
        else:
            raise ValueError("Unsupported protocol: " + scheme)
        
        # Handle Auth
        if username is not None:
            if password is not None:
                credentials = f"{username}:{password}"
            else:
                credentials = username
        elif auth is not None:
            credentials = ':'.join(auth)
        else:
            credentials = None
        
        if credentials is not None:
            auth_b64 = b2a_base64(credentials.encode('utf-8')).strip()
            req_headers['Authorization'] = b'Basic ' + auth_b64
        
        # Create Request
        conn = conn_class(host, port=port, timeout=timeout)
        
        # Send Request
        conn.request(method, path, body=data, headers=req_headers, cookies=cookies.items())
        
        # Get Response
        resp = Response(conn.getresponse())
        
        # Update Cookie Jar
        if resp.cookies:
            cookies.update(resp.cookies)
        
        # Check for Redirects
        if redirects > 0 and resp.status_code in [301, 302, 303, 307, 308]:
            location = resp.raw.getheader('Location')
            
            if location:
                conn.close()
                redirects -= 1
                
                old_method = method
                old_scheme = scheme
                old_host = host
                old_port = port
                
                if resp.status_code in [301, 302, 303]:
                    method = 'GET'
                
                if (method != old_method):
                    data = None
                    for key in headers.keys():
                        if key.lower() == 'content-type':
                            del headers[key]
                
                url = urljoin(url, location)
                scheme, netloc, path, query, _ = urlsplit(url)
                username, password, host, port = netlocsplit(netloc)
                
                if (scheme != old_scheme) or (host != old_host) or (port != old_port):
                    # Empty the cookie jar
                    cookies = {}
                    # Delete the auth info
                    auth = None
                    #TODO: are there headers we should delete?
                
                continue
        
        if not stream:
            _ = resp.content
        
        return resp

# Method shortcuts
def get(url, **kwargs):
    return request("GET", url, **kwargs)

def post(url, **kwargs):
    return request("POST", url, **kwargs)

def put(url, **kwargs):
    return request("PUT", url, **kwargs)

def patch(url, **kwargs):
    return request("PATCH", url, **kwargs)

def delete(url, **kwargs):
    return request("DELETE", url, **kwargs)

def head(url, **kwargs):
    return request("HEAD", url, **kwargs)

