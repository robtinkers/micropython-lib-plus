
_QUOTE_PLUS = {
    ord('\t'):'%09',
    ord('\n'):'%0A',
    ord('\r'):'%0D',
    ord('"'): '%22',
    ord('#'): '%23',
    ord('%'): '%25',
    ord('&'): '%26',
    ord("'"): '%27',
    ord('+'): '%2B',
    ord('/'): '%2F',
    ord(';'): '%3B',
    ord('='): '%3D',
    ord('?'): '%3F',
    ord(' '): '+',
}

def quote_plus(s, safe=''):
    # Similar to Cpython but uses a blacklist for efficiency
    # Adapted from micropython-lib string.translate()
    import io

    sb = io.StringIO()
    for c in s:
        v = ord(c)
        if v in _QUOTE_PLUS and c not in _safe:
            v = _QUOTE_PLUS[v]
            if isinstance(v, int):
                sb.write(chr(v))
            elif v is not None:
                sb.write(v)
        else:
            sb.write(c)
    return sb.getvalue()

def quote(s, safe='/'):
    # Similar to Cpython but uses a blacklist for efficiency
    s = quote_plus(s, safe)
    if '+' in s:  # Avoid creating a new object if not necessary
        s = s.replace('+', '%20')
    return s

def unquote(s):
    # Similar to Cpython. Raises ValueError if unable to percent-decode.
    if '%' not in s:
        return s
    parts = s.split('%')
    result = bytearray()
    result.extend(parts[0].encode())
    for item in parts[1:]:
        if len(item) < 2:
            raise ValueError()
        result.append(int(item[:2], 16))
        result.extend(item[2:].encode())
    return result.decode()

def unquote_plus(s):
    # Similar to Cpython
    if '+' in s:  # Avoid creating a new object if not necessary
        s = s.replace('+', ' ')
    return unquote(s)

def urlencode(data):
    # Similar to Cpython
    parts = []
    for key, val in data.items():
        if True:  # emulates quote_via=quote_plus
            key, val = quote_plus(key), quote_plus(val)
        if key:
            parts.append(key + '=' + val)
    return '&'.join(parts)

def urldecode(qs):
    # Similar to CPython but returns a simple dict, not a dict of lists.
    # For example, urldecode('foo=1&bar=2&baz') returns {'foo': '1', 'bar': '2', 'baz': ''}.
    data = {}
    parts = qs.split('&')
    for part in parts:
        key, sep, val = part.partition('=')
        if True:
            key, val = unquote_plus(key), unquote_plus(val)
        if key:
            data[key] = val
    return data

