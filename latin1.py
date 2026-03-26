
@micropython.viper
def _is_visible_latin1(buf:ptr8, buflen:int) -> int:
    i = 0
    while (i < buflen):
        b = buf[i]
        i += 1
        if b < 32 or (127 <= b < 160):
            return 0
    return 1

def latin1_to_utf8(s):
    @micropython.viper
    def latin1_to_utf8_helper(src: ptr8, srclen: int, dst: ptr8) -> int:
        write = int(dst) != 0
        dstlen = 0
        is7bit = 1
        
        i = 0
        while (i < srclen):
            b = src[i]
            i += 1
            
            if b < 128:
                if write:
                    dst[dstlen] = b
                dstlen += 1
            elif b < 192:
                is7bit = 0
                if write:
                    dst[dstlen+0] = 0xC2
                    dst[dstlen+1] = b
                dstlen += 2
            else:
                is7bit = 0
                if write:
                    dst[dstlen+0] = 0xC3
                    dst[dstlen+1] = b - 64
                dstlen += 2
        
        return 0 if is7bit else dstlen
    
    len_s = len(s)
    if len_s == 0:
        return b''
    utf8len = latin1_to_utf8_helper(s, len_s, 0)
    if utf8len == 0:
        return s.decode()
    utf8buf = bytearray(utf8len)
    latin1_to_utf8_helper(s, len_s, utf8buf)
    return utf8buf.decode()

print(latin1_to_utf8(b'hello!'))
print(latin1_to_utf8(b'\xDF\xCA\x54\xC5'))

