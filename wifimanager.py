# very much a work in progress

import micropython, network, os, time

class WifiManager:

    def __init__(self, *, filename=None, timeout=10):
        self._filename = filename
        self._timeout = timeout
        self._sta_if = network.WLAN(network.STA_IF)
        self.reset_networks()

    def reset_networks(self):
        self._networks = []

    def list_networks(self, td="", tdx=",", tr="", trx="\n", tb="\n", tbx="\n", *, encoding="utf-8"):
        result = ""
        if tb:
            result += tb
        for nw in self._networks:
            if tr:
                result += tr
            for p in nw:
                if td:
                    result += td
                result += p.decode(encoding) if isinstance(p, bytes) else str(p)
                if tdx:
                    result += tdx
            if trx:
                result += trx
        if tbx:
            result += tbx
        return result

    def load_networks(self, filename=None):
        if filename is None:
            filename = self._filename
        self.reset_networks()
        try:
            with open(filename, "rb") as fh:
                for nw in fh.read().split(b"\n"):
                    stripped = nw.rstrip(b"\r")
                    if stripped:
                        self._networks.append(stripped.split(b"\t"))
            return True
        except OSError:
            return False

    def save_networks(self, filename=None):
        if filename is None:
            filename = self._filename
        tempfile = filename + ".tmp"
        data = b"\n".join(b"\t".join(nw) for nw in self._networks)
        try:
            with open(tempfile, "wb") as fh:
                fh.write(data)
            os.rename(tempfile, filename)
            return True
        except OSError:
            return False
        finally:
            try:
                os.remove(tempfile)
            except Exception:
                pass

    def add_network(self, *params):
        len_params = len(params)
        if len_params == 0:
            return False
        params = [p.encode("utf-8") if isinstance(p, str) else p for p in params]
        if len_params == 1:
            params.append(b'')
            len_params = 2

        for i in range(len(self._networks)):
            if len(self._networks[i]) == len_params:
                if all(self._networks[i][j] == params[j] for j in range(len_params)):
                    return False
        self._networks.append(params)
        return True

    def del_network(self, *params):
        len_params = len(params)
        if len_params == 0:
            return False
        params = [p.encode("utf-8") if isinstance(p, str) else p for p in params]
        if len_params == 1:
            params.append(b'')
            len_params = 2

        n = 0
        i = 0
        while i < len(self._networks):
            if len(self._networks[i]) == len_params:
                if all(self._networks[i][j] == params[j] for j in range(len_params)):
                    del self._networks[i]
                    n += 1
                    continue
            i += 1
        return n

    def connect_to_wifi(self, timeout=None):
        if timeout is None:
            timeout = self._timeout

        ap_if = network.WLAN(network.AP_IF)
        try:
            ap_if.disconnect()
        except Exception:
            pass
        try:
            ap_if.active(False)
        except Exception:
            pass
        del ap_if

        sta_if = self._sta_if
        sta_if.active(True)
        scanned = sta_if.scan()
        scanned.sort(key=lambda x: -x[3])

        for scan in scanned:
            for nw in self._networks:
                if scan[0] != nw[0]:
                    continue

                try:
                    sta_if.disconnect()
                except Exception:
                    pass

                ticks0 = time.ticks_ms()

                print('Connecting to', repr(nw), end='')
                connect_params = list(nw)
                if len(connect_params) == 1:
                    connect_params.append(b'')
                sta_if.connect(*connect_params)

                i = 0
                while not sta_if.isconnected() and time.ticks_diff(time.ticks_ms(), ticks0) < (timeout * 1000):
                    i += 1
                    if (i % 10) == 0:
                        print('.', end='')
                    time.sleep_ms(100)

                if not sta_if.isconnected():
                    print(' timeout')
                    continue
                print(' Connected!')

                return True

        return False
