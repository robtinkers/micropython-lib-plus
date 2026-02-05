# robtinkers/i2c.py

from micropython import const
import machine
import time  # only needed for _SimpleLock
import struct  # only needed for I2CDeviceMixInStructs and I2CStruct

MODE_8 = "8"
MODE_16BE = "16BE"
MODE_16LE = "16LE"

_ACQUIRE_BUS = (False,)
_ACQUIRE_DEV = (True,)


try:
    import _thread
except ImportError:
    _thread = None

    class _SimpleLock:
        # A very simple lock implementation that should only be used when _thread.allocate_lock is not available
        # It is not thread-safe, but is otherwise sufficient for the purposes of this library
        
        def __init__(self):
            self._locked = False
        
        def locked(self):
            return self._locked
        
        def acquire(self, blocking=True):
            if not blocking:
                if self._locked:
                    return False
                self._locked = True
                return True
            while self._locked:
                time.sleep_ms(1)
            self._locked = True
            return True
        
        def release(self):
            if self._locked:
                self._locked = False
            else:
                raise RuntimeError("Release unlocked lock")

def _allocate_lock():
    if _thread is None:
        return _SimpleLock()
    else:
        return _thread.allocate_lock()


class I2CBus:
    # based on the CircuitPython busio.i2c.I2C interface
    
    def __init__(self, i2c_id, scl=None, sda=None, *, lock=None, **kwargs):
        if isinstance(i2c_id, int):
            self._i2c = machine.I2C(i2c_id, scl=scl, sda=sda, **kwargs)
        else:
            self._i2c = i2c_id
            if scl is not None or sda is not None or kwargs:
                raise TypeError("unexpected arguments")
        
        if lock is None:
            self._lock = _allocate_lock()
        else:
            self._lock = lock
        
        # Pre-allocated buffers for modify_mem to avoid fragmentation
        self._long = bytearray(4)
        mv = memoryview(self._long)
        self._word = mv[0:2]
        self._byte = mv[0:1]
    
    def __enter__(self):
        if not self._lock.acquire(*_ACQUIRE_BUS):
            raise RuntimeError("I2C bus lock failed")
        return self 
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.unlock()
        return False
    
    def try_lock(self):
        return self._lock.acquire(False)
    
    def unlock(self):
        self._lock.release()
    
    # Helper methods
    
    def _require_lock(self):
        if not self._lock.locked():
            raise RuntimeError("I2C bus is not locked")
    
    # MicroPython general operations
    
    def init(self, *args, **kwargs):
        raise NotImplementedError("I2CBus.init() is not implemented")
    
    def deinit(self):
        if self._i2c is not None:
            if hasattr(self._i2c, "deinit"):
                self._i2c.deinit()
            self._i2c = None
    
    # NOTE: Does not require the bus to be locked
    def scan(self):
        return self._i2c.scan()
    
    # MicroPython standard operations
    
    def readfrom(self, addr, nbytes, stop=True):
        self._require_lock()
        return self._i2c.readfrom(addr, nbytes, stop)
    
    # MicroPython has this natively, but without the start and end parameters needed for CircuitPython-compatibility
    def readfrom_into(self, addr, buf, stop=True, *, start=0, end=None):
        self._require_lock()
        if start == 0 and (end is None or end == len(buf)):
            return self._i2c.readfrom_into(addr, buf, stop)
        elif isinstance(buf, memoryview):
            return self._i2c.readfrom_into(addr, buf[start:end], stop)
        else:
            mv = memoryview(buf)
            return self._i2c.readfrom_into(addr, mv[start:end], stop)
    
    # MicroPython has this natively, but without the start and end parameters needed for CircuitPython-compatibility
    def writeto(self, addr, buf, stop=True, *, start=0, end=None):
        self._require_lock()
        if start == 0 and (end is None or end == len(buf)):
            return self._i2c.writeto(addr, buf, stop)
        elif isinstance(buf, memoryview):
            return self._i2c.writeto(addr, buf[start:end], stop)
        else:
            mv = memoryview(buf)
            return self._i2c.writeto(addr, mv[start:end], stop)
    
    def writevto(self, addr, vector, stop=True):
        self._require_lock()
        return self._i2c.writevto(addr, vector, stop)
    
    def readfrom_mem(self, addr, memaddr, nbytes, *, addrsize=8):
        self._require_lock()
        return self._i2c.readfrom_mem(addr, memaddr, nbytes, addrsize=addrsize)
    
    # MicroPython has this natively, but without the start and end parameters needed for CircuitPython-compatibility
    def readfrom_mem_into(self, addr, memaddr, buf, *, start=0, end=None, addrsize=8):
        self._require_lock()
        if start != 0 or (end is not None and end != len(buf)):
            if not isinstance(buf, memoryview):
                buf = memoryview(buf)
            buf = buf[start:end]
        return self._i2c.readfrom_mem_into(addr, memaddr, buf, addrsize=addrsize)
    
    # MicroPython has this natively, but without the start and end parameters needed for CircuitPython-compatibility
    def writeto_mem(self, addr, memaddr, buf, *, start=0, end=None, addrsize=8):
        self._require_lock()
        if start != 0 or (end is not None and end != len(buf)):
            if not isinstance(buf, memoryview):
                buf = memoryview(buf)
            buf = buf[start:end]
        return self._i2c.writeto_mem(addr, memaddr, buf, addrsize=addrsize)
    
    # Extension, needed for I2CDevice.write_register()
    def modify_mem(self, addr, memaddr, mode, setbits, clrbits=None, *, addrsize=8):
        self._require_lock()
        
        buf = self._byte if (mode == MODE_8) else self._word
        
        if clrbits is not None:
            self._i2c.readfrom_mem_into(addr, memaddr, buf, addrsize=addrsize)
            
            # Decode buffer to int
            if mode == MODE_16LE:
                val = buf[0] | (buf[1] << 8)
            elif mode == MODE_16BE:
                val = (buf[0] << 8) | buf[1]
            else:
                val = buf[0]
                
            val = (val & ~clrbits) | setbits
        else:
            val = setbits
        
        # Encode int to buffer
        if mode == MODE_16LE:
            buf[0], buf[1] = val & 0xFF, (val >> 8) & 0xFF
        elif mode == MODE_16BE:
            buf[0], buf[1] = (val >> 8) & 0xFF, val & 0xFF
        else:
            buf[0] = val & 0xFF
        
        self._i2c.writeto_mem(addr, memaddr, buf, addrsize=addrsize)
    
    # CircuitPython-specific operations
    
    def writeto_then_readfrom(self, addr, out_buffer, in_buffer, *, out_start=0, out_end=None, in_start=0, in_end=None):
        self._require_lock()
        try:
            self.writeto(addr, out_buffer, False, start=out_start, end=out_end)
            self.readfrom_into(addr, in_buffer, True, start=in_start, end=in_end)
        except OSError:
            try:
                self.writeto(addr, b"", True)
            except Exception:
                pass
            raise
    
    def probe(self, address):
        self._require_lock()
        result = False
        try:
            self._i2c.writeto(address, b"", True)
            result = True
        except OSError:
            pass
        return result


class I2CDevice:
    
    DEFAULT_ADDRESS = None
    DEFAULT_ADDRSIZE = const(8)
    
    def __init__(self, bus, address, *, probe=True, addrsize=None, retries=0, retry_delay_ms=5):
        self._bus = bus
        
        if addrsize is None:
            addrsize = self.DEFAULT_ADDRSIZE
        if addrsize != 8 and addrsize != 16:
            raise ValueError("addrsize must be 8 or 16")
        self._addrsize = addrsize
        
        self._retries = retries
        self._retry_delay_ms = retry_delay_ms
        
        self._long = bytearray(4)
        mv = memoryview(self._long)
        self._word = mv[0:2]
        self._byte = mv[0:1]
        
        self._in_context = False
        
        if address is None:
            address = self.DEFAULT_ADDRESS
        if address is None:
            raise ValueError("I2C device DEFAULT_ADDRESS not set")
        
        if getattr(self, 'SCRATCH_SIZE', None):
            self._scratch_ba = bytearray(self.SCRATCH_SIZE)
            self._scratch_mv = memoryview(self._scratch_ba)
        
        if isinstance(address, int) and not probe:
            self._address = address
            return
        
        with self._bus:
            result = None
            if isinstance(address, int):
                if self._bus.probe(address):
                    result = address
            else:
                for addr in address:
                    if self._bus.probe(addr):
                        if result is not None:
                            raise ValueError("Multiple devices found")
                        result = addr
            if result is None:
                raise ValueError("Device not found")
            self._address = result
    
    def __enter__(self):
        if self._in_context:
            raise RuntimeError("I2C device is already locked")
        if not self._bus._lock.acquire(*_ACQUIRE_DEV):
            raise RuntimeError("I2C bus lock failed")
        self._in_context = True
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self._in_context = False
        self._bus._lock.release()
        return False
    
    # Helper methods
    
    def _run(self, method, *args, retries=None, retry_delay_ms=None, **kwargs):
        if retries is None:
            retries = self._retries
        if retry_delay_ms is None:
            retry_delay_ms = self._retry_delay_ms
        
        just_locked = False
        if not self._in_context:
            if not self._bus._lock.acquire(*_ACQUIRE_DEV):
                raise RuntimeError("I2C bus lock failed")
            just_locked = True
        
        try:
            last_exc = None
            for i in range(max(1, retries + 1)):
                try:
                    if i > 0:
                        time.sleep_ms(retry_delay_ms)
                    return method(self._address, *args, **kwargs)
                except OSError as e:
                    last_exc = e
            if last_exc is not None:
                raise last_exc
        finally:
            if just_locked:
                self._bus._lock.release()
    
    # Micropython standard operations
    
    def readfrom(self, nbytes, stop=True):
        return self._run(self._bus.readfrom, nbytes, stop)
    
    def readfrom_into(self, buf, stop=True, *, start=0, end=None):
        self._run(self._bus.readfrom_into, buf, stop, start=start, end=end)
    
    def writeto(self, buf, stop=True, *, start=0, end=None):
        return self._run(self._bus.writeto, buf, stop, start=start, end=end)
    
    def writevto(self, vector, stop=True):
        return self._run(self._bus.writevto, vector, stop)
    
    def readfrom_mem(self, memaddr, nbytes, *, addrsize=None):
        if addrsize is None:
            addrsize = self._addrsize
        return self._run(self._bus.readfrom_mem, memaddr, nbytes, addrsize=addrsize)
    
    def readfrom_mem_into(self, memaddr, buf, *, start=0, end=None, addrsize=None):
        if addrsize is None:
            addrsize = self._addrsize
        return self._run(self._bus.readfrom_mem_into, memaddr, buf, start=start, end=end, addrsize=addrsize)
    
    def writeto_mem(self, memaddr, buf, *, start=0, end=None, addrsize=None):
        if addrsize is None:
            addrsize = self._addrsize
        return self._run(self._bus.writeto_mem, memaddr, buf, start=start, end=end, addrsize=addrsize)
    
    # Extension
    def modify_mem(self, memaddr, mode, setbits, clrbits=None, *, addrsize=None):
        if addrsize is None:
            addrsize = self._addrsize
        return self._run(self._bus.modify_mem, memaddr, mode, setbits, clrbits, addrsize=addrsize)
    
    # CircuitPython-specific operations
    
    def writeto_then_readfrom(self, out_buffer, in_buffer, *, out_start=0, out_end=None, in_start=0, in_end=None):
        return self._run(self._bus.writeto_then_readfrom, out_buffer, in_buffer, out_start=out_start, out_end=out_end, in_start=in_start, in_end=in_end)
    
    # adafruit_bus_device.i2c_device.I2CDevice aliases
    
    readinto = readfrom_into
    write = writeto
    write_then_readinto = writeto_then_readfrom


class I2CDeviceMixInStructs:
    
    SCRATCH_SIZE = const(32)
    
    def _readstructfrom_mem_with(self, memaddr, buf, fmt):
        if memaddr is None:
            self.readfrom_into(buf)
        else:
            self.readfrom_mem_into(memaddr, buf)
        return struct.unpack(fmt, buf)
    
    def readstructfrom_mem_with(self, memaddr, buf, fmt):
        size = struct.calcsize(fmt)
        if len(buf) != size:
            raise ValueError("Buffer size must match format size")
        return self._readstructfrom_mem_with(memaddr, buf, fmt)
    
    def readstructfrom_with(self, buf, fmt):
        return self.readstructfrom_mem_with(None, buf, fmt)
    
    def readstructfrom_mem(self, memaddr, fmt):
        size = struct.calcsize(fmt)
        if self.SCRATCH_SIZE > size:
            buf = self._scratch_mv[:size]
        elif self.SCRATCH_SIZE == size > 0:
            buf = self._scratch_mv 
        else:
            if self.SCRATCH_SIZE > 0:
                print("Warning: readstructfrom created new bytearray() size", size, "bytes")
            buf = bytearray(size)
        return self._readstructfrom_mem_with(memaddr, buf, fmt)
    
    def readstructfrom(self, fmt):
        return self.readstructfrom_mem(None, fmt)
    
    def _writestructto_mem_with(self, memaddr, buf, fmt, *values):
        struct.pack_into(fmt, buf, 0, *values)
        if memaddr is None:
            return self.writeto(buf)
        else:
            return self.writeto_mem(memaddr, buf)
    
    def writestructto_mem_with(self, memaddr, buf, fmt, *values):
        size = struct.calcsize(fmt)
        if len(buf) != size:
            raise ValueError("Buffer size must match format size")
        return self._writestructto_mem_with(memaddr, buf, fmt, *values)
    
    def writestructto_with(self, buf, fmt, *values):
        return self.writestructto_mem_with(None, buf, fmt, *values)
    
    def writestructto_mem(self, memaddr, fmt, *values):
        size = struct.calcsize(fmt)
        if self.SCRATCH_SIZE > size:
            buf = self._scratch_mv[:size]
        elif self.SCRATCH_SIZE == size > 0:
            buf = self._scratch_mv 
        else:
            if self.SCRATCH_SIZE > 0:
                print("Warning: writestructto created new bytearray() size", size, "bytes")
            buf = bytearray(size)
        return self._writestructto_mem_with(memaddr, buf, fmt, *values)
    
    def writestructto(self, fmt, *values):
        return self.writestructto_mem(None, fmt, *values)


class I2CDeviceMixInRegisters:
    
    DEFAULT_LSB_FIRST = True
    
    def read_register(self, address, width=1, lsb_first=None, num_bits=None, lowest_bit=0, *, signed=False):
        """Reads an 8- or 16-bit value from a register."""
        
        if lsb_first is None:
            lsb_first = self.DEFAULT_LSB_FIRST
        
        if width == 1:
            buf = self._byte
        elif width == 2:
            buf = self._word
        else:
            raise ValueError("width must be 1 or 2")
        
        if num_bits is None:
            num_bits = width * 8
        
        if not (0 <= num_bits + lowest_bit <= width * 8):
            raise ValueError("bitfield invalid")
        
        self.readfrom_mem_into(address, buf)
        if width == 1:
            val = buf[0]
        elif width == 2:
            if lsb_first:
                val = (buf[1] << 8) | buf[0]
            else:
                val = (buf[0] << 8) | buf[1]
        
        if lowest_bit:
            val >>= lowest_bit
        
        val &= ((1 << num_bits) - 1)
        
        if signed and (val & (1 << (num_bits - 1))):
            val -= (1 << num_bits)
        
        return val
    
    def write_register(self, value, address, width=1, lsb_first=None, num_bits=None, lowest_bit=0, *, signed=None):
        """Writes an 8- or 16-bit value to a register."""
        
        if lsb_first is None:
            lsb_first = self.DEFAULT_LSB_FIRST
        
        if width == 1:
            maxval = 256
            mode = MODE_8
        elif width == 2:
            maxval = 65536
            if lsb_first:
                mode = MODE_16LE
            else:
                mode = MODE_16BE
        else:
            raise ValueError("width must be 1 or 2")
        
        if signed is None:
            signed = bool(value < 0)
        if signed and value < 0:
            value += maxval
        if not (0 <= value < maxval):
            raise ValueError("value out of range")
        
        if num_bits is None:
            self.modify_mem(address, mode, value)
            return
        
        if not (0 <= num_bits + lowest_bit <= width * 8):
            raise ValueError("bitfield invalid")
        
        mask = (1 << num_bits) - 1
        clrbits = mask << lowest_bit
        setbits = (value & mask) << lowest_bit
        
        self.modify_mem(address, mode, setbits, clrbits)


class I2CRegister:
    
    def __init__(self, address, width=1, lsb_first=None, num_bits=None, lowest_bit=0, *, signed=None):
        self.address = address
        self.width = width
        self.lsb_first = lsb_first
        self.num_bits = num_bits
        self.lowest_bit = lowest_bit
        self.signed = signed
    
    def __get__(self, instance, cls=None):
        if instance is None:
            return self
        return instance.read_register(self.address, self.width, self.lsb_first, self.num_bits, self.lowest_bit, signed=self.signed)
    
    def __set__(self, instance, value):
        instance.write_register(value, self.address, self.width, self.lsb_first, self.num_bits, self.lowest_bit, signed=self.signed)


# Based on adafruit_register.i2c_bit

class I2CROBit:
    
    def __init__(self, register_address: int, bit: int, register_width: int = 1, lsb_first: bool = True):
        self.register = I2CRegister(register_address, register_width, lsb_first, 1, bit, signed=False)
    
    def __get__(self, instance, cls=None):
        if instance is None:
            return self
        return self.register.__get__(instance)

class I2CRWBit(I2CROBit):
    
    def __set__(self, instance, value):
        self.register.__set__(instance, value)

class I2CROBits:
    
    def __init__(self, num_bits: int, register_address: int, lowest_bit: int, register_width: int = 1, lsb_first: bool = True, signed: bool = False):
        self.register = I2CRegister(register_address, register_width, lsb_first, num_bits, lowest_bit, signed=signed)
    
    def __get__(self, instance, cls=None):
        if instance is None:
            return self
        return self.register.__get__(instance)

class I2CRWBits(I2CROBits):
    
    def __set__(self, instance, value):
        self.register.__set__(instance, value)

class I2CROUnaryStruct:
    def __init__(self, register_address: int, struct_format: str):
        self.register_address = register_address
        self.struct_format = struct_format
    
    def __get__(self, instance, cls=None):
        if instance is None:
            return self
        return instance.readstructfrom_mem(self.register_address, self.struct_format)[0]

class I2CUnaryStruct(I2CROUnaryStruct):
    def __set__(self, instance, value):
        instance.writestructto_mem(self.register_address, self.struct_format, value)

# extension
class I2CROStruct:
    def __init__(self, register_address: int, struct_format: str):
        self.register_address = register_address
        self.struct_format = struct_format
    
    def __get__(self, instance, cls=None):
        if instance is None:
            return self
        return instance.readstructfrom_mem(self.register_address, self.struct_format)

class I2CStruct(I2CROStruct):
    def __set__(self, instance, value):
        instance.writestructto_mem(self.register_address, self.struct_format, *value)
