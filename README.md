# AMSI-Patch-Script

- Process Scanning: Continuously monitors running PowerShell processes.
- AMSI Detection: Detects if amsi.dll is loaded in a process.
- Patch Application: Automatically patches the AMSI interface to bypass antivirus checks.
- Cross-Process Memory Manipulation: Reads and writes memory to patch the AMSI functionality in the target process.

Requirements

    Python 3.6+
    ctypes for interacting with the Windows API
    psutil for process management

# Usage

Run the script with administrator privileges for it to function correctly. It continuously monitors PowerShell processes and applies the patch if necessary.


- Process Enumeration: Uses CreateToolhelp32Snapshot to take a snapshot of all running processes and checks if they are powershell.exe.
- Memory Patching: Reads process memory and searches for the AMSI-related byte pattern to apply the patch.
- AMSI DLL Check: Uses psutil to determine if amsi.dll is loaded into a specific process's memory.
