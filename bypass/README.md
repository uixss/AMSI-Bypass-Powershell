
### Version 1

- **Basic AMSI patching**: This version scans the process memory for specific patterns and applies a patch to disable AMSI in the target `powershell.exe` process.
- **Module scanning**: Uses Windows API functions to scan for loaded modules in a process, specifically looking for `amsi.dll`.
- **Pattern matching**: Once the AMSI module is identified, the script searches for a predefined byte pattern and applies a patch if found.
- **Limitations**: Lacks user privilege verification and additional hardening techniques, making it vulnerable to detection or failure if not executed with elevated privileges.

### Version 2

- **Improved privilege management**: The script checks if it's running with administrative privileges using `IsUserAnAdmin()` and prompts for elevation if needed.
- **UAC Bypass**: Attempts to bypass User Account Control (UAC) by invoking `fodhelper.exe` to elevate privileges.
- **Disables PowerShell logging**: Adds functionality to disable `ScriptBlockLogging` in Windows Registry, which improves stealth.
- **Modular and extended error handling**: Better organized with additional error handling mechanisms. It ensures smoother operation, especially in scenarios where reading and writing to process memory might fail.

## Feature Comparison

| **Feature**                            | **Version 1**                                                | **Version 2**                                                |
|----------------------------------------|--------------------------------------------------------------|--------------------------------------------------------------|
| **Patch AMSI in PowerShell**           | Yes                                                          | Yes                                                          |
| **Admin Privilege Check**              | No                                                           | Yes, checks admin privileges using `IsUserAnAdmin()`          |
| **UAC Bypass**                         | No                                                           | Yes, attempts UAC bypass with `fodhelper.exe`                 |
| **Disable PowerShell Logging**         | No                                                           | Yes, disables `ScriptBlockLogging` in Windows registry using PowerShell commands |
| **Process Iteration**                  | Iterates over processes to find PowerShell instances and applies AMSI patch | Same as V1                                                    |
| **Memory Patching**                    | Patches memory by searching for specific byte patterns        | Same as V1                                                    |

## How to Use

### Version 1
1. Run the script in an environment where you need to disable AMSI.
2. The script will scan for `powershell.exe` processes and attempt to patch the AMSI module in memory.
3. No administrative privilege checks are included, so ensure you have sufficient permissions.

### Version 2
1. Run the script. If the script is not running with elevated privileges, it will prompt for admin rights using UAC.
2. The script will attempt to disable PowerShell logging for increased stealth.
3. If successful, it will patch the AMSI module similarly to Version 1 but with improved handling and privilege elevation.
