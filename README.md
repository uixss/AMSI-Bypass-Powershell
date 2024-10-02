# AMSI Bypass

This project contains two Python scripts designed to detect and patch the PowerShell process that has the library loaded amsi.dll. The first script is responsible for monitoring the processes in execution, and the second applies the patch to amsi.dllwhen she's spotted.

Monitor processes in the system and check if amsi.dllis loaded in the process powershell.exe. If it is detected that amsi.dllIt's loaded, call the second script (patcher.py) to apply the patch.
Main functions:

    is'amsi.loaded(proc): Check if amsi.dllHe's loaded into the given process.
    main(): Continuously monitor processes and apply the patch when needed.
    get.module-base-address(pid, module-name): You get the module base address specified in the given process.
    SPatt(startaddr, pattern): Look for a specific pattern in process memory.
    PatchProcess(pid): Applies the patch to the corresponding memory address.


---

# BYPASS-FOLDER

---


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

### Note:
The use of these scripts is intended for educational purposes and security research. Misuse in environments without proper authorization may violate laws or regulations.


# Credits

https://github.com/ZeroMemoryEx

https://github.com/S1lkys/SharpKiller

 | 48:85D2 | test rdx, rdx |

 | 74 3F | je amsi.7FFAE957C694 |

 | 48 : 85C9 | test rcx, rcx |

 | 74 3A | je amsi.7FFAE957C694 |

 | 48 : 8379 08 00 | cmp qword ptr ds : [rcx + 8] , 0 |

 | 74 33 | je amsi.7FFAE957C694 |

- the search pattern will be like this :
{ 0x48,'?','?', 0x74,'?',0x48,'?' ,'?' ,0x74,'?' ,0x48,'?' ,'?' ,'?' ,'?',0x74,0x33}

![image](https://github.com/ltcflip/amsi-bypass/assets/153377701/3a57f643-2896-49b1-b96f-80e1e7f56852)

# Patch

![image](https://github.com/ltcflip/amsi-bypass/assets/153377701/339ad662-591e-48cd-bab0-adf475d4d1dc)



## Contributing
Feel free to submit issues or pull requests to improve the functionality and error handling in these scripts.

