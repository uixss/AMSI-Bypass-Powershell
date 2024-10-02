# AMSI-Patch-Powershell

- Process Scanning: Continuously monitors running PowerShell processes.
- AMSI Detection: Detects if amsi.dll is loaded in a process.
- Patch Application: Automatically patches the AMSI interface to bypass antivirus checks.
- Cross-Process Memory Manipulation: Reads and writes memory to patch the AMSI functionality in the target process.

# Usage

Run the script with administrator privileges for it to function correctly. It continuously monitors PowerShell processes and applies the patch if necessary.


- Process Enumeration: Uses CreateToolhelp32Snapshot to take a snapshot of all running processes and checks if they are powershell.exe.
- Memory Patching: Reads process memory and searches for the AMSI-related byte pattern to apply the patch.
- AMSI DLL Check: Uses psutil to determine if amsi.dll is loaded into a specific process's memory.


# Credits

https://github.com/bytepulze/amsi-bypass

- for example :

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
