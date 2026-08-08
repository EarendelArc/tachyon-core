[CmdletBinding()]
param(
    [string]$BinaryPath = "",
    [string]$EvidenceDirectory = "",
    [string]$CommitSHA = "",
    [string]$RunID = "",
    [string]$RunAttempt = "",
    [switch]$RunServiceSIDHarness,
    [switch]$RunGoHarness,
    [switch]$RunPathSecurityTests,
    [switch]$RunProvisioningSecurityTests,
    [switch]$RunEvidenceFailureTests
)

$ErrorActionPreference = "Stop"
$scriptRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($scriptRoot)) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
if ([string]::IsNullOrWhiteSpace($BinaryPath)) {
    $BinaryPath = Join-Path $scriptRoot "..\tachyon-core.exe"
}

if ($null -eq ('TachyonHarness.KillOnCloseJob' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace TachyonHarness {
    public sealed class JobFaultPlan {
        private readonly object sync = new object();
        private int assignFailures;
        private int terminateFailures;
        private int closeFailures;
        private int resumeFailures;

        public JobFaultPlan(int assignFailures, int terminateFailures, int closeFailures, int resumeFailures) {
            this.assignFailures = assignFailures;
            this.terminateFailures = terminateFailures;
            this.closeFailures = closeFailures;
            this.resumeFailures = resumeFailures;
        }

        internal bool ConsumeAssignFailure() { lock (sync) { return Consume(ref assignFailures); } }
        internal bool ConsumeTerminateFailure() { lock (sync) { return Consume(ref terminateFailures); } }
        internal bool ConsumeCloseFailure() { lock (sync) { return Consume(ref closeFailures); } }
        internal bool ConsumeResumeFailure() { lock (sync) { return Consume(ref resumeFailures); } }

        private static bool Consume(ref int remaining) {
            if (remaining <= 0) return false;
            remaining--;
            return true;
        }
    }

    public sealed class AssignedProcessStartResult {
        private readonly List<string> errors = new List<string>();
        internal IntPtr ProcessHandle { get; set; }
        internal IntPtr ThreadHandle { get; set; }
        public KillOnCloseJob Job { get; internal set; }
        public Process Process { get; internal set; }
        public int ProcessId { get; internal set; }
        public long StartTicksUtc { get; internal set; }
        public bool Created { get; internal set; }
        public bool Assigned { get; internal set; }
        public bool Resumed { get; internal set; }
        public bool ExitConfirmed { get; internal set; }
        public bool HandoffCompleted { get; internal set; }
        public bool NativeHandlesClosed { get { return ProcessHandle == IntPtr.Zero && ThreadHandle == IntPtr.Zero; } }
        public bool HasNativeProcessHandle { get { return ProcessHandle != IntPtr.Zero; } }
        public bool HasNativeThreadHandle { get { return ThreadHandle != IntPtr.Zero; } }
        public bool Success { get; internal set; }
        public string[] Errors { get { return errors.ToArray(); } }
        internal void AddError(string value) { errors.Add(value); }
    }

    public sealed class OwnedProcessActionResult {
        private readonly List<string> errors = new List<string>();
        public bool IdentityConfirmed { get; internal set; }
        public bool TerminationAttempted { get; internal set; }
        public bool TerminationSucceeded { get; internal set; }
        public bool WaitCompleted { get; internal set; }
        public bool ExitConfirmed { get; internal set; }
        public bool HandlesClosed { get; internal set; }
        public bool Success { get; internal set; }
        public string[] Errors { get { return errors.ToArray(); } }
        internal void AddError(string value) { errors.Add(value); }
    }

    public sealed class JobCloseResult {
        public bool Success { get; internal set; }
        public bool AlreadyClosed { get; internal set; }
        public bool HandleRetained { get; internal set; }
        public int Attempt { get; internal set; }
        public int ErrorCode { get; internal set; }
        public string Error { get; internal set; }
    }

    public sealed class KillOnCloseJob : IDisposable {
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectBasicProcessIdList = 3;
        private const int JobObjectExtendedLimitInformation = 9;
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint START_FAILURE_EXIT_CODE = 0x0000e101;
        private readonly object sync = new object();
        private readonly JobFaultPlan faults;
        private IntPtr handle;
        private bool closed;
        private int closeAttempts;

        private KillOnCloseJob(IntPtr handle, JobFaultPlan faults) { this.handle = handle; this.faults = faults; }

        public bool IsClosed { get { lock (sync) { return closed; } } }
        public uint LimitFlags {
            get {
                IntPtr job = RequireHandle();
                int size = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try {
                    uint returned;
                    if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size, out returned)) {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryInformationJobObject limits failed");
                    }
                    return Marshal.PtrToStructure<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(buffer).BasicLimitInformation.LimitFlags;
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
        }

        public static KillOnCloseJob Create() {
            IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
            if (job == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObjectW failed");
            try {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                int size = Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>();
                IntPtr buffer = Marshal.AllocHGlobal(size);
                try {
                    Marshal.StructureToPtr(limits, buffer, false);
                    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, buffer, (uint)size)) {
                        throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject failed");
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
                return new KillOnCloseJob(job, new JobFaultPlan(0, 0, 0, 0));
            }
            catch {
                CloseHandle(job);
                throw;
            }
        }

        public static KillOnCloseJob CreateWithFaults(int assignFailures, int terminateFailures, int closeFailures, int resumeFailures) {
            if (assignFailures < 0 || terminateFailures < 0 || closeFailures < 0 || resumeFailures < 0) {
                throw new ArgumentOutOfRangeException("failure counts must be non-negative");
            }
            KillOnCloseJob job = Create();
            return new KillOnCloseJob(job.DetachHandle(), new JobFaultPlan(assignFailures, terminateFailures, closeFailures, resumeFailures));
        }

        public AssignedProcessStartResult StartAssignedProcess(string applicationPath, string[] arguments) {
            AssignedProcessStartResult result = new AssignedProcessStartResult();
            result.Job = this;
            IntPtr job = RequireHandle();
            string commandLine = QuoteArgument(applicationPath);
            if (arguments != null) {
                foreach (string argument in arguments) commandLine += " " + QuoteArgument(argument ?? String.Empty);
            }
            STARTUPINFO startup = new STARTUPINFO();
            startup.cb = (uint)Marshal.SizeOf<STARTUPINFO>();
            PROCESS_INFORMATION information = new PROCESS_INFORMATION();
            StringBuilder mutableCommandLine = new StringBuilder(commandLine);
            if (!CreateProcessW(applicationPath, mutableCommandLine, IntPtr.Zero, IntPtr.Zero, false,
                CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, Environment.CurrentDirectory, ref startup, out information)) {
                result.AddError("create_process_failed win32=" + Marshal.GetLastWin32Error());
                return result;
            }
            result.Created = true;
            result.ProcessId = unchecked((int)information.dwProcessId);
            result.ProcessHandle = information.hProcess;
            result.ThreadHandle = information.hThread;
            try {
                long startTicks;
                if (!TryGetStartTicks(information.hProcess, out startTicks)) {
                    result.AddError("get_process_times_failed win32=" + Marshal.GetLastWin32Error());
                }
                else { result.StartTicksUtc = startTicks; }
                result.Process = Process.GetProcessById(result.ProcessId);

                int operationError;
                if (!TryAssign(job, information.hProcess, out operationError)) {
                    result.AddError("assign_process_to_job_failed win32=" + operationError);
                }
                else {
                    result.Assigned = true;
                    bool assigned;
                    if (!IsProcessInJob(information.hProcess, job, out assigned) || !assigned) {
                        result.AddError("is_process_in_job_failed win32=" + Marshal.GetLastWin32Error());
                    }
                    else if (!TryResume(information.hThread, out operationError)) {
                        result.AddError("resume_thread_failed win32=" + operationError);
                    }
                    else {
                        result.Resumed = true;
                        if (result.StartTicksUtc != 0 && result.Process != null) result.Success = true;
                        else result.AddError("launch identity was incomplete after resume");
                    }
                }
            }
            catch (Exception error) {
                result.AddError("start_exception type=" + error.GetType().Name + " message=" + error.Message);
            }
            return result;
        }

        public OwnedProcessActionResult AcceptSuccessfulLaunch(AssignedProcessStartResult owned) {
            OwnedProcessActionResult result = new OwnedProcessActionResult();
            if (!ValidateOwnership(owned, result)) return result;
            if (!owned.Success || !owned.Assigned || !owned.Resumed || owned.Process == null) {
                result.AddError("launch is not eligible for successful handoff");
                return result;
            }
            try {
                if (owned.Process.Id != owned.ProcessId || owned.Process.StartTime.ToUniversalTime().Ticks != owned.StartTicksUtc) {
                    result.AddError("managed process identity did not match launch ownership");
                    return result;
                }
                result.IdentityConfirmed = true;
            }
            catch (Exception error) {
                result.AddError("managed process identity check failed type=" + error.GetType().Name + " message=" + error.Message);
                return result;
            }
            if (!CloseOwnedHandles(owned, result)) return result;
            owned.HandoffCompleted = true;
            result.Success = true;
            return result;
        }

        public OwnedProcessActionResult TryTerminateAndWait(AssignedProcessStartResult owned, int waitMilliseconds) {
            OwnedProcessActionResult result = new OwnedProcessActionResult();
            if (!ValidateOwnership(owned, result)) return result;
            if (waitMilliseconds < 0) {
                result.AddError("wait timeout must be non-negative");
                return result;
            }
            if (owned.ExitConfirmed) {
                result.IdentityConfirmed = true;
                result.WaitCompleted = true;
                result.ExitConfirmed = true;
                result.Success = CloseOwnedHandles(owned, result);
                return result;
            }
            if (!ConfirmNativeProcessIdentity(owned, result)) return result;
            result.TerminationAttempted = true;
            int terminateError;
            result.TerminationSucceeded = TryTerminate(owned.ProcessHandle, out terminateError);
            if (!result.TerminationSucceeded) result.AddError("terminate_process_failed win32=" + terminateError);
            uint wait = WaitForSingleObject(owned.ProcessHandle, result.TerminationSucceeded ? (uint)waitMilliseconds : Math.Min((uint)waitMilliseconds, 100u));
            if (wait == WAIT_OBJECT_0) {
                owned.ExitConfirmed = true;
                result.WaitCompleted = true;
                result.ExitConfirmed = true;
                result.Success = CloseOwnedHandles(owned, result);
                return result;
            }
            if (wait != WAIT_TIMEOUT) result.AddError("process_wait_failed win32=" + Marshal.GetLastWin32Error());
            else result.AddError("process_wait_timed_out");
            return result;
        }

        public OwnedProcessActionResult TryWaitForExitAndRelease(AssignedProcessStartResult owned, int waitMilliseconds) {
            OwnedProcessActionResult result = new OwnedProcessActionResult();
            if (!ValidateOwnership(owned, result)) return result;
            if (waitMilliseconds < 0) {
                result.AddError("wait timeout must be non-negative");
                return result;
            }
            if (owned.ExitConfirmed) {
                result.IdentityConfirmed = true;
                result.WaitCompleted = true;
                result.ExitConfirmed = true;
                result.Success = CloseOwnedHandles(owned, result);
                return result;
            }
            if (!ConfirmNativeProcessIdentity(owned, result)) return result;
            uint wait = WaitForSingleObject(owned.ProcessHandle, (uint)waitMilliseconds);
            if (wait != WAIT_OBJECT_0) {
                if (wait == WAIT_TIMEOUT) result.AddError("process_wait_timed_out");
                else result.AddError("process_wait_failed win32=" + Marshal.GetLastWin32Error());
                return result;
            }
            owned.ExitConfirmed = true;
            result.WaitCompleted = true;
            result.ExitConfirmed = true;
            result.Success = CloseOwnedHandles(owned, result);
            return result;
        }

        public JobCloseResult TryClose() {
            lock (sync) {
                JobCloseResult result = new JobCloseResult();
                result.Attempt = ++closeAttempts;
                if (closed) {
                    result.Success = true;
                    result.AlreadyClosed = true;
                    return result;
                }
                if (handle == IntPtr.Zero) {
                    result.Error = "Job handle is unexpectedly empty before close.";
                    result.HandleRetained = false;
                    return result;
                }
                if (faults.ConsumeCloseFailure()) {
                    result.ErrorCode = 5;
                    result.Error = "injected CloseHandle(job) failure";
                    result.HandleRetained = true;
                    return result;
                }
                if (!CloseHandle(handle)) {
                    result.ErrorCode = Marshal.GetLastWin32Error();
                    result.Error = "CloseHandle(job) failed";
                    result.HandleRetained = true;
                    return result;
                }
                handle = IntPtr.Zero;
                closed = true;
                result.Success = true;
                return result;
            }
        }

        public ulong[] ActiveProcessIds() {
            IntPtr job = RequireHandle();
            const int capacity = 1024;
            int size = 8 + (capacity * IntPtr.Size);
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try {
                for (int index = 0; index < size; index++) Marshal.WriteByte(buffer, index, 0);
                uint returned;
                if (!QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, (uint)size, out returned)) {
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "QueryInformationJobObject failed");
                }
                uint count = unchecked((uint)Marshal.ReadInt32(buffer, 4));
                if (count > capacity) throw new InvalidOperationException("Job process list exceeds harness hard limit");
                List<ulong> processIds = new List<ulong>((int)count);
                for (int index = 0; index < count; index++) {
                    long value = IntPtr.Size == 8 ? Marshal.ReadInt64(buffer, 8 + (index * IntPtr.Size)) : Marshal.ReadInt32(buffer, 8 + (index * IntPtr.Size));
                    processIds.Add(unchecked((ulong)value));
                }
                return processIds.ToArray();
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        public void Dispose() {
            JobCloseResult result = TryClose();
            if (!result.Success) throw new Win32Exception(result.ErrorCode, result.Error);
        }

        private IntPtr RequireHandle() {
            lock (sync) {
                if (closed || handle == IntPtr.Zero) throw new ObjectDisposedException("KillOnCloseJob");
                return handle;
            }
        }

        private IntPtr DetachHandle() {
            lock (sync) {
                IntPtr detached = handle;
                handle = IntPtr.Zero;
                closed = true;
                return detached;
            }
        }

        private bool TryAssign(IntPtr job, IntPtr process, out int error) {
            if (faults.ConsumeAssignFailure()) { error = 5; return false; }
            if (AssignProcessToJobObject(job, process)) { error = 0; return true; }
            error = Marshal.GetLastWin32Error();
            return false;
        }

        private bool TryTerminate(IntPtr process, out int error) {
            if (faults.ConsumeTerminateFailure()) { error = 5; return false; }
            if (TerminateProcess(process, START_FAILURE_EXIT_CODE)) { error = 0; return true; }
            error = Marshal.GetLastWin32Error();
            return false;
        }

        private bool TryResume(IntPtr thread, out int error) {
            if (faults.ConsumeResumeFailure()) { error = 5; return false; }
            if (ResumeThread(thread) != UInt32.MaxValue) { error = 0; return true; }
            error = Marshal.GetLastWin32Error();
            return false;
        }

        private static bool TryGetStartTicks(IntPtr process, out long ticks) {
            FILETIME creation;
            FILETIME exit;
            FILETIME kernel;
            FILETIME user;
            if (!GetProcessTimes(process, out creation, out exit, out kernel, out user)) { ticks = 0; return false; }
            long fileTime = ((long)creation.HighDateTime << 32) | creation.LowDateTime;
            ticks = DateTime.FromFileTimeUtc(fileTime).Ticks;
            return true;
        }

        private bool ValidateOwnership(AssignedProcessStartResult owned, OwnedProcessActionResult result) {
            if (owned == null) { result.AddError("launch ownership is null"); return false; }
            if (!Object.ReferenceEquals(owned.Job, this)) { result.AddError("launch ownership belongs to a different Job"); return false; }
            if (!owned.Created) { result.AddError("launch did not create a process"); return false; }
            return true;
        }

        private bool ConfirmNativeProcessIdentity(AssignedProcessStartResult owned, OwnedProcessActionResult result) {
            if (owned.ProcessHandle == IntPtr.Zero) {
                result.AddError("owned native process handle is unavailable");
                return false;
            }
            uint nativeProcessId = GetProcessId(owned.ProcessHandle);
            if (nativeProcessId == 0) {
                result.AddError("GetProcessId failed win32=" + Marshal.GetLastWin32Error());
                return false;
            }
            if (nativeProcessId != unchecked((uint)owned.ProcessId)) {
                result.AddError("native process handle PID did not match launch ownership");
                return false;
            }
            long nativeStartTicks;
            if (owned.StartTicksUtc == 0 || !TryGetStartTicks(owned.ProcessHandle, out nativeStartTicks)) {
                result.AddError("native process handle start time could not be verified win32=" + Marshal.GetLastWin32Error());
                return false;
            }
            if (nativeStartTicks != owned.StartTicksUtc) {
                result.AddError("native process handle start time did not match launch ownership");
                return false;
            }
            result.IdentityConfirmed = true;
            return true;
        }

        private static bool CloseOwnedHandles(AssignedProcessStartResult owned, OwnedProcessActionResult result) {
            if (owned.ThreadHandle != IntPtr.Zero) {
                if (!CloseHandle(owned.ThreadHandle)) {
                    result.AddError("CloseHandle(thread) failed win32=" + Marshal.GetLastWin32Error());
                    return false;
                }
                owned.ThreadHandle = IntPtr.Zero;
            }
            if (owned.ProcessHandle != IntPtr.Zero) {
                if (!CloseHandle(owned.ProcessHandle)) {
                    result.AddError("CloseHandle(process) failed win32=" + Marshal.GetLastWin32Error());
                    return false;
                }
                owned.ProcessHandle = IntPtr.Zero;
            }
            result.HandlesClosed = owned.NativeHandlesClosed;
            return result.HandlesClosed;
        }

        private static string QuoteArgument(string value) {
            StringBuilder quoted = new StringBuilder();
            quoted.Append('"');
            int backslashes = 0;
            foreach (char character in value) {
                if (character == '\\') { backslashes++; continue; }
                if (character == '"') {
                    quoted.Append('\\', (backslashes * 2) + 1);
                    quoted.Append('"');
                    backslashes = 0;
                    continue;
                }
                quoted.Append('\\', backslashes);
                backslashes = 0;
                quoted.Append(character);
            }
            quoted.Append('\\', backslashes * 2);
            quoted.Append('"');
            return quoted.ToString();
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO {
            public uint cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME {
            public uint LowDateTime;
            public uint HighDateTime;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObjectW(IntPtr securityAttributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int informationClass, IntPtr information, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int informationClass, IntPtr information, uint length, out uint returnedLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine, IntPtr processAttributes,
            IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory,
            ref STARTUPINFO startupInfo, out PROCESS_INFORMATION processInformation);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(IntPtr process, out FILETIME creation, out FILETIME exit, out FILETIME kernel, out FILETIME user);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetProcessId(IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
    }
}
'@
}

function Get-HarnessRoot {
    param([string]$ProgramDataPath = $env:ProgramData)
    if ([string]::IsNullOrWhiteSpace($ProgramDataPath)) { throw "ProgramData is required for the Service SID harness." }
    return Join-Path $ProgramDataPath "Tachyon\Harness"
}

function Assert-NoReparsePointPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($full)
    $relative = $full.Substring($root.Length).TrimStart('\', '/')
    $current = $root
    foreach ($part in ($relative -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $current = Join-Path $current $part
        if (-not (Test-Path -LiteralPath $current)) { continue }
        if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Harness path contains a reparse point: $current"
        }
    }
}

function Assert-HarnessDiagnosticPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ProgramDataPath = $env:ProgramData
    )
    $root = [IO.Path]::GetFullPath((Get-HarnessRoot $ProgramDataPath)).TrimEnd([char]'\', [char]'/')
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Diagnostic path escapes the protected harness root."
    }
    $relative = $full.Substring($prefix.Length)
    $parts = $relative -split '[\\/]'
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[0-9a-fA-F]{32}$' -or -not [string]::Equals($parts[1], 'helper-health.json', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Diagnostic path must be Harness\\<GUID>\\helper-health.json."
    }
    return $full
}

function Assert-HarnessReadyPath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [string]$ProgramDataPath = $env:ProgramData
    )
    $root = [IO.Path]::GetFullPath((Get-HarnessRoot $ProgramDataPath)).TrimEnd([char]'\', [char]'/')
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = $root + [IO.Path]::DirectorySeparatorChar
    if (-not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Ready path escapes the protected harness root."
    }
    $parts = $full.Substring($prefix.Length) -split '[\\/]'
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[0-9a-fA-F]{32}$' -or -not [string]::Equals($parts[1], 'core-ready.json', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Ready path must be Harness\\<GUID>\\core-ready.json."
    }
    return $full
}

function Resolve-ServiceSID {
    param(
        [Parameter(Mandatory = $true)][string]$ScPath,
        [Parameter(Mandatory = $true)][string]$ServiceName
    )
    $showSID = (& $ScPath showsid $ServiceName | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "sc.exe showsid failed with exit code $LASTEXITCODE" }
    if ($showSID -notmatch 'S-1-5-80-[0-9-]+') { throw "SCM did not expose a restricted Service SID" }
    return $Matches[0]
}

function Resolve-VerifiedHarnessPath {
    param(
        [Parameter(Mandatory = $true)][string]$HarnessID,
        [string]$ProgramDataPath = $env:ProgramData
    )
    if ($HarnessID -notmatch '^[0-9a-f]{32}$') { throw "Harness GUID validation failed." }
    $programDataFull = [IO.Path]::GetFullPath($ProgramDataPath)
    $root = [IO.Path]::GetFullPath((Get-HarnessRoot $programDataFull))
    $directory = [IO.Path]::GetFullPath((Join-Path $root $HarnessID))
    $diagnostic = Assert-HarnessDiagnosticPath (Join-Path $directory 'helper-health.json') $programDataFull
    $ready = Assert-HarnessReadyPath (Join-Path $directory 'core-ready.json') $programDataFull
    return [PSCustomObject]@{ Directory = $directory; Diagnostic = $diagnostic; Ready = $ready; ProgramData = $programDataFull }
}

function New-VerifiedHarnessPath {
    param(
        [Parameter(Mandatory = $true)][string]$HarnessID,
        [string]$ProgramDataPath = $env:ProgramData
    )
    $harness = Resolve-VerifiedHarnessPath $HarnessID $ProgramDataPath
    $root = Split-Path -Parent $harness.Directory
    $directory = $harness.Directory
    foreach ($path in @((Split-Path -Parent $root), $root, $directory)) {
        # Paths are derived from ProgramData plus a validated GUID. Directory's
        # API has no wildcard expansion and is supported by Windows PowerShell 5.1.
        Assert-NoReparsePointPath $path
        try { [void][IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($path)) }
        catch { throw "Create protected harness directory failed: $($_.Exception.Message)" }
        Assert-NoReparsePointPath $path
    }
    return $harness
}

function New-ProtectedHarnessDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$HarnessID,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID
    )
    $serviceAccountSID = [Security.Principal.NTAccount]::new('NT SERVICE', $ServiceName).Translate([Security.Principal.SecurityIdentifier])
    if ($serviceAccountSID.Value -ne $ServiceSID) { throw "NT SERVICE account SID does not match SCM Service SID." }
    $harness = New-VerifiedHarnessPath $HarnessID
    $directory = $harness.Directory
    Set-PreprovisionedDiagnosticArtifacts $directory $harness.Diagnostic $serviceAccountSID $OwnerSID
    return $harness
}

function Get-DiagnosticLimitedRights {
    param([switch]$File)
    $rights = [Security.AccessControl.FileSystemRights]::ReadPermissions -bor [Security.AccessControl.FileSystemRights]::ReadAttributes
    if ($File) {
        $rights = $rights -bor [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData
    }
    return [Security.AccessControl.FileSystemRights]$rights
}

function Get-DiagnosticExpectedMask {
    param([switch]$File)
    $localService = [Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new($localService, (Get-DiagnosticLimitedRights -File:$File), [Security.AccessControl.AccessControlType]::Allow)
    return [uint32]$rule.FileSystemRights
}

function Get-DiagnosticAccessRules {
    param([Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL)
    # PowerShell 7's Access view can omit SIDs that have no account-name mapping.
    return $ACL.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
}

function Get-DiagnosticSIDAccessSummary {
    param(
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$SID
    )
    $count = 0
    $mask = [uint32]0
    foreach ($accessRule in (Get-DiagnosticAccessRules $ACL)) {
        if ($accessRule.IdentityReference.Value -ne $SID.Value -or $accessRule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
        $count++
        $mask = [uint32]($mask -bor [uint32]$accessRule.FileSystemRights)
    }
    return [PSCustomObject]@{ Count = $count; Mask = $mask }
}

function Get-RawDiagnosticSIDAccessSummary {
    param(
        [Parameter(Mandatory = $true)][string]$SDDL,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$SID
    )
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($SDDL)
    $count = 0
    $mask = [uint32]0
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.CommonAce] -or
            $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
            $ace.SecurityIdentifier.Value -ne $SID.Value) { continue }
        $count++
        $mask = [uint32]($mask -bor [uint32]$ace.AccessMask)
    }
    return [PSCustomObject]@{ Count = $count; Mask = $mask }
}

function New-ExactDiagnosticSecurity {
    param(
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$File
    )
    $security = if ($File) { [Security.AccessControl.FileSecurity]::new() } else { [Security.AccessControl.DirectorySecurity]::new() }
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($OwnerSID)
    $limitedRights = Get-DiagnosticLimitedRights -File:$File
    foreach ($rule in @(
        [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalSystemSid, $null), [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow),
        [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null), [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow),
        [Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new([Security.Principal.WellKnownSidType]::LocalServiceSid, $null), $limitedRights, [Security.AccessControl.AccessControlType]::Allow),
        [Security.AccessControl.FileSystemAccessRule]::new($ServiceSID, $limitedRights, [Security.AccessControl.AccessControlType]::Allow)
    )) {
        $security.SetAccessRule($rule)
    }
    return $security
}

function Assert-ExactDiagnosticSecurityObject {
    param(
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$File,
        [switch]$SkipOwnerVerification
    )
    if ((-not $SkipOwnerVerification -and $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $OwnerSID.Value) -or -not $acl.AreAccessRulesProtected) {
        throw "Diagnostic owner or inheritance policy is not exact."
    }
    if (-not $acl.AreAccessRulesCanonical) { throw "Diagnostic ACL is not canonical." }
    $limitedRights = Get-DiagnosticExpectedMask -File:$File
    $expected = @{}
    $expected['S-1-5-18'] = [uint32]0x1F01FF
    $expected['S-1-5-32-544'] = [uint32]0x1F01FF
    $expected['S-1-5-19'] = $limitedRights
    $expected[$ServiceSID.Value] = $limitedRights
    $actual = @{}
    foreach ($accessRule in (Get-DiagnosticAccessRules $acl)) {
        if ($accessRule.IsInherited -or $accessRule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $accessRule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
            $accessRule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "Diagnostic ACL contains a non-explicit allow ACE."
        }
        $sid = $accessRule.IdentityReference.Value
        if (-not $expected.ContainsKey($sid)) { throw "Diagnostic ACL grants unexpected SID $sid." }
        $rights = [uint32]$accessRule.FileSystemRights
        $expectedRights = [uint32]$expected[$sid]
        if ($rights -eq 0) { throw "Diagnostic ACL contains an empty ACE for SID $sid." }
        if (($rights -bor $expectedRights) -ne $expectedRights) { throw "Diagnostic ACL broadens SID $sid." }
        $currentRights = if ($actual.ContainsKey($sid)) { [uint32]$actual[$sid] } else { [uint32]0 }
        $actual[$sid] = [uint32]($currentRights -bor $rights)
    }
    foreach ($sid in $expected.Keys) {
        if (-not $actual.ContainsKey($sid) -or [uint32]$actual[$sid] -ne [uint32]$expected[$sid]) {
            $actualRights = if ($actual.ContainsKey($sid)) { [uint32]$actual[$sid] } else { [uint32]0 }
            throw "Diagnostic ACL access mismatch for SID $sid; actual=0x$($actualRights.ToString('X')) expected=0x$(([uint32]$expected[$sid]).ToString('X'))."
        }
    }
}

function Assert-ExactDiagnosticSecurity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$File
    )
    $acl = Get-Acl -LiteralPath $Path
    Assert-ExactDiagnosticSecurityObject $acl $ServiceSID $OwnerSID -File:$File
}

function Assert-DiagnosticSecurityRejected {
    param(
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage
    )
    $failure = $null
    try { Assert-ExactDiagnosticSecurityObject $ACL $ServiceSID $OwnerSID -File }
    catch { $failure = $_ }
    if ($null -eq $failure) { throw "Invalid diagnostic ACL was accepted; expected '$ExpectedMessage'." }
    if (-not $failure.Exception.Message.Contains($ExpectedMessage)) {
        throw "Invalid diagnostic ACL failed for the wrong reason: '$($failure.Exception.Message)'; expected '$ExpectedMessage'."
    }
}

function Write-DiagnosticAclObjectDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][System.Security.AccessControl.FileSystemSecurity]$ACL
    )
    try {
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
        Write-Host "$Label ACL owner=$($ACL.GetOwner([Security.Principal.SecurityIdentifier]).Value) protected=$($ACL.AreAccessRulesProtected) canonical=$($ACL.AreAccessRulesCanonical)"
        Write-Host "$Label ACL SDDL=$($ACL.GetSecurityDescriptorSddlForm($sections))"
        foreach ($accessRule in (Get-DiagnosticAccessRules $ACL)) {
            $sid = $accessRule.IdentityReference.Value
            $rights = [uint32]$accessRule.FileSystemRights
            Write-Host "$Label ACE sid=$sid mask=0x$($rights.ToString('X')) type=$($accessRule.AccessControlType) inherited=$($accessRule.IsInherited) inheritance=$($accessRule.InheritanceFlags) propagation=$($accessRule.PropagationFlags)"
        }
    }
    catch { Write-Warning "$Label ACL diagnostics failed: $($_.Exception.Message)" }
}

function Write-DiagnosticAclDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Path
    )
    try {
        if (-not (Test-Path -LiteralPath $Path)) {
            Write-Host "$Label ACL: path does not exist"
            return
        }
        $acl = Get-Acl -LiteralPath $Path
        Write-DiagnosticAclObjectDiagnostics $Label $acl
    }
    catch { Write-Warning "$Label ACL diagnostics failed: $($_.Exception.Message)" }
}

function Set-PrivateHarnessCleanupAccess {
    param([Parameter(Mandatory = $true)][string]$Directory, [Parameter(Mandatory = $true)][string]$Diagnostic)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $directorySecurity = [Security.AccessControl.DirectorySecurity]::new()
    $directorySecurity.SetAccessRuleProtection($true, $false)
    $directorySecurity.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
    [IO.DirectoryInfo]::new($Directory).SetAccessControl($directorySecurity)
    if (Test-Path -LiteralPath $Diagnostic) {
        $fileSecurity = [Security.AccessControl.FileSecurity]::new()
        $fileSecurity.SetAccessRuleProtection($true, $false)
        $fileSecurity.SetAccessRule([Security.AccessControl.FileSystemAccessRule]::new($identity, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow))
        [IO.FileInfo]::new($Diagnostic).SetAccessControl($fileSecurity)
    }
}

function Remove-VerifiedHarnessArtifacts {
    param([Parameter(Mandatory = $true)][PSCustomObject]$Harness)
    $harnessID = Split-Path -Leaf $Harness.Directory
    $verified = Resolve-VerifiedHarnessPath $harnessID $Harness.ProgramData
    if (-not [string]::Equals($verified.Directory, [IO.Path]::GetFullPath($Harness.Directory), [StringComparison]::OrdinalIgnoreCase) -or
        -not [string]::Equals($verified.Diagnostic, [IO.Path]::GetFullPath($Harness.Diagnostic), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Harness cleanup path does not match the verified absolute path."
    }
    if (Test-Path -LiteralPath $verified.Directory) { Assert-NoReparsePointPath $verified.Directory }
    if (Test-Path -LiteralPath $verified.Directory) {
        try { Remove-Item -LiteralPath $verified.Directory -Recurse -Force -ErrorAction Stop }
        catch {
            Set-PrivateHarnessCleanupAccess $verified.Directory $verified.Diagnostic
            Remove-Item -LiteralPath $verified.Directory -Recurse -Force -ErrorAction Stop
        }
    }
    if (Test-Path -LiteralPath $verified.Diagnostic) { throw "Harness diagnostic '$($verified.Diagnostic)' still exists after cleanup." }
    if (Test-Path -LiteralPath $verified.Directory) { throw "Harness directory '$($verified.Directory)' still exists after cleanup." }
}

function Set-PreprovisionedDiagnosticArtifacts {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Diagnostic,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ServiceSID,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$OwnerSID,
        [switch]$SkipPostProvisionVerification
    )
    Assert-NoReparsePointPath $Directory
    try { [IO.File]::Open($Diagnostic, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::Read).Dispose() }
    catch { throw "Create pre-provisioned diagnostic file failed: $($_.Exception.Message)" }
    Assert-NoReparsePointPath $Diagnostic
    $fileSecurity = New-ExactDiagnosticSecurity $ServiceSID $OwnerSID -File
    $directorySecurity = New-ExactDiagnosticSecurity $ServiceSID $OwnerSID
    Assert-ExactDiagnosticSecurityObject $fileSecurity $ServiceSID $OwnerSID -File -SkipOwnerVerification
    Assert-ExactDiagnosticSecurityObject $directorySecurity $ServiceSID $OwnerSID -SkipOwnerVerification
    Set-Acl -LiteralPath $Diagnostic -AclObject $fileSecurity
    Set-Acl -LiteralPath $Directory -AclObject $directorySecurity
    if (-not $SkipPostProvisionVerification) {
        try {
            Assert-ExactDiagnosticSecurity $Directory $ServiceSID $OwnerSID
            Assert-ExactDiagnosticSecurity $Diagnostic $ServiceSID $OwnerSID -File
        }
        catch {
            Write-DiagnosticAclDiagnostics 'directory' $Directory
            Write-DiagnosticAclDiagnostics 'diagnostic' $Diagnostic
            throw
        }
    }
}

function Invoke-ScDiagnostic {
    param(
        [Parameter(Mandatory = $true)][string]$ScPath,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $output = & $ScPath @Arguments 2>&1 | Out-String
    $exitCode = $LASTEXITCODE
    Write-Host "sc.exe $Label exit code: $exitCode"
    if (-not [string]::IsNullOrWhiteSpace($output)) { Write-Host $output.TrimEnd() }
    return $exitCode
}

function Write-SafeHarnessFailureDiagnostics {
    param(
        [Parameter(Mandatory = $true)][string]$ScPath,
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [string]$DiagnosticPath = ""
    )
    Write-Warning "Helper Service SID harness failed. Emitting non-secret service diagnostics."
    [void](Invoke-ScDiagnostic $ScPath 'query' @('query', $ServiceName))
    [void](Invoke-ScDiagnostic $ScPath 'qc' @('qc', $ServiceName))
    if (-not [string]::IsNullOrWhiteSpace($DiagnosticPath) -and (Test-Path -LiteralPath $DiagnosticPath)) {
        try {
            $health = Get-Content -LiteralPath $DiagnosticPath -Raw | ConvertFrom-Json
            $safe = [ordered]@{
                status = $health.status; capture_provider = $health.capture_provider; pipe_connected = $health.pipe_connected
                authenticated = $health.authenticated; lifecycle = $health.lifecycle; stop_timed_out = $health.stop_timed_out
                provider_cleanup = $health.provider_cleanup; service_sid_present = $health.service_sid_present
                restricted_sid_count = $health.restricted_sid_count; stage = $health.stage; attempt = $health.attempt
                reconnects = $health.reconnects; last_error = $health.last_error
            }
            Write-Host ("safe helper diagnostic: " + ($safe | ConvertTo-Json -Compress))
        }
        catch { Write-Warning "Diagnostic file exists but its safe public fields could not be parsed." }
    }
}

function Stop-VerifiedHarnessProcess {
    param(
        [Parameter(Mandatory = $true)]$Process,
        [Parameter(Mandatory = $true)][int]$ExpectedProcessID,
        [Parameter(Mandatory = $true)][long]$ExpectedStartTicks,
        [int]$WaitMilliseconds = 5000,
        [scriptblock]$KillProcess = { param($Target) $Target.Kill() },
        [scriptblock]$KillProcessTree = { param($Target) $Target.Kill($true) },
        [scriptblock]$WaitForExit = { param($Target, $Timeout) return $Target.WaitForExit($Timeout) },
        [scriptblock]$FindProcessByID = { param($ProcessID) return Get-Process -Id $ProcessID -ErrorAction SilentlyContinue }
    )
    $errors = [System.Collections.Generic.List[string]]::new()
    $result = [ordered]@{
        pid = $ExpectedProcessID
        start_ticks_utc = $ExpectedStartTicks
        identity_source = 'process_object'
        initially_exited = $false
        process_kill_attempted = $false
        initial_wait_completed = $false
        tree_kill_attempted = $false
        tree_wait_completed = $false
        final_has_exited = $false
        pid_residual = $false
        pid_reused = $false
        success = $false
        errors = @()
    }
    $identityVerified = $true
    try {
        if ([int]$Process.Id -ne $ExpectedProcessID) { throw "Core process object PID changed." }
        $result.initially_exited = [bool]$Process.HasExited
        $objectStartTicks = $null
        try {
            if ($null -ne $Process.StartTime) { $objectStartTicks = [long]$Process.StartTime.ToUniversalTime().Ticks }
        }
        catch { $objectStartTicks = $null }
        if ($null -ne $objectStartTicks) {
            if ($objectStartTicks -ne $ExpectedStartTicks) { throw "Core process object start time changed." }
        }
        else {
            $resident = & $FindProcessByID $ExpectedProcessID
            if ($null -ne $resident) {
                if ([long]$resident.StartTime.ToUniversalTime().Ticks -ne $ExpectedStartTicks) { throw "Core PID was reused before identity verification." }
                if ($result.initially_exited) { throw "Core process object exited while its original PID remains active." }
                $result.identity_source = 'pid_start_time'
            }
            elseif ($result.initially_exited) {
                # No termination authority is exercised here; launch-time identity plus PID absence proves cleanup.
                $result.identity_source = 'captured_start_time_pid_absent'
            }
            else { throw "Core process start time was unavailable while the process remained active." }
        }
    }
    catch {
        $errors.Add("Core process identity verification failed: $($_.Exception.Message)")
        $identityVerified = $false
    }

    $resolveKillTarget = {
        param([string]$Stage)
        $candidate = $null
        try { $candidate = & $FindProcessByID $ExpectedProcessID }
        catch {
            $errors.Add("$Stage PID lookup failed; termination refused: $($_.Exception.Message)")
            return $null
        }
        if ($null -eq $candidate) { return $null }
        try {
            if ($candidate -is [Diagnostics.Process] -and $candidate.Handle -eq [IntPtr]::Zero) { throw "process handle is unavailable" }
            $candidateID = [int]$candidate.Id
            $candidateStartTicks = [long]$candidate.StartTime.ToUniversalTime().Ticks
            if ($candidateID -ne $ExpectedProcessID -or $candidateStartTicks -ne $ExpectedStartTicks) {
                if ($candidateID -eq $ExpectedProcessID) { $result.pid_reused = $true }
                $errors.Add("$Stage PID/StartTime mismatch; termination refused.")
                return $null
            }
            return $candidate
        }
        catch {
            $errors.Add("$Stage StartTime could not be read; termination refused: $($_.Exception.Message)")
            return $null
        }
    }

    if ($identityVerified -and $result.initially_exited) {
        try { $result.initial_wait_completed = [bool](& $WaitForExit $Process $WaitMilliseconds) }
        catch { $errors.Add("Exited Core process wait confirmation failed: $($_.Exception.Message)") }
    }
    elseif ($identityVerified) {
        $killTarget = & $resolveKillTarget 'Core process termination'
        if ($null -ne $killTarget) {
            try {
                $result.process_kill_attempted = $true
                & $KillProcess $killTarget
            }
            catch {
                try { if (-not [bool]$Process.HasExited) { $errors.Add("Core process termination failed: $($_.Exception.Message)") } }
                catch { $errors.Add("Core process termination and state check failed: $($_.Exception.Message)") }
            }
        }
        try { $result.initial_wait_completed = [bool](& $WaitForExit $Process $WaitMilliseconds) }
        catch {
            try { if ([bool]$Process.HasExited) { $result.initial_wait_completed = $true } else { $errors.Add("Core process initial wait failed: $($_.Exception.Message)") } }
            catch { $errors.Add("Core process initial wait and state check failed: $($_.Exception.Message)") }
        }

        $stillRunning = $true
        try { $stillRunning = -not [bool]$Process.HasExited }
        catch { $errors.Add("Core process state check failed: $($_.Exception.Message)") }
        if (-not $result.initial_wait_completed -or $stillRunning) {
            $treeTarget = & $resolveKillTarget 'Core process tree termination'
            if ($null -ne $treeTarget) {
                try {
                    $result.tree_kill_attempted = $true
                    & $KillProcessTree $treeTarget
                }
                catch {
                    try { if (-not [bool]$Process.HasExited) { $errors.Add("Core process tree termination failed: $($_.Exception.Message)") } }
                    catch { $errors.Add("Core process tree termination and state check failed: $($_.Exception.Message)") }
                }
            }
            try { $result.tree_wait_completed = [bool](& $WaitForExit $Process $WaitMilliseconds) }
            catch {
                try { if ([bool]$Process.HasExited) { $result.tree_wait_completed = $true } else { $errors.Add("Core process tree wait failed: $($_.Exception.Message)") } }
                catch { $errors.Add("Core process tree wait and state check failed: $($_.Exception.Message)") }
            }
        }
    }

    try { $result.final_has_exited = [bool]$Process.HasExited }
    catch { $errors.Add("Core process final state check failed: $($_.Exception.Message)") }
    try {
        $resident = & $FindProcessByID $ExpectedProcessID
        if ($null -ne $resident) {
            $residentStartTicks = [long]$resident.StartTime.ToUniversalTime().Ticks
            if ($residentStartTicks -eq $ExpectedStartTicks) {
                $result.pid_residual = $true
                $errors.Add("Core process PID $ExpectedProcessID with the original start time is still running.")
            }
            else {
                # PID reuse is evidence, never authority to terminate an unrelated process.
                $result.pid_reused = $true
            }
        }
    }
    catch { $errors.Add("Core process PID residual check failed: $($_.Exception.Message)") }
    $result.errors = @($errors)
    $waitConfirmed = $result.initial_wait_completed -or $result.tree_wait_completed
    $result.success = $identityVerified -and $waitConfirmed -and $result.final_has_exited -and -not $result.pid_residual -and $errors.Count -eq 0
    return [PSCustomObject]$result
}

function Stop-OwnedHarnessLaunch {
    param(
        [Parameter(Mandatory = $true)]$Launch,
        [int]$WaitMilliseconds = 5000,
        [scriptblock]$FindProcessByID = { param($ProcessID) return Get-Process -Id $ProcessID -ErrorAction SilentlyContinue },
        [scriptblock]$KillFallback = { param($Target) $Target.Kill() },
        [scriptblock]$WaitFallback = { param($Target, $Timeout) return $Target.WaitForExit($Timeout) }
    )
    $errors = [System.Collections.Generic.List[string]]::new()
    $result = [ordered]@{
        pid = $Launch.ProcessId
        start_ticks_utc = $Launch.StartTicksUtc
        native = $null
        fallback_attempted = $false
        fallback_identity_confirmed = $false
        fallback_wait_completed = $false
        fallback_kill_refused = $false
        pid_reused = $false
        release = $null
        exit_confirmed = $false
        handles_closed = [bool]$Launch.NativeHandlesClosed
        success = $false
        errors = @()
    }
    try {
        $native = $Launch.Job.TryTerminateAndWait($Launch, $WaitMilliseconds)
        $result.native = $native
        if ($native.Success) {
            $result.exit_confirmed = [bool]$native.ExitConfirmed
            $result.handles_closed = [bool]$native.HandlesClosed
            $result.success = $result.exit_confirmed -and $result.handles_closed
            return [PSCustomObject]$result
        }
        $errors.Add("native owned-handle cleanup failed: $($native.Errors -join '; ')")
    }
    catch { $errors.Add("native owned-handle cleanup threw: $($_.Exception.Message)") }

    $candidate = $null
    try { $candidate = & $FindProcessByID $Launch.ProcessId }
    catch {
        $result.fallback_kill_refused = $true
        $errors.Add("PID fallback lookup failed; kill refused: $($_.Exception.Message)")
    }
    if ($null -eq $candidate -and -not $result.fallback_kill_refused) {
        try {
            $release = $Launch.Job.TryWaitForExitAndRelease($Launch, $WaitMilliseconds)
            $result.release = $release
            if ($release.Success) {
                $result.exit_confirmed = [bool]$release.ExitConfirmed
                $result.handles_closed = [bool]$release.HandlesClosed
                $result.success = $result.exit_confirmed -and $result.handles_closed
                $result.errors = @($errors)
                return [PSCustomObject]$result
            }
            $errors.Add("PID was absent but owned handle did not confirm exit: $($release.Errors -join '; ')")
        }
        catch { $errors.Add("PID-absent owned-handle release failed: $($_.Exception.Message)") }
    }
    elseif ($null -ne $candidate) {
        $candidateMatches = $false
        try {
            if ($candidate -isnot [Diagnostics.Process] -or $candidate.Handle -eq [IntPtr]::Zero) {
                throw "PID fallback could not acquire a stable process handle"
            }
            $candidateID = [int]$candidate.Id
            $candidateStartTicks = [long]$candidate.StartTime.ToUniversalTime().Ticks
            if ($candidateID -eq [int]$Launch.ProcessId -and $candidateStartTicks -eq [long]$Launch.StartTicksUtc) {
                $candidateMatches = $true
                $result.fallback_identity_confirmed = $true
            }
            else {
                $result.fallback_kill_refused = $true
                $result.pid_reused = $candidateID -eq [int]$Launch.ProcessId -and $candidateStartTicks -ne [long]$Launch.StartTicksUtc
                $errors.Add("PID fallback identity mismatch; kill refused.")
            }
        }
        catch {
            $result.fallback_kill_refused = $true
            $errors.Add("PID fallback StartTime could not be read; kill refused: $($_.Exception.Message)")
        }
        if ($candidateMatches) {
            $result.fallback_attempted = $true
            try { & $KillFallback $candidate }
            catch { $errors.Add("PID fallback termination failed: $($_.Exception.Message)") }
            try { $result.fallback_wait_completed = [bool](& $WaitFallback $candidate $WaitMilliseconds) }
            catch { $errors.Add("PID fallback wait failed: $($_.Exception.Message)") }
            if (-not $result.fallback_wait_completed) { $errors.Add("PID fallback wait timed out.") }
            try {
                $release = $Launch.Job.TryWaitForExitAndRelease($Launch, $WaitMilliseconds)
                $result.release = $release
                if ($release.Success) {
                    $result.exit_confirmed = [bool]$release.ExitConfirmed
                    $result.handles_closed = [bool]$release.HandlesClosed
                }
                else { $errors.Add("owned handle did not confirm fallback exit: $($release.Errors -join '; ')") }
            }
            catch { $errors.Add("owned-handle fallback release failed: $($_.Exception.Message)") }
        }
    }

    $result.handles_closed = [bool]$Launch.NativeHandlesClosed
    $result.success = $result.exit_confirmed -and $result.handles_closed -and -not $result.fallback_kill_refused -and $errors.Count -eq 0
    $result.errors = @($errors)
    return [PSCustomObject]$result
}

function Confirm-OwnedHarnessLaunchReleased {
    param(
        $Launch,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$WaitMilliseconds = 5000
    )
    if ($null -eq $Launch -or -not $Launch.Created -or $Launch.NativeHandlesClosed) { return $null }
    $release = $Launch.Job.TryWaitForExitAndRelease($Launch, $WaitMilliseconds)
    if (-not $release.Success -or -not $release.ExitConfirmed -or -not $release.HandlesClosed) {
        throw "$Label did not release owned native handles after Job cleanup: $($release.Errors -join '; ')"
    }
    return $release
}

function Start-HarnessOwnedProcess {
    param(
        [Parameter(Mandatory = $true)]$Job,
        [Parameter(Mandatory = $true)][string]$ApplicationPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $launch = $null
    $handoff = $null
    $cleanup = $null
    $primaryErrors = [System.Collections.Generic.List[string]]::new()
    try {
        $launch = $Job.StartAssignedProcess($ApplicationPath, $Arguments)
        if (-not $launch.Success) { $primaryErrors.Add("process launch failed: $($launch.Errors -join '; ')") }
        else {
            $handoff = $Job.AcceptSuccessfulLaunch($launch)
            if (-not $handoff.Success) { $primaryErrors.Add("process ownership handoff failed: $($handoff.Errors -join '; ')") }
        }
    }
    catch { $primaryErrors.Add("process launch threw before ownership handoff: $($_.Exception.Message)") }
    finally {
        if ($null -ne $launch -and $launch.Created -and $primaryErrors.Count -gt 0 -and -not $launch.NativeHandlesClosed) {
            try { $cleanup = Stop-OwnedHarnessLaunch $launch }
            catch { $primaryErrors.Add("initial failed-launch cleanup threw: $($_.Exception.Message)") }
        }
    }
    $cleanupSucceeded = $null -eq $cleanup -or [bool]$cleanup.success
    return [PSCustomObject]@{
        launch = $launch
        process = if ($null -ne $launch) { $launch.Process } else { $null }
        start_ticks_utc = if ($null -ne $launch) { $launch.StartTicksUtc } else { [long]0 }
        handoff = $handoff
        cleanup = $cleanup
        success = $primaryErrors.Count -eq 0 -and $cleanupSucceeded
        primary_errors = @($primaryErrors)
    }
}

function Wait-HarnessProcessIdentityGone {
    param(
        [Parameter(Mandatory = $true)][int]$ProcessID,
        [Parameter(Mandatory = $true)][long]$StartTicks,
        [int]$TimeoutMilliseconds = 5000
    )
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    do {
        $candidate = Get-Process -Id $ProcessID -ErrorAction SilentlyContinue
        if ($null -eq $candidate) {
            return [PSCustomObject]@{ pid = $ProcessID; gone = $true; pid_reused = $false; residual = $false }
        }
        try {
            if ([long]$candidate.StartTime.ToUniversalTime().Ticks -ne $StartTicks) {
                return [PSCustomObject]@{ pid = $ProcessID; gone = $true; pid_reused = $true; residual = $false }
            }
        }
        catch {
            if ([DateTime]::UtcNow -ge $deadline) {
                return [PSCustomObject]@{ pid = $ProcessID; gone = $false; pid_reused = $false; residual = $true; error = $_.Exception.Message }
            }
        }
        if ([DateTime]::UtcNow -ge $deadline) {
            return [PSCustomObject]@{ pid = $ProcessID; gone = $false; pid_reused = $false; residual = $true }
        }
        Start-Sleep -Milliseconds 50
    } while ($true)
}

function Close-HarnessJobAndVerifyCleanup {
    param(
        [Parameter(Mandatory = $true)]$Job,
        [Parameter(Mandatory = $true)]$CoreProcess,
        [Parameter(Mandatory = $true)][int]$CoreProcessID,
        [Parameter(Mandatory = $true)][long]$CoreStartTicks,
        [bool]$Assigned,
        [int]$WaitMilliseconds = 5000
    )
    $errors = [System.Collections.Generic.List[string]]::new()
    $members = [System.Collections.Generic.List[object]]::new()
    $closeAttempts = [System.Collections.Generic.List[object]]::new()
    $result = [ordered]@{
        assigned = $Assigned
        limit_flags = 'KILL_ON_JOB_CLOSE'
        silent_breakaway_enabled = $false
        closed = $false
        close_retried = $false
        close_attempts = @()
        active_member_count_before_close = 0
        child_member_count_before_close = 0
        child_cleanup_confirmed = $false
        child_results = @()
        core = $null
        success = $false
        errors = @()
    }
    try {
        if ([uint32]$Job.LimitFlags -ne [uint32]0x2000) { throw "Job limit flags are not exactly KILL_ON_JOB_CLOSE." }
        foreach ($memberIDValue in @($Job.ActiveProcessIds())) {
            if ([uint64]$memberIDValue -gt [uint32]::MaxValue) { throw "Job member PID exceeds Windows PID range." }
            $memberID = [int][uint32]$memberIDValue
            $member = Get-Process -Id $memberID -ErrorAction SilentlyContinue
            if ($null -eq $member) { continue }
            $members.Add([PSCustomObject]@{ pid = $memberID; start_ticks_utc = [long]$member.StartTime.ToUniversalTime().Ticks })
        }
        $result.active_member_count_before_close = $members.Count
        $result.child_member_count_before_close = @($members | Where-Object { $_.pid -ne $CoreProcessID }).Count
    }
    catch { $errors.Add("Job member snapshot failed: $($_.Exception.Message)") }

    for ($attempt = 1; $attempt -le 2 -and -not $Job.IsClosed; $attempt++) {
        try {
            $close = $Job.TryClose()
            $closeAttempts.Add([PSCustomObject]@{
                attempt = $close.Attempt
                success = [bool]$close.Success
                already_closed = [bool]$close.AlreadyClosed
                handle_retained = [bool]$close.HandleRetained
                error_code = $close.ErrorCode
                error = $close.Error
            })
        }
        catch { $closeAttempts.Add([PSCustomObject]@{ attempt = $attempt; success = $false; handle_retained = $true; error = $_.Exception.Message }) }
    }
    $result.closed = [bool]$Job.IsClosed
    $result.close_retried = $closeAttempts.Count -gt 1

    $coreCleanup = Stop-VerifiedHarnessProcess $CoreProcess $CoreProcessID $CoreStartTicks -WaitMilliseconds $WaitMilliseconds
    $result.core = $coreCleanup
    if (-not $coreCleanup.success) { $errors.Add("Core cleanup did not prove exit: $($coreCleanup | ConvertTo-Json -Depth 4 -Compress)") }

    $childResults = [System.Collections.Generic.List[object]]::new()
    foreach ($member in $members) {
        if ($member.pid -eq $CoreProcessID) { continue }
        if ($Job.IsClosed) {
            $childResult = Wait-HarnessProcessIdentityGone $member.pid $member.start_ticks_utc $WaitMilliseconds
        }
        else {
            $childProcess = Get-Process -Id $member.pid -ErrorAction SilentlyContinue
            if ($null -eq $childProcess) {
                $childResult = [PSCustomObject]@{ pid = $member.pid; gone = $true; pid_reused = $false; residual = $false; direct_fallback = $true }
            }
            else {
                $directCleanup = Stop-VerifiedHarnessProcess $childProcess $member.pid $member.start_ticks_utc -WaitMilliseconds $WaitMilliseconds
                $childResult = [PSCustomObject]@{
                    pid = $member.pid
                    gone = [bool]$directCleanup.success
                    pid_reused = [bool]$directCleanup.pid_reused
                    residual = [bool]$directCleanup.pid_residual
                    direct_fallback = $true
                    cleanup = $directCleanup
                }
            }
        }
        $childResults.Add($childResult)
        if (-not $childResult.gone -or $childResult.residual) { $errors.Add("Job child PID $($member.pid) survived cleanup.") }
    }

    if (-not $Job.IsClosed) {
        try {
            foreach ($memberIDValue in @($Job.ActiveProcessIds())) {
                $memberID = [int][uint32]$memberIDValue
                if ($memberID -eq $PID) { throw "Harness attempted to clean its own PID from the Job." }
                $memberProcess = Get-Process -Id $memberID -ErrorAction SilentlyContinue
                if ($null -eq $memberProcess) { continue }
                $memberStartTicks = [long]$memberProcess.StartTime.ToUniversalTime().Ticks
                $memberCleanup = Stop-VerifiedHarnessProcess $memberProcess $memberID $memberStartTicks -WaitMilliseconds $WaitMilliseconds
                if (-not $memberCleanup.success) { $errors.Add("Late Job member PID $memberID survived direct fallback cleanup.") }
            }
        }
        catch { $errors.Add("Job member fallback cleanup failed: $($_.Exception.Message)") }
        try {
            $close = $Job.TryClose()
            $closeAttempts.Add([PSCustomObject]@{
                attempt = $close.Attempt
                success = [bool]$close.Success
                already_closed = [bool]$close.AlreadyClosed
                handle_retained = [bool]$close.HandleRetained
                error_code = $close.ErrorCode
                error = $close.Error
                after_member_cleanup = $true
            })
        }
        catch { $closeAttempts.Add([PSCustomObject]@{ success = $false; handle_retained = $true; error = $_.Exception.Message; after_member_cleanup = $true }) }
    }
    $result.closed = [bool]$Job.IsClosed
    if (-not $result.closed) {
        try {
            $remainingMembers = @($Job.ActiveProcessIds())
            if ($remainingMembers.Count -gt 0) { $errors.Add("Job remained open with $($remainingMembers.Count) active member(s).") }
            else { $errors.Add("Job remained open after bounded close retries; no active members remained.") }
        }
        catch { $errors.Add("Job remained open and member verification failed: $($_.Exception.Message)") }
    }
    $result.child_results = @($childResults)
    $result.child_cleanup_confirmed = @($childResults | Where-Object { -not $_.gone -or $_.residual }).Count -eq 0
    $result.close_attempts = @($closeAttempts)
    $result.close_retried = $closeAttempts.Count -gt 1
    $result.errors = @($errors)
    $result.success = $Assigned -and $result.closed -and $coreCleanup.success -and $result.child_cleanup_confirmed -and $errors.Count -eq 0
    return [PSCustomObject]$result
}

function Close-HarnessJobWithBoundedFallback {
    param(
        [Parameter(Mandatory = $true)]$Job,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$WaitMilliseconds = 5000
    )
    $attempts = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()
    for ($attempt = 1; $attempt -le 3 -and -not $Job.IsClosed; $attempt++) {
        try {
            $close = $Job.TryClose()
            $attempts.Add([PSCustomObject]@{ attempt = $close.Attempt; success = [bool]$close.Success; handle_retained = [bool]$close.HandleRetained; error = $close.Error })
        }
        catch { $attempts.Add([PSCustomObject]@{ attempt = $attempt; success = $false; handle_retained = $true; error = $_.Exception.Message }) }
    }

    if (-not $Job.IsClosed) {
        try {
            foreach ($memberIDValue in @($Job.ActiveProcessIds())) {
                $memberID = [int][uint32]$memberIDValue
                if ($memberID -eq $PID) { throw "$Label fallback encountered its own PID in the Job." }
                $member = Get-Process -Id $memberID -ErrorAction SilentlyContinue
                if ($null -eq $member) { continue }
                $startTicks = [long]$member.StartTime.ToUniversalTime().Ticks
                $cleanup = Stop-VerifiedHarnessProcess $member $memberID $startTicks -WaitMilliseconds $WaitMilliseconds
                if (-not $cleanup.success) { $errors.Add("$Label member PID $memberID cleanup failed: $($cleanup.errors -join '; ')") }
            }
        }
        catch { $errors.Add("$Label member fallback failed: $($_.Exception.Message)") }
        try {
            $close = $Job.TryClose()
            $attempts.Add([PSCustomObject]@{ attempt = $close.Attempt; success = [bool]$close.Success; handle_retained = [bool]$close.HandleRetained; error = $close.Error; after_member_cleanup = $true })
        }
        catch { $attempts.Add([PSCustomObject]@{ success = $false; handle_retained = $true; error = $_.Exception.Message; after_member_cleanup = $true }) }
    }

    $remaining = @()
    if (-not $Job.IsClosed) {
        try { $remaining = @($Job.ActiveProcessIds()) }
        catch { $errors.Add("$Label residual member query failed: $($_.Exception.Message)") }
        $errors.Add("$Label Job handle remained open after bounded retries; active_members=$($remaining.Count)")
    }
    $result = [PSCustomObject]@{
        closed = [bool]$Job.IsClosed
        attempts = @($attempts)
        active_members = $remaining.Count
        success = [bool]$Job.IsClosed -and $remaining.Count -eq 0 -and $errors.Count -eq 0
        errors = @($errors)
    }
    if (-not $result.success) { throw "$Label bounded Job fallback failed: $($result | ConvertTo-Json -Depth 5 -Compress)" }
    return $result
}

function ConvertTo-SafeHealthEvidence {
    param($Health)
    if ($null -eq $Health) { return $null }
    $lastError = [string]$Health.last_error
    $lastError = $lastError -replace '(?i)(token\s*[=:]\s*)[^\s,;]+', '$1[redacted]'
    $lastError = $lastError -replace '(?i)\b[0-9a-f]{64}\b', '[redacted-sha256]'
    return [PSCustomObject][ordered]@{
        status = $Health.status
        capture_provider = $Health.capture_provider
        pipe_connected = [bool]$Health.pipe_connected
        authenticated = [bool]$Health.authenticated
        stage = $Health.stage
        attempt = $Health.attempt
        reconnects = $Health.reconnects
        last_error = $lastError
        lifecycle = $Health.lifecycle
        service_sid_present = [bool]$Health.service_sid_present
        restricted_sid_count = $Health.restricted_sid_count
        pid = $Health.pid
        updated_at = $Health.updated_at
        stop_timed_out = [bool]$Health.stop_timed_out
        provider_cleanup = $Health.provider_cleanup
    }
}

function ConvertTo-SafeReadyEvidence {
    param($Ready)
    if ($null -eq $Ready) { return $null }
    return [PSCustomObject][ordered]@{ stage = $Ready.stage; pid = $Ready.pid; pipe = $Ready.pipe }
}

function Assert-HarnessSuccessEvidence {
    param(
        [Parameter(Mandatory = $true)]$Health,
        [Parameter(Mandatory = $true)]$Ready,
        [Parameter(Mandatory = $true)][int]$CoreProcessID,
        [Parameter(Mandatory = $true)][int]$ServiceProcessID,
        [Parameter(Mandatory = $true)][string]$ExpectedPipe,
        [Parameter(Mandatory = $true)][string]$ServiceSID
    )
    if ($Health.status -ne 'not_ready' -or $Health.capture_provider -ne 'not_ready') { throw "helper fail-closed health state is invalid" }
    if (-not $Health.pipe_connected -or -not $Health.authenticated -or $Health.stage -ne 'authenticated') { throw "helper authenticated pipe health is invalid" }
    $attempt = [uint64]$Health.attempt
    $reconnects = [uint64]$Health.reconnects
    if ($attempt -lt 1 -or $attempt -gt 3 -or $reconnects -gt 2 -or $reconnects + 1 -ne $attempt) { throw "helper reconnect evidence is outside the bounded policy" }
    if (-not [string]::IsNullOrWhiteSpace([string]$Health.last_error)) { throw "successful helper health retained a pipe error" }
    if ($Health.lifecycle -ne 'running' -or [int]$Health.pid -ne $ServiceProcessID) { throw "helper lifecycle or PID evidence is invalid" }
    if (-not $Health.service_sid_present -or [int]$Health.restricted_sid_count -lt 1 -or $ServiceSID -notmatch '^S-1-5-80-[0-9-]+$') { throw "helper Service SID evidence is invalid" }
    if ($Ready.stage -ne 'listening' -or [int]$Ready.pid -ne $CoreProcessID -or $Ready.pipe -ne $ExpectedPipe) { throw "Core ready PID or pipe evidence is invalid" }
}

function Write-HarnessEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        $Health,
        $Ready,
        [Parameter(Mandatory = $true)]$Cleanup,
        [string]$Commit,
        [string]$ActionsRunID,
        [string]$ActionsRunAttempt,
        [string]$ServiceName,
        [string]$ServiceSID
    )
    if (-not [string]::IsNullOrWhiteSpace($Commit) -and $Commit -notmatch '^[0-9a-fA-F]{40}([0-9a-fA-F]{24})?$') { throw "evidence commit SHA is invalid" }
    if (-not [string]::IsNullOrWhiteSpace($ActionsRunID) -and $ActionsRunID -notmatch '^[0-9]+$') { throw "evidence run ID is invalid" }
    if (-not [string]::IsNullOrWhiteSpace($ActionsRunAttempt) -and $ActionsRunAttempt -notmatch '^[0-9]+$') { throw "evidence run attempt is invalid" }
    $absolute = [IO.Path]::GetFullPath($Directory)
    [void][IO.Directory]::CreateDirectory($absolute)
    $utf8 = [Text.UTF8Encoding]::new($false)
    $documents = [ordered]@{
        'health.sanitized.json' = $Health
        'ready.sanitized.json' = $Ready
        'cleanup.json' = $Cleanup
    }
    $hashes = [ordered]@{}
    foreach ($entry in $documents.GetEnumerator()) {
        $path = Join-Path $absolute $entry.Key
        [IO.File]::WriteAllText($path, ($entry.Value | ConvertTo-Json -Depth 8), $utf8)
        $hashes[$entry.Key] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $manifest = [PSCustomObject][ordered]@{
        schema_version = 1
        commit_sha = $Commit.ToLowerInvariant()
        run_id = $ActionsRunID
        run_attempt = $ActionsRunAttempt
        workflow = $env:GITHUB_WORKFLOW
        job = $env:GITHUB_JOB
        generated_at = [DateTime]::UtcNow.ToString('o')
        service_name = $ServiceName
        service_sid = $ServiceSID
        files = $hashes
    }
    $manifestPath = Join-Path $absolute 'manifest.json'
    [IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json -Depth 8), $utf8)
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $absolute 'manifest.sha256'), "$manifestHash  manifest.json`n", $utf8)
}

function Invoke-HarnessJobProcessFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Command
    )
    $job = $null
    $process = $null
    $startResult = $null
    $startTicks = [long]0
    $cleanup = $null
    try {
        $powerShellPath = (Get-Process -Id $PID).Path
        $job = [TachyonHarness.KillOnCloseJob]::Create()
        $startOutcome = Start-HarnessOwnedProcess $job $powerShellPath ([string[]]@('-NoProfile', '-NonInteractive', '-Command', $Command))
        $startResult = $startOutcome.launch
        if (-not $startOutcome.success) {
            throw "$Label fixture process failed to start safely: $($startOutcome | Select-Object success,primary_errors,cleanup | ConvertTo-Json -Depth 6 -Compress)"
        }
        $process = $startOutcome.process
        $startTicks = [long]$startOutcome.start_ticks_utc
        if (@($job.ActiveProcessIds()) -notcontains [uint64]$process.Id) { throw "$Label fixture process was not assigned to the Job." }
        $cleanup = Close-HarnessJobAndVerifyCleanup $job $process $process.Id $startTicks $true
        if (-not $cleanup.success -or -not $cleanup.assigned -or -not $cleanup.closed -or
            $cleanup.silent_breakaway_enabled -or -not $cleanup.core.success -or -not $cleanup.child_cleanup_confirmed) {
            throw "$Label fixture did not prove bounded Job cleanup: $($cleanup.errors -join '; ')"
        }
        return $cleanup
    }
    finally {
        if ($null -ne $startResult -and $startResult.Created -and -not $startResult.NativeHandlesClosed) {
            $ownedFallback = Stop-OwnedHarnessLaunch $startResult
            if (-not $ownedFallback.success) { throw "$Label fixture owner fallback failed: $($ownedFallback.errors -join '; ')" }
        }
        if ($null -ne $job -and -not $job.IsClosed) {
            [void](Close-HarnessJobWithBoundedFallback $job "$Label fixture")
        }
        [void](Confirm-OwnedHarnessLaunchReleased $startResult "$Label fixture")
        if ($null -ne $process -and $startTicks -ne 0) {
            $fallback = Stop-VerifiedHarnessProcess $process $process.Id $startTicks
            if (-not $fallback.success) { throw "$Label fixture fallback did not prove process exit: $($fallback.errors -join '; ')" }
        }
    }
}

function Invoke-FastParentJobCleanupFixture {
    $directory = Join-Path ([IO.Path]::GetTempPath()) "tachyon-helper-job-child-$([guid]::NewGuid().ToString('N'))"
    $childPIDPath = Join-Path $directory 'child.pid'
    $job = $null
    $parent = $null
    $parentStartResult = $null
    $parentStartTicks = [long]0
    $child = $null
    $childStartTicks = [long]0
    try {
        [void][IO.Directory]::CreateDirectory($directory)
        $powerShellPath = (Get-Process -Id $PID).Path
        $escapedPowerShellPath = $powerShellPath.Replace("'", "''")
        $escapedChildPIDPath = $childPIDPath.Replace("'", "''")
        $parentScript = "`$child = Start-Process -FilePath '$escapedPowerShellPath' -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden; [IO.File]::WriteAllText('$escapedChildPIDPath', [string]`$child.Id)"
        $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($parentScript))

        $job = [TachyonHarness.KillOnCloseJob]::Create()
        $parentStartOutcome = Start-HarnessOwnedProcess $job $powerShellPath ([string[]]@('-NoProfile', '-NonInteractive', '-EncodedCommand', $encodedCommand))
        $parentStartResult = $parentStartOutcome.launch
        if (-not $parentStartOutcome.success) {
            throw "Fast-parent fixture process failed to start safely: $($parentStartOutcome | Select-Object success,primary_errors,cleanup | ConvertTo-Json -Depth 6 -Compress)"
        }
        $parent = $parentStartOutcome.process
        $parentStartTicks = [long]$parentStartOutcome.start_ticks_utc
        $parentWaitCompleted = [bool]$parent.WaitForExit(5000)
        if (-not $parentWaitCompleted -or -not $parent.HasExited) { throw "Fast-parent fixture parent did not exit within the bounded wait." }

        $childDeadline = [DateTime]::UtcNow.AddSeconds(5)
        while (-not (Test-Path -LiteralPath $childPIDPath)) {
            if ([DateTime]::UtcNow -ge $childDeadline) { throw "Fast-parent fixture did not publish the child PID." }
            Start-Sleep -Milliseconds 25
        }
        $childPIDText = [IO.File]::ReadAllText($childPIDPath).Trim()
        $childPID = 0
        if (-not [int]::TryParse($childPIDText, [ref]$childPID) -or $childPID -le 0) { throw "Fast-parent fixture published an invalid child PID." }
        $child = Get-Process -Id $childPID -ErrorAction Stop
        $childStartTicks = [long]$child.StartTime.ToUniversalTime().Ticks
        if (@($job.ActiveProcessIds()) -notcontains [uint64]$childPID) { throw "Fast-parent fixture child did not inherit the Job." }

        $cleanup = Close-HarnessJobAndVerifyCleanup $job $parent $parent.Id $parentStartTicks $true
        if (-not $cleanup.success -or -not $cleanup.closed -or $cleanup.child_member_count_before_close -lt 1 -or
            -not $cleanup.child_cleanup_confirmed) {
            throw "Fast-parent fixture did not prove descendant cleanup: $($cleanup.errors -join '; ')"
        }
        $childGone = Wait-HarnessProcessIdentityGone $childPID $childStartTicks 5000
        if (-not $childGone.gone -or $childGone.residual) { throw "Fast-parent fixture left the long-running child behind." }
        return $cleanup
    }
    finally {
        if ($null -ne $parentStartResult -and $parentStartResult.Created -and -not $parentStartResult.NativeHandlesClosed) {
            $ownedFallback = Stop-OwnedHarnessLaunch $parentStartResult
            if (-not $ownedFallback.success) { throw "Fast-parent fixture owner fallback failed: $($ownedFallback.errors -join '; ')" }
        }
        if ($null -ne $job -and -not $job.IsClosed) {
            [void](Close-HarnessJobWithBoundedFallback $job 'Fast-parent fixture')
        }
        [void](Confirm-OwnedHarnessLaunchReleased $parentStartResult 'Fast-parent fixture')
        foreach ($entry in @(
            @{ Label = 'child'; Process = $child; StartTicks = $childStartTicks },
            @{ Label = 'parent'; Process = $parent; StartTicks = $parentStartTicks }
        )) {
            if ($null -eq $entry.Process -or $entry.StartTicks -eq 0) { continue }
            $fallback = Stop-VerifiedHarnessProcess $entry.Process $entry.Process.Id $entry.StartTicks
            if (-not $fallback.success) { throw "Fast-parent fixture $($entry.Label) fallback did not prove exit: $($fallback.errors -join '; ')" }
        }
        if (Test-Path -LiteralPath $directory) {
            Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $directory) { throw "Fast-parent fixture left its temporary directory behind." }
        }
    }
}

function Invoke-HarnessJobFaultInjectionTests {
    $powerShellPath = (Get-Process -Id $PID).Path
    $failedStartEvidence = [System.Collections.Generic.List[object]]::new()
    foreach ($fixture in @(
        @{ Label = 'assign'; AssignFailures = 1; TerminateFailures = 0; ResumeFailures = 0; ExpectAssigned = $false; InjectFallbackFailure = $false },
        @{ Label = 'terminate-fallback'; AssignFailures = 1; TerminateFailures = 1; ResumeFailures = 0; ExpectAssigned = $false; InjectFallbackFailure = $true },
        @{ Label = 'resume'; AssignFailures = 0; TerminateFailures = 0; ResumeFailures = 1; ExpectAssigned = $true; InjectFallbackFailure = $false }
    )) {
        $job = $null
        $start = $null
        $initialCleanup = $null
        $finalCleanup = $null
        try {
            $job = [TachyonHarness.KillOnCloseJob]::CreateWithFaults($fixture.AssignFailures, $fixture.TerminateFailures, 0, $fixture.ResumeFailures)
            $start = $job.StartAssignedProcess($powerShellPath, [string[]]@('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30'))
            if ($start.Success -or -not $start.Created -or ([bool]$start.Assigned -ne [bool]$fixture.ExpectAssigned) -or $start.Resumed -or
                -not $start.HasNativeProcessHandle -or -not $start.HasNativeThreadHandle -or $start.NativeHandlesClosed) {
                throw "$($fixture.Label) fixture did not return an owned failed-start state."
            }
            if ($fixture.InjectFallbackFailure) {
                $initialCleanup = Stop-OwnedHarnessLaunch $start -KillFallback { param($Target) } -WaitFallback { param($Target, $Timeout) return $false }
                if ($initialCleanup.success -or -not $initialCleanup.fallback_attempted -or $initialCleanup.fallback_kill_refused -or $start.NativeHandlesClosed) {
                    throw "Terminate/fallback failure fixture did not preserve ownership for outer finally retry."
                }
            }
            else {
                $initialCleanup = Stop-OwnedHarnessLaunch $start
                if (-not $initialCleanup.success -or -not $start.NativeHandlesClosed) {
                    throw "$($fixture.Label) fixture did not complete owned-handle cleanup: $($initialCleanup.errors -join '; ')"
                }
            }
        }
        finally {
            if ($null -ne $start -and $start.Created -and -not $start.NativeHandlesClosed) {
                $finalCleanup = Stop-OwnedHarnessLaunch $start
                if (-not $finalCleanup.success) { throw "$($fixture.Label) outer finally retry failed: $($finalCleanup.errors -join '; ')" }
            }
            if ($null -ne $job -and -not $job.IsClosed) { [void](Close-HarnessJobWithBoundedFallback $job "$($fixture.Label) failure fixture") }
            [void](Confirm-OwnedHarnessLaunchReleased $start "$($fixture.Label) failure fixture")
        }
        $gone = Wait-HarnessProcessIdentityGone $start.ProcessId $start.StartTicksUtc 5000
        if (-not $gone.gone -or $gone.residual -or -not $start.NativeHandlesClosed) { throw "$($fixture.Label) fixture left process ownership unresolved." }
        $failedStartEvidence.Add([PSCustomObject]@{
            label = $fixture.Label
            assigned = [bool]$start.Assigned
            initial_cleanup_success = [bool]$initialCleanup.success
            outer_retry_used = $null -ne $finalCleanup
            outer_retry_success = $null -eq $finalCleanup -or [bool]$finalCleanup.success
            handles_closed = [bool]$start.NativeHandlesClosed
            residual = [bool]$gone.residual
        })
    }

    $replacementJob = $null
    $replacementStart = $null
    $replacementProcess = $null
    $replacementTicks = [long]0
    $replacementKillCalls = [PSCustomObject]@{ Value = 0 }
    try {
        $replacementJob = [TachyonHarness.KillOnCloseJob]::CreateWithFaults(1, 1, 0, 0)
        $replacementStart = $replacementJob.StartAssignedProcess($powerShellPath, [string[]]@('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30'))
        $replacementProcess = Start-Process -FilePath $powerShellPath -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden
        $replacementTicks = [long]$replacementProcess.StartTime.ToUniversalTime().Ticks
        $refused = Stop-OwnedHarnessLaunch $replacementStart `
            -FindProcessByID { param($ProcessID) return $replacementProcess } `
            -KillFallback { param($Target) $replacementKillCalls.Value++ }
        if ($refused.success -or -not $refused.fallback_kill_refused -or $replacementKillCalls.Value -ne 0 -or $replacementProcess.HasExited) {
            throw "PID replacement fixture did not refuse fallback termination."
        }
    }
    finally {
        if ($null -ne $replacementStart -and $replacementStart.Created -and -not $replacementStart.NativeHandlesClosed) {
            $ownerRetry = Stop-OwnedHarnessLaunch $replacementStart
            if (-not $ownerRetry.success) { throw "PID replacement fixture owner retry failed: $($ownerRetry.errors -join '; ')" }
        }
        if ($null -ne $replacementJob -and -not $replacementJob.IsClosed) { [void](Close-HarnessJobWithBoundedFallback $replacementJob 'PID replacement fixture') }
        [void](Confirm-OwnedHarnessLaunchReleased $replacementStart 'PID replacement fixture')
        if ($null -ne $replacementProcess -and $replacementTicks -ne 0) {
            $replacementCleanup = Stop-VerifiedHarnessProcess $replacementProcess $replacementProcess.Id $replacementTicks
            if (-not $replacementCleanup.success) { throw "PID replacement control process cleanup failed: $($replacementCleanup.errors -join '; ')" }
        }
    }

    $closeJob = $null
    $closeProcess = $null
    $closeStart = $null
    $closeStartTicks = [long]0
    $retryEvidence = $null
    try {
        $closeJob = [TachyonHarness.KillOnCloseJob]::CreateWithFaults(0, 0, 1, 0)
        $closeOutcome = Start-HarnessOwnedProcess $closeJob $powerShellPath ([string[]]@('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30'))
        $closeStart = $closeOutcome.launch
        if (-not $closeOutcome.success) { throw "CloseHandle retry fixture could not start: $($closeOutcome.primary_errors -join '; ')" }
        $closeProcess = $closeOutcome.process
        $closeStartTicks = [long]$closeOutcome.start_ticks_utc
        $firstClose = $closeJob.TryClose()
        if ($firstClose.Success -or -not $firstClose.HandleRetained -or $closeJob.IsClosed -or $closeProcess.HasExited) {
            throw "Injected CloseHandle failure did not retain the live Job and process."
        }
        $secondClose = $closeJob.TryClose()
        if (-not $secondClose.Success -or $secondClose.AlreadyClosed -or -not $closeJob.IsClosed) {
            throw "Retried CloseHandle did not close the retained Job handle."
        }
        $idempotentClose = $closeJob.TryClose()
        if (-not $idempotentClose.Success -or -not $idempotentClose.AlreadyClosed) { throw "Closed Job state was not idempotent." }
        $gone = Wait-HarnessProcessIdentityGone $closeProcess.Id $closeStartTicks 5000
        if (-not $gone.gone -or $gone.residual) { throw "Retried Job close left its member process behind." }
        $retryEvidence = [PSCustomObject]@{
            first_success = [bool]$firstClose.Success
            first_handle_retained = [bool]$firstClose.HandleRetained
            second_success = [bool]$secondClose.Success
            idempotent_success = [bool]$idempotentClose.Success
            member_cleanup_confirmed = [bool]$gone.gone -and -not [bool]$gone.residual
        }
    }
    finally {
        if ($null -ne $closeStart -and $closeStart.Created -and -not $closeStart.NativeHandlesClosed) {
            $ownerFallback = Stop-OwnedHarnessLaunch $closeStart
            if (-not $ownerFallback.success) { throw "CloseHandle retry fixture owner fallback failed: $($ownerFallback.errors -join '; ')" }
        }
        if ($null -ne $closeJob -and -not $closeJob.IsClosed) { [void](Close-HarnessJobWithBoundedFallback $closeJob 'CloseHandle retry fixture') }
        [void](Confirm-OwnedHarnessLaunchReleased $closeStart 'CloseHandle retry fixture')
        if ($null -ne $closeProcess -and $closeStartTicks -ne 0) {
            $fallback = Stop-VerifiedHarnessProcess $closeProcess $closeProcess.Id $closeStartTicks
            if (-not $fallback.success) { throw "CloseHandle retry fixture fallback did not prove process exit: $($fallback.errors -join '; ')" }
        }
    }

    $persistentJob = $null
    $persistentProcess = $null
    $persistentStart = $null
    $persistentStartTicks = [long]0
    $persistentChild = $null
    $persistentChildStartTicks = [long]0
    $persistentDirectory = Join-Path ([IO.Path]::GetTempPath()) "tachyon-helper-close-fault-$([guid]::NewGuid().ToString('N'))"
    $persistentChildPIDPath = Join-Path $persistentDirectory 'child.pid'
    $primaryFailureEvidence = $null
    try {
        [void][IO.Directory]::CreateDirectory($persistentDirectory)
        $escapedPowerShellPath = $powerShellPath.Replace("'", "''")
        $escapedChildPIDPath = $persistentChildPIDPath.Replace("'", "''")
        $persistentScript = "`$child = Start-Process -FilePath '$escapedPowerShellPath' -ArgumentList @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden; [IO.File]::WriteAllText('$escapedChildPIDPath', [string]`$child.Id); Start-Sleep -Seconds 30"
        $persistentCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($persistentScript))
        $persistentJob = [TachyonHarness.KillOnCloseJob]::CreateWithFaults(0, 0, 3, 0)
        $persistentOutcome = Start-HarnessOwnedProcess $persistentJob $powerShellPath ([string[]]@('-NoProfile', '-NonInteractive', '-EncodedCommand', $persistentCommand))
        $persistentStart = $persistentOutcome.launch
        if (-not $persistentOutcome.success) { throw "Persistent CloseHandle fixture could not start safely: $($persistentOutcome.primary_errors -join '; ')" }
        $persistentProcess = $persistentOutcome.process
        $persistentStartTicks = [long]$persistentOutcome.start_ticks_utc
        $childDeadline = [DateTime]::UtcNow.AddSeconds(5)
        while (-not (Test-Path -LiteralPath $persistentChildPIDPath)) {
            if ([DateTime]::UtcNow -ge $childDeadline) { throw "Persistent CloseHandle fixture did not publish its child PID." }
            Start-Sleep -Milliseconds 25
        }
        $persistentChildPID = 0
        if (-not [int]::TryParse([IO.File]::ReadAllText($persistentChildPIDPath).Trim(), [ref]$persistentChildPID) -or $persistentChildPID -le 0) {
            throw "Persistent CloseHandle fixture published an invalid child PID."
        }
        $persistentChild = Get-Process -Id $persistentChildPID -ErrorAction Stop
        $persistentChildStartTicks = [long]$persistentChild.StartTime.ToUniversalTime().Ticks
        if (@($persistentJob.ActiveProcessIds()) -notcontains [uint64]$persistentChildPID) { throw "Persistent CloseHandle fixture child did not inherit the Job." }
        $primaryFailureEvidence = Close-HarnessJobAndVerifyCleanup $persistentJob $persistentProcess $persistentProcess.Id $persistentStartTicks $true
        if ($primaryFailureEvidence.success -or $primaryFailureEvidence.closed -or $primaryFailureEvidence.core.pid_residual -or
            -not $primaryFailureEvidence.child_cleanup_confirmed -or $primaryFailureEvidence.child_member_count_before_close -lt 1) {
            throw "Persistent CloseHandle fixture did not fail closed after bounded primary retries."
        }
    }
    finally {
        if ($null -ne $persistentStart -and $persistentStart.Created -and -not $persistentStart.NativeHandlesClosed) {
            $ownerFallback = Stop-OwnedHarnessLaunch $persistentStart
            if (-not $ownerFallback.success) { throw "Persistent CloseHandle fixture owner fallback failed: $($ownerFallback.errors -join '; ')" }
        }
        if ($null -ne $persistentJob -and -not $persistentJob.IsClosed) { [void](Close-HarnessJobWithBoundedFallback $persistentJob 'Persistent CloseHandle fixture') }
        [void](Confirm-OwnedHarnessLaunchReleased $persistentStart 'Persistent CloseHandle fixture')
        foreach ($entry in @(
            @{ Label = 'parent'; Process = $persistentProcess; StartTicks = $persistentStartTicks },
            @{ Label = 'child'; Process = $persistentChild; StartTicks = $persistentChildStartTicks }
        )) {
            if ($null -eq $entry.Process -or $entry.StartTicks -eq 0) { continue }
            $fallback = Stop-VerifiedHarnessProcess $entry.Process $entry.Process.Id $entry.StartTicks
            if (-not $fallback.success) { throw "Persistent CloseHandle fixture $($entry.Label) fallback did not prove process exit: $($fallback.errors -join '; ')" }
        }
        if (Test-Path -LiteralPath $persistentDirectory) {
            Remove-Item -LiteralPath $persistentDirectory -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $persistentDirectory) { throw "Persistent CloseHandle fixture left its temporary directory behind." }
        }
    }
    if ($null -eq $primaryFailureEvidence -or -not $persistentJob.IsClosed) { throw "Persistent CloseHandle fixture did not complete final cleanup." }

    return [PSCustomObject]@{
        failed_starts = @($failedStartEvidence)
        close_retry = $retryEvidence
        persistent_close_primary_failure = [PSCustomObject]@{
            success = [bool]$primaryFailureEvidence.success
            closed = [bool]$primaryFailureEvidence.closed
            member_cleanup_confirmed = [bool]$primaryFailureEvidence.child_cleanup_confirmed
            fallback_closed = [bool]$persistentJob.IsClosed
        }
    }
}

function Invoke-EvidenceFailureTests {
    $baselineHealth = [PSCustomObject]@{
        status = 'not_ready'; capture_provider = 'not_ready'; pipe_connected = $true; authenticated = $true
        stage = 'authenticated'; attempt = 1; reconnects = 0; last_error = $null; lifecycle = 'running'
        service_sid_present = $true; restricted_sid_count = 1; pid = 200
    }
    $baselineReady = [PSCustomObject]@{ stage = 'listening'; pid = 100; pipe = '\\.\pipe\Tachyon\evidence-test' }
    foreach ($case in @(
        @{ Name = 'wrong stage'; Mutate = { param($Health, $Ready) $Health.stage = 'connect_failed' } },
        @{ Name = 'missing attempt'; Mutate = { param($Health, $Ready) $Health.attempt = 0 } },
        @{ Name = 'unexpected reconnect'; Mutate = { param($Health, $Ready) $Health.reconnects = 1 } },
        @{ Name = 'retained error'; Mutate = { param($Health, $Ready) $Health.last_error = 'injected' } },
        @{ Name = 'wrong helper PID'; Mutate = { param($Health, $Ready) $Health.pid = 201 } },
        @{ Name = 'wrong pipe'; Mutate = { param($Health, $Ready) $Ready.pipe = '\\.\pipe\Tachyon\wrong' } },
        @{ Name = 'missing Service SID'; Mutate = { param($Health, $Ready) $Health.service_sid_present = $false } }
    )) {
        $health = $baselineHealth | ConvertTo-Json | ConvertFrom-Json
        $ready = $baselineReady | ConvertTo-Json | ConvertFrom-Json
        & $case.Mutate $health $ready
        $rejected = $false
        try { Assert-HarnessSuccessEvidence $health $ready 100 200 '\\.\pipe\Tachyon\evidence-test' 'S-1-5-80-1-2-3-4-5' }
        catch { $rejected = $true }
        if (-not $rejected) { throw "Evidence failure fixture '$($case.Name)' was accepted." }
    }

    $start = [DateTime]::UtcNow
    $stuck = [PSCustomObject]@{ Id = 4242; StartTime = $start; HasExited = $false }
    $stuckResult = Stop-VerifiedHarnessProcess $stuck 4242 $start.Ticks -WaitMilliseconds 1 `
        -KillProcess { param($Target) } -KillProcessTree { param($Target) } `
        -WaitForExit { param($Target, $Timeout) return $false } -FindProcessByID { param($ProcessID) return $stuck }
    if ($stuckResult.success -or -not $stuckResult.tree_kill_attempted -or -not $stuckResult.pid_residual) { throw "Stuck Core cleanup fixture was not rejected." }

    $escalated = [PSCustomObject]@{ Id = 4292; StartTime = $start; HasExited = $false }
    $escalatedResult = Stop-VerifiedHarnessProcess $escalated 4292 $start.Ticks -WaitMilliseconds 1 `
        -KillProcess { param($Target) } -KillProcessTree { param($Target) $Target.HasExited = $true } `
        -WaitForExit { param($Target, $Timeout) return [bool]$Target.HasExited } `
        -FindProcessByID { param($ProcessID) if ($escalated.HasExited) { return $null }; return $escalated }
    if (-not $escalatedResult.success -or -not $escalatedResult.tree_kill_attempted -or -not $escalatedResult.tree_wait_completed) { throw "Core tree-kill escalation fixture did not prove exit." }

    $exited = [PSCustomObject]@{ Id = 4343; StartTime = $start; HasExited = $true }
    $replacement = [PSCustomObject]@{ Id = 4343; StartTime = $start.AddSeconds(1); HasExited = $false }
    $killCalls = [PSCustomObject]@{ Value = 0 }
    $reusedResult = Stop-VerifiedHarnessProcess $exited 4343 $start.Ticks `
        -KillProcess { param($Target) $killCalls.Value++ } -KillProcessTree { param($Target) $killCalls.Value++ } `
        -WaitForExit { param($Target, $Timeout) return $true } -FindProcessByID { param($ProcessID) return $replacement }
    if (-not $reusedResult.success -or -not $reusedResult.pid_reused -or $killCalls.Value -ne 0) { throw "PID reuse fixture was killed or rejected." }

    $mismatched = [PSCustomObject]@{ Id = 4444; StartTime = $start; HasExited = $false }
    $mismatchKillCalls = [PSCustomObject]@{ Value = 0 }
    $mismatchResult = Stop-VerifiedHarnessProcess $mismatched 4445 $start.Ticks `
        -KillProcess { param($Target) $mismatchKillCalls.Value++ } -KillProcessTree { param($Target) $mismatchKillCalls.Value++ } `
        -FindProcessByID { param($ProcessID) return $null }
    if ($mismatchResult.success -or $mismatchKillCalls.Value -ne 0) { throw "Mismatched Core identity fixture was killed or accepted." }

    $testProcess = $null
    $testStartTicks = [long]0
    try {
        $powerShellPath = (Get-Process -Id $PID).Path
        $testProcess = Start-Process -FilePath $powerShellPath -ArgumentList @('-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 30') -PassThru -WindowStyle Hidden
        $testStartTicks = [long]$testProcess.StartTime.ToUniversalTime().Ticks
        $realCleanup = Stop-VerifiedHarnessProcess $testProcess $testProcess.Id $testStartTicks
        if (-not $realCleanup.success -or -not $realCleanup.initial_wait_completed -or -not $realCleanup.final_has_exited -or $realCleanup.pid_residual) {
            throw "Real console cleanup did not prove bounded process exit."
        }
    }
    finally {
        if ($null -ne $testProcess -and $testStartTicks -ne 0) {
            $fallbackCleanup = Stop-VerifiedHarnessProcess $testProcess $testProcess.Id $testStartTicks
            if (-not $fallbackCleanup.success) { throw "Real console cleanup test fallback did not prove exit: $($fallbackCleanup.errors -join '; ')" }
        }
    }

    $normalJobCleanup = Invoke-HarnessJobProcessFixture 'Normal Core' 'Start-Sleep -Seconds 30'
    $hungJobCleanup = Invoke-HarnessJobProcessFixture 'Hung Core' 'while ($true) { Start-Sleep -Milliseconds 100 }'
    $descendantJobCleanup = Invoke-FastParentJobCleanupFixture
    $jobFaultEvidence = Invoke-HarnessJobFaultInjectionTests

    $evidenceDirectory = Join-Path ([IO.Path]::GetTempPath()) "tachyon-helper-evidence-$([guid]::NewGuid().ToString('N'))"
    try {
        $secretHealth = $baselineHealth | ConvertTo-Json | ConvertFrom-Json
        $secretHealth.last_error = "token=do-not-publish hash=$('b' * 64)"
        $sanitizedSecretHealth = ConvertTo-SafeHealthEvidence $secretHealth
        if ($sanitizedSecretHealth.last_error -match 'do-not-publish' -or $sanitizedSecretHealth.last_error -match ('b' * 64)) {
            throw "Health evidence did not redact token or SHA-256 values."
        }
        $cleanup = [PSCustomObject]@{
            success = $true
            failures = @()
            core = $escalatedResult
            job = $descendantJobCleanup
            job_fixtures = [PSCustomObject]@{ normal = $normalJobCleanup; hung = $hungJobCleanup }
            job_faults = $jobFaultEvidence
        }
        Write-HarnessEvidence $evidenceDirectory (ConvertTo-SafeHealthEvidence $baselineHealth) (ConvertTo-SafeReadyEvidence $baselineReady) $cleanup `
            ('a' * 40) '12345' '2' 'TachyonHelperHarness-evidence' 'S-1-5-80-1-2-3-4-5'
        foreach ($name in @('health.sanitized.json', 'ready.sanitized.json', 'cleanup.json', 'manifest.json', 'manifest.sha256')) {
            if (-not (Test-Path -LiteralPath (Join-Path $evidenceDirectory $name))) { throw "Evidence file '$name' was not generated." }
        }
        $manifest = Get-Content -LiteralPath (Join-Path $evidenceDirectory 'manifest.json') -Raw | ConvertFrom-Json
        foreach ($name in @('health.sanitized.json', 'ready.sanitized.json', 'cleanup.json')) {
            $actualHash = (Get-FileHash -LiteralPath (Join-Path $evidenceDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($manifest.files.$name -ne $actualHash) { throw "Evidence hash mismatch for '$name'." }
        }
        $manifestHash = (Get-FileHash -LiteralPath (Join-Path $evidenceDirectory 'manifest.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        $recordedHash = ((Get-Content -LiteralPath (Join-Path $evidenceDirectory 'manifest.sha256') -Raw).Trim() -split ' ')[0]
        if ($recordedHash -ne $manifestHash -or $manifest.commit_sha -ne ('a' * 40) -or $manifest.run_id -ne '12345' -or $manifest.run_attempt -ne '2') {
            throw "Evidence manifest metadata or hash is invalid."
        }
        $cleanupEvidence = Get-Content -LiteralPath (Join-Path $evidenceDirectory 'cleanup.json') -Raw | ConvertFrom-Json
        if (-not $cleanupEvidence.job.assigned -or -not $cleanupEvidence.job.closed -or
            $cleanupEvidence.job.silent_breakaway_enabled -or -not $cleanupEvidence.job.child_cleanup_confirmed -or
            $cleanupEvidence.job.child_member_count_before_close -lt 1) {
            throw "Cleanup evidence did not preserve the Job assignment and descendant cleanup proof."
        }
        $allEvidence = (Get-ChildItem -LiteralPath $evidenceDirectory -File | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n"
        if ($allEvidence -match '(?i)token|trusted_server_sha256|core_sha256') { throw "Evidence output contains a forbidden secret field name." }
    }
    finally {
        if (Test-Path -LiteralPath $evidenceDirectory) { Remove-Item -LiteralPath $evidenceDirectory -Recurse -Force -ErrorAction Stop }
    }
    Write-Host "Harness evidence and cleanup failure tests passed."
}

function Wait-HarnessServiceState {
    param([Parameter(Mandatory = $true)][string]$ServiceName, [Parameter(Mandatory = $true)][string]$State, [int]$TimeoutSeconds = 10)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($State -eq 'Deleted' -and $null -eq $service) { return $true }
        if ($State -eq 'Stopped' -and ($null -eq $service -or $service.Status -eq 'Stopped')) { return $true }
        Start-Sleep -Milliseconds 200
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Invoke-HarnessPathSecurityTests {
    $programData = Join-Path ([IO.Path]::GetTempPath()) "tachyon-harness-path-$([guid]::NewGuid().ToString('N'))"
    try {
        $valid = Join-Path $programData "Tachyon\Harness\0123456789abcdef0123456789abcdef\helper-health.json"
        $validReady = Join-Path $programData "Tachyon\Harness\0123456789abcdef0123456789abcdef\core-ready.json"
        if ((Assert-HarnessDiagnosticPath $valid $programData) -ne [IO.Path]::GetFullPath($valid)) { throw "Valid harness path was not canonicalized." }
        if ((Assert-HarnessReadyPath $validReady $programData) -ne [IO.Path]::GetFullPath($validReady)) { throw "Valid ready path was not canonicalized." }
        foreach ($invalid in @(
            (Join-Path $programData "Tachyon\Harness\bad\helper-health.json"),
            (Join-Path $programData "Tachyon\Harness\0123456789abcdef0123456789abcdef\other.json"),
            (Join-Path $programData "Tachyon\Harness\0123456789abcdef0123456789abcdef\..\helper-health.json"),
            (Join-Path $programData "outside.json")
        )) {
            $accepted = $true
            try { [void](Assert-HarnessDiagnosticPath $invalid $programData) } catch { $accepted = $false }
            if ($accepted) { throw "Unsafe harness path was accepted: $invalid" }
        }
        foreach ($invalidReady in @(
            (Join-Path $programData "Tachyon\Harness\bad\core-ready.json"),
            (Join-Path $programData "Tachyon\Harness\0123456789abcdef0123456789abcdef\other.json"),
            (Join-Path $programData "Tachyon\Harness\0123456789abcdef0123456789abcdef\..\core-ready.json"),
            (Join-Path $programData "outside-ready.json")
        )) {
            $accepted = $true
            try { [void](Assert-HarnessReadyPath $invalidReady $programData) } catch { $accepted = $false }
            if ($accepted) { throw "Unsafe ready path was accepted: $invalidReady" }
        }
        $created = New-VerifiedHarnessPath '0123456789abcdef0123456789abcdef' $programData
        if (-not (Test-Path -LiteralPath $created.Directory) -or $created.Diagnostic -ne $valid -or $created.Ready -ne $validReady) {
            throw "Verified harness directory was not created at the expected canonical path."
        }
        Assert-NoReparsePointPath $created.Directory
        Write-Host "Harness path security tests passed."
    }
    finally {
        if (Test-Path -LiteralPath $programData) {
            Remove-Item -LiteralPath $programData -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $programData) { throw "Harness path security test cleanup left a residual directory." }
        }
    }
}

function Invoke-SetupFailureCleanupTest {
    $programData = Join-Path ([IO.Path]::GetTempPath()) "tachyon-harness-setup-failure-$([guid]::NewGuid().ToString('N'))"
    $resolved = Resolve-VerifiedHarnessPath '0123456789abcdef0123456789abcdef' $programData
    $completedHarness = $null
    $injectedFailureObserved = $false
    try {
        try {
            $partial = New-VerifiedHarnessPath '0123456789abcdef0123456789abcdef' $programData
            [IO.File]::WriteAllText($partial.Diagnostic, 'partial setup')
            $serviceSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')
            $ownerSID = [Security.Principal.WindowsIdentity]::GetCurrent().User
            Set-PreprovisionedDiagnosticArtifacts $partial.Directory $partial.Diagnostic $serviceSID $ownerSID -SkipPostProvisionVerification
            throw "injected harness setup failure"
        }
        catch {
            if ($_.Exception.Message -ne 'injected harness setup failure') { throw }
            $injectedFailureObserved = $true
        }
        finally {
            Remove-VerifiedHarnessArtifacts $resolved
        }
        if ($null -ne $completedHarness) { throw "Setup failure test unexpectedly assigned a completed harness." }
        if (-not $injectedFailureObserved) { throw "Setup failure test did not observe the injected failure." }
        if ((Test-Path -LiteralPath $resolved.Directory) -or (Test-Path -LiteralPath $resolved.Diagnostic)) {
            throw "Setup failure cleanup left harness artifacts behind."
        }
        Write-Host "Harness setup failure cleanup test passed."
    }
    finally {
        if (Test-Path -LiteralPath $programData) {
            Remove-Item -LiteralPath $programData -Recurse -Force -ErrorAction Stop
        }
    }
}

function Invoke-ProvisioningSecurityTests {
    $programData = Join-Path ([IO.Path]::GetTempPath()) "tachyon-harness-acl-$([guid]::NewGuid().ToString('N'))"
    $harness = $null
    try {
        $harness = New-VerifiedHarnessPath '0123456789abcdef0123456789abcdef' $programData
        $serviceSID = [Security.Principal.SecurityIdentifier]::new('S-1-5-80-1-2-3-4-5')
        $ownerSID = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $isAdministrator = ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ((Get-DiagnosticExpectedMask) -ne [uint32]0x120080) { throw "Directory rights did not canonicalize to 0x120080." }
        if ((Get-DiagnosticExpectedMask -File) -ne [uint32]0x120086) { throw "File rights did not canonicalize to 0x120086." }
        Set-PreprovisionedDiagnosticArtifacts $harness.Directory $harness.Diagnostic $serviceSID $ownerSID -SkipPostProvisionVerification:(-not $isAdministrator)
        if ($isAdministrator) {
            Assert-ExactDiagnosticSecurity $harness.Directory $serviceSID $ownerSID
            Assert-ExactDiagnosticSecurity $harness.Diagnostic $serviceSID $ownerSID -File
        }
        $fileACL = New-ExactDiagnosticSecurity $serviceSID $ownerSID -File
        $writeDAC = [Security.AccessControl.FileSystemRights]::ChangePermissions
        foreach ($accessRule in (Get-DiagnosticAccessRules $fileACL)) {
            $sid = $accessRule.IdentityReference.Value
            if (($sid -eq 'S-1-5-19' -or $sid -eq $serviceSID.Value) -and (($accessRule.FileSystemRights -band $writeDAC) -ne 0)) {
                throw "Least-privilege diagnostic ACE grants ChangePermissions."
            }
        }
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
        $splitACL = [Security.AccessControl.FileSecurity]::new()
        $splitSDDL = "O:$($ownerSID.Value)D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120086;;;LS)(A;;0x120080;;;$($serviceSID.Value))(A;;0x6;;;$($serviceSID.Value))"
        $logicalSplit = Get-RawDiagnosticSIDAccessSummary $splitSDDL $serviceSID
        if ($logicalSplit.Count -ne 2 -or $logicalSplit.Mask -ne [uint32]0x120086) {
            throw "Raw logical split-ACE input is invalid: count=$($logicalSplit.Count) union=0x$($logicalSplit.Mask.ToString('X'))."
        }
        $splitACL.SetSecurityDescriptorSddlForm($splitSDDL, $sections)
        $splitInput = Get-DiagnosticSIDAccessSummary $splitACL $serviceSID
        if (($splitInput.Count -ne 1 -and $splitInput.Count -ne 2) -or $splitInput.Mask -ne [uint32]0x120086) {
            throw "FileSecurity split-ACE canonicalization is not strictly equivalent: count=$($splitInput.Count) union=0x$($splitInput.Mask.ToString('X'))."
        }
        Assert-ExactDiagnosticSecurityObject $splitACL $serviceSID $ownerSID -File
        Write-DiagnosticAclObjectDiagnostics 'split input' $splitACL
        if ($isAdministrator) {
            Set-Acl -LiteralPath $harness.Diagnostic -AclObject $splitACL
            $persistedSplitACL = Get-Acl -LiteralPath $harness.Diagnostic
            $persistedSplit = Get-DiagnosticSIDAccessSummary $persistedSplitACL $serviceSID
            if (($persistedSplit.Count -ne 1 -and $persistedSplit.Count -ne 2) -or $persistedSplit.Mask -ne [uint32]0x120086) {
                Write-DiagnosticAclObjectDiagnostics 'persisted split' $persistedSplitACL
                throw "Persisted split-ACE fixture is not strictly equivalent: count=$($persistedSplit.Count) union=0x$($persistedSplit.Mask.ToString('X'))."
            }
            Assert-ExactDiagnosticSecurityObject $persistedSplitACL $serviceSID $ownerSID -File
            Write-DiagnosticAclObjectDiagnostics 'persisted split' $persistedSplitACL
            Write-Host "Persisted split-ACE fixture passed: logical_count=$($logicalSplit.Count) object_count=$($splitInput.Count) persisted_count=$($persistedSplit.Count) union=0x$($persistedSplit.Mask.ToString('X'))."
        }
        else { Write-Host "Logical split-ACE fixture passed: logical_count=$($logicalSplit.Count) object_count=$($splitInput.Count) union=0x$($splitInput.Mask.ToString('X')); elevated CI covers NTFS persistence." }

        $unexpectedACL = [Security.AccessControl.FileSecurity]::new()
        $unexpectedACL.SetSecurityDescriptorSddlForm("$splitSDDL(A;;0x2;;;BU)", $sections)
        Assert-DiagnosticSecurityRejected $unexpectedACL $serviceSID $ownerSID 'unexpected SID'
        $denyACL = [Security.AccessControl.FileSecurity]::new()
        $denyACL.SetSecurityDescriptorSddlForm("O:$($ownerSID.Value)D:PAI(D;;0x2;;;$($serviceSID.Value))(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120086;;;LS)(A;;0x120086;;;$($serviceSID.Value))", $sections)
        Assert-DiagnosticSecurityRejected $denyACL $serviceSID $ownerSID 'non-explicit allow ACE'
        $inheritedACL = [Security.AccessControl.FileSecurity]::new()
        $inheritedACL.SetSecurityDescriptorSddlForm("$splitSDDL(A;ID;0x1;;;SY)", $sections)
        Assert-DiagnosticSecurityRejected $inheritedACL $serviceSID $ownerSID 'non-explicit allow ACE'
        $writeDACACL = [Security.AccessControl.FileSecurity]::new()
        $writeDACACL.SetSecurityDescriptorSddlForm("O:$($ownerSID.Value)D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120086;;;LS)(A;;0x160086;;;$($serviceSID.Value))", $sections)
        Assert-DiagnosticSecurityRejected $writeDACACL $serviceSID $ownerSID 'broadens SID'
        Write-Host "Strict ACL rejection tests passed: extra SID, deny, inherited, and WRITE_DAC."
        Invoke-SetupFailureCleanupTest
        if (-not $isAdministrator) { Write-Host "Provisioning ACL object policy passed; elevated CI covers persisted ACL verification and LocalService E2E." }
        Write-Host "Harness diagnostic provisioning security tests passed."
    }
    finally {
        if ($null -ne $harness) { Remove-VerifiedHarnessArtifacts $harness }
        if (Test-Path -LiteralPath $programData) {
            Remove-Item -LiteralPath $programData -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $programData) { throw "Harness provisioning security test cleanup left a residual directory." }
        }
    }
}

if ($RunGoHarness) {
    & mise exec -- go test ./internal/capturedudp -run "TestWindowsNamedPipe(WrongSIDIsDeniedByACL|RejectsLowIntegrityPolicy|MatchesEnabledServiceGroup)$" -count=1
    if ($LASTEXITCODE -ne 0) { throw "Windows identity harness failed with exit code $LASTEXITCODE" }
}

if ($RunPathSecurityTests) { Invoke-HarnessPathSecurityTests }
if ($RunProvisioningSecurityTests) { Invoke-ProvisioningSecurityTests }
if ($RunEvidenceFailureTests) { Invoke-EvidenceFailureTests }

if ($RunServiceSIDHarness) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "The temporary Service SID harness requires an elevated PowerShell session."
    }
    $scPath = Join-Path $env:WINDIR "System32\sc.exe"
    if (-not (Test-Path -LiteralPath $scPath)) { throw "System32 sc.exe was not found." }
    $resolvedBinary = (Resolve-Path -LiteralPath $BinaryPath).Path
    $name = "TachyonHelperHarness-$([guid]::NewGuid().ToString('N'))"
    if ($name -notmatch '^[A-Za-z0-9_.-]{1,80}$' -or (Get-Service -Name $name -ErrorAction SilentlyContinue)) { throw "temporary service name validation failed" }
    $harnessID = [guid]::NewGuid().ToString('N')
    $corePipe = "\\.\pipe\Tachyon\harness-core-$harnessID"
    $serverSID = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    $diagnosticOwnerSID = ([Security.Principal.WindowsIdentity]::GetCurrent()).User
    $coreProcess = $null
    $coreStartResult = $null
    $coreStartTicks = [long]0
    $coreJob = $null
    $coreJobAssigned = $false
    $harness = $null
    $health = $null
    $ready = $null
    $safeHealth = $null
    $safeReady = $null
    $serviceSID = ""
    $harnessPath = Resolve-VerifiedHarnessPath $harnessID
    $trustedHash = (Get-FileHash -LiteralPath $resolvedBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    $quotedBinary = [char]34 + $resolvedBinary + [char]34
    $quotedTrustedBinary = [char]34 + $resolvedBinary + [char]34
    $failure = $null
    $cleanupFailures = [System.Collections.Generic.List[string]]::new()
    $cleanupEvidence = [ordered]@{
        service_stop_confirmed = $false
        service_delete_confirmed = $false
        job = $null
        core = $null
        diagnostic_removed = $false
        ready_removed = $false
        harness_directory_removed = $false
        success = $false
        failures = @()
    }
    try {
        & $scPath create $name binPath= "$quotedBinary helper --service --service-name $name --pipe $corePipe --server-sid $serverSID --core-binary $quotedTrustedBinary --core-sha256 $trustedHash" start= demand obj= "NT AUTHORITY\LocalService" | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service creation failed with exit code $LASTEXITCODE" }
        & $scPath sidtype $name restricted | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service SID setup failed with exit code $LASTEXITCODE" }
        $serviceSID = Resolve-ServiceSID $scPath $name
        $harness = New-ProtectedHarnessDirectory $harnessID $name $serviceSID $diagnosticOwnerSID
        if (-not [string]::Equals($harness.Directory, $harnessPath.Directory, [StringComparison]::OrdinalIgnoreCase) -or
            -not [string]::Equals($harness.Diagnostic, $harnessPath.Diagnostic, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Created harness path does not match the pre-resolved cleanup path."
        }
        $image = "$quotedBinary helper --service --service-name $name --service-sid $serviceSID --diagnostic-owner-sid $($diagnosticOwnerSID.Value) --pipe $corePipe --server-sid $serverSID --core-binary $quotedTrustedBinary --core-sha256 $trustedHash --diagnostic-file $($harness.Diagnostic) --diagnostic-test-override"
        & $scPath config $name binPath= $image | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service configuration failed with exit code $LASTEXITCODE" }
        $coreJob = [TachyonHarness.KillOnCloseJob]::Create()
        $coreStartOutcome = Start-HarnessOwnedProcess $coreJob $resolvedBinary ([string[]]@('helper', '--test-server', '--pipe', $corePipe, '--allow-sid', $serviceSID, '--ready-file', $harness.Ready))
        $coreStartResult = $coreStartOutcome.launch
        $coreJobAssigned = [bool]$coreStartResult.Assigned
        if (-not $coreStartOutcome.success) {
            throw "test Core failed to start safely: $($coreStartOutcome | Select-Object success,primary_errors,cleanup | ConvertTo-Json -Depth 6 -Compress)"
        }
        $coreProcess = $coreStartOutcome.process
        $coreStartTicks = [long]$coreStartOutcome.start_ticks_utc
        $readyDeadline = (Get-Date).AddSeconds(10)
        do {
            if ($coreProcess.HasExited) { throw "test Core exited before pipe readiness; exit_code=$($coreProcess.ExitCode)" }
            if (Test-Path -LiteralPath $harness.Ready) {
                try { $ready = Get-Content -LiteralPath $harness.Ready -Raw | ConvertFrom-Json }
                catch { $ready = $null }
                if ($null -ne $ready) {
                    if ($ready.stage -ne 'listening' -or [int]$ready.pid -ne $coreProcess.Id -or $ready.pipe -ne $corePipe) {
                        throw "test Core ready identity does not match the launched listener"
                    }
                    $safeReady = ConvertTo-SafeReadyEvidence $ready
                    break
                }
            }
            if ((Get-Date) -gt $readyDeadline) { throw "test Core did not publish pipe listener readiness" }
            Start-Sleep -Milliseconds 50
        } while ($true)
        & $scPath start $name | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "temporary service start failed with exit code $LASTEXITCODE" }
        $deadline = (Get-Date).AddSeconds(10)
        while (-not (Test-Path -LiteralPath $harness.Diagnostic)) {
            if ((Get-Date) -gt $deadline) { throw "helper diagnostic file was not produced" }
            Start-Sleep -Milliseconds 100
        }
        do {
            if ($coreProcess.HasExited) { throw "test Core exited during helper authentication; exit_code=$($coreProcess.ExitCode)" }
            $health = Get-Content -LiteralPath $harness.Diagnostic -Raw | ConvertFrom-Json
            if ($health.pipe_connected -and $health.authenticated) { break }
            if ((Get-Date) -gt $deadline) {
                throw "helper did not complete Core pipe authentication; stage=$($health.stage) attempt=$($health.attempt) reconnects=$($health.reconnects) last_error=$($health.last_error)"
            }
            Start-Sleep -Milliseconds 100
        } while ($true)
        if ($health.status -ne "not_ready") { throw "helper unexpectedly reported status '$($health.status)'" }
        if ($health.capture_provider -ne "not_ready") { throw "capture provider was not fail-closed" }
        $serviceInstance = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'"
        if ($null -eq $serviceInstance -or $serviceInstance.State -ne 'Running' -or [int]$serviceInstance.ProcessId -le 0) { throw "temporary helper service PID was not available" }
        Assert-HarnessSuccessEvidence $health $ready $coreProcess.Id ([int]$serviceInstance.ProcessId) $corePipe $serviceSID
        $safeHealth = ConvertTo-SafeHealthEvidence $health
        Write-Host "Temporary restricted Service SID harness passed; helper health is NotReady as required."
    }
    catch {
        $failure = $_
        if ($null -eq $safeReady -and $null -ne $ready) { $safeReady = ConvertTo-SafeReadyEvidence $ready }
        if ($null -eq $safeHealth -and $null -ne $health) { $safeHealth = ConvertTo-SafeHealthEvidence $health }
        if ($null -eq $safeHealth -and (Test-Path -LiteralPath $harnessPath.Diagnostic)) {
            try { $safeHealth = ConvertTo-SafeHealthEvidence (Get-Content -LiteralPath $harnessPath.Diagnostic -Raw | ConvertFrom-Json) }
            catch { Write-Warning "Failed health evidence could not be parsed for artifact output." }
        }
        if ($null -eq $safeReady -and (Test-Path -LiteralPath $harnessPath.Ready)) {
            try { $safeReady = ConvertTo-SafeReadyEvidence (Get-Content -LiteralPath $harnessPath.Ready -Raw | ConvertFrom-Json) }
            catch { Write-Warning "Failed ready evidence could not be parsed for artifact output." }
        }
        Write-DiagnosticAclDiagnostics 'directory' $harnessPath.Directory
        Write-DiagnosticAclDiagnostics 'diagnostic' $harnessPath.Diagnostic
        Write-SafeHarnessFailureDiagnostics $scPath $name $harnessPath.Diagnostic
    }
    finally {
        try {
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) {
                [void](Invoke-ScDiagnostic $scPath 'stop' @('stop', $name))
                if (Wait-HarnessServiceState $name 'Stopped') { $cleanupEvidence.service_stop_confirmed = $true }
                else { $cleanupFailures.Add("temporary service '$name' did not stop") }
                [void](Invoke-ScDiagnostic $scPath 'delete' @('delete', $name))
                if (Wait-HarnessServiceState $name 'Deleted') { $cleanupEvidence.service_delete_confirmed = $true }
                else { $cleanupFailures.Add("temporary service '$name' was not deleted") }
            }
            else {
                $cleanupEvidence.service_stop_confirmed = $true
                $cleanupEvidence.service_delete_confirmed = $true
            }
        }
        catch { $cleanupFailures.Add("service cleanup failed: $($_.Exception.Message)") }
        if ($null -ne $coreStartResult -and $coreStartResult.Created -and -not $coreStartResult.NativeHandlesClosed) {
            try {
                $ownedCleanup = Stop-OwnedHarnessLaunch $coreStartResult
                if (-not $ownedCleanup.success) { $cleanupFailures.Add("test Core owned launch cleanup failed: $($ownedCleanup.errors -join '; ')") }
            }
            catch { $cleanupFailures.Add("test Core owned launch cleanup threw: $($_.Exception.Message)") }
        }
        if ($null -ne $coreProcess -and $null -ne $coreJob) {
            try {
                $jobCleanup = Close-HarnessJobAndVerifyCleanup $coreJob $coreProcess $coreProcess.Id $coreStartTicks $coreJobAssigned
                $cleanupEvidence.job = $jobCleanup
                $cleanupEvidence.core = $jobCleanup.core
                if (-not $jobCleanup.success) { $cleanupFailures.Add("test Core Job cleanup did not prove process-tree exit: $($jobCleanup.errors -join '; ')") }
            }
            catch { $cleanupFailures.Add("test Core cleanup failed: $($_.Exception.Message)") }
        }
        elseif ($null -ne $coreProcess) {
            try {
                $coreCleanup = Stop-VerifiedHarnessProcess $coreProcess $coreProcess.Id $coreStartTicks
                $cleanupEvidence.core = $coreCleanup
                if (-not $coreCleanup.success) { $cleanupFailures.Add("test Core fallback cleanup did not prove process exit: $($coreCleanup.errors -join '; ')") }
            }
            catch { $cleanupFailures.Add("test Core fallback cleanup failed: $($_.Exception.Message)") }
        }
        else { $cleanupEvidence.core = [PSCustomObject]@{ success = $true; not_started = $true } }
        if ($null -ne $coreJob -and -not $coreJob.IsClosed) {
            try {
                $fallbackJobClose = Close-HarnessJobWithBoundedFallback $coreJob 'test Core Job'
                if ($null -eq $cleanupEvidence.job) {
                    $cleanupEvidence.job = [PSCustomObject]@{
                        assigned = $coreJobAssigned
                        limit_flags = 'KILL_ON_JOB_CLOSE'
                        silent_breakaway_enabled = $false
                        closed = $true
                        child_cleanup_confirmed = $true
                        success = $coreJobAssigned
                        fallback_close = $true
                        close_attempts = $fallbackJobClose.attempts
                    }
                }
            }
            catch {
                if ($null -eq $cleanupEvidence.job) {
                    $cleanupEvidence.job = [PSCustomObject]@{
                        assigned = $coreJobAssigned
                        limit_flags = 'KILL_ON_JOB_CLOSE'
                        silent_breakaway_enabled = $false
                        closed = [bool]$coreJob.IsClosed
                        child_cleanup_confirmed = $false
                        success = $false
                        fallback_close = $true
                        error = $_.Exception.Message
                    }
                }
                $cleanupFailures.Add("test Core Job fallback close failed: $($_.Exception.Message)")
            }
        }
        if ($null -ne $coreJob -and $null -eq $cleanupEvidence.job) {
            $cleanupEvidence.job = [PSCustomObject]@{
                assigned = $coreJobAssigned
                limit_flags = 'KILL_ON_JOB_CLOSE'
                silent_breakaway_enabled = $false
                closed = [bool]$coreJob.IsClosed
                child_cleanup_confirmed = $false
                success = $false
                fallback_close = $true
                error = 'primary Job cleanup did not produce structured evidence'
            }
            $cleanupFailures.Add("test Core Job cleanup did not produce structured evidence")
        }
        try { [void](Confirm-OwnedHarnessLaunchReleased $coreStartResult 'test Core Job') }
        catch { $cleanupFailures.Add("test Core owned handles remained after Job cleanup: $($_.Exception.Message)") }
        try { Remove-VerifiedHarnessArtifacts $harnessPath }
        catch { $cleanupFailures.Add("harness artifact cleanup failed: $($_.Exception.Message)") }
        try {
            if (Get-Service -Name $name -ErrorAction SilentlyContinue) { $cleanupFailures.Add("temporary service '$name' still exists after cleanup") }
            else { $cleanupEvidence.service_delete_confirmed = $true }
        }
        catch { $cleanupFailures.Add("temporary service residual check failed: $($_.Exception.Message)") }
        try {
            if (Test-Path -LiteralPath $harnessPath.Diagnostic) { $cleanupFailures.Add("diagnostic '$($harnessPath.Diagnostic)' still exists after cleanup") }
            else { $cleanupEvidence.diagnostic_removed = $true }
        }
        catch { $cleanupFailures.Add("diagnostic residual check failed: $($_.Exception.Message)") }
        try {
            if (Test-Path -LiteralPath $harnessPath.Ready) { $cleanupFailures.Add("ready file '$($harnessPath.Ready)' still exists after cleanup") }
            else { $cleanupEvidence.ready_removed = $true }
        }
        catch { $cleanupFailures.Add("ready-file residual check failed: $($_.Exception.Message)") }
        try {
            if (Test-Path -LiteralPath $harnessPath.Directory) { $cleanupFailures.Add("directory '$($harnessPath.Directory)' still exists after cleanup") }
            else { $cleanupEvidence.harness_directory_removed = $true }
        }
        catch { $cleanupFailures.Add("directory residual check failed: $($_.Exception.Message)") }
    }
    $cleanupEvidence.failures = @($cleanupFailures)
    $cleanupEvidence.success = $cleanupFailures.Count -eq 0
    Write-Host ("Harness cleanup result: " + (([PSCustomObject]$cleanupEvidence) | ConvertTo-Json -Depth 8 -Compress))
    if (-not [string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
        try { Write-HarnessEvidence $EvidenceDirectory $safeHealth $safeReady ([PSCustomObject]$cleanupEvidence) $CommitSHA $RunID $RunAttempt $name $serviceSID }
        catch {
            $cleanupFailures.Add("harness evidence write failed: $($_.Exception.Message)")
            $cleanupEvidence.failures = @($cleanupFailures)
            $cleanupEvidence.success = $false
        }
    }
    if ($cleanupFailures.Count -gt 0) {
        Write-SafeHarnessFailureDiagnostics $scPath $name $harnessPath.Diagnostic
    }
    if ($null -ne $failure -and $cleanupFailures.Count -gt 0) {
        throw "Service SID harness failed: $($failure.Exception.Message); cleanup failed independently: $($cleanupFailures -join '; ')"
    }
    if ($null -ne $failure) { throw "Service SID harness failed: $($failure.Exception.Message)" }
    if ($cleanupFailures.Count -gt 0) {
        throw "Service SID harness cleanup failed: $($cleanupFailures -join '; ')"
    }
}

if (-not $RunServiceSIDHarness -and -not $RunGoHarness -and -not $RunPathSecurityTests -and -not $RunProvisioningSecurityTests -and -not $RunEvidenceFailureTests) {
    Write-Host "No harness selected. Use -RunServiceSIDHarness (administrator), -RunGoHarness, -RunPathSecurityTests, -RunProvisioningSecurityTests, and/or -RunEvidenceFailureTests."
}
