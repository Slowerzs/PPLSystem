use endian_codec::{DecodeLE, EncodeLE, PackedSize};

#[derive(Debug)]
#[allow(non_snake_case)]
#[repr(C, packed)]
pub struct BitmapHeader {
    pub Signature: u32,
    pub ValidDump: u32,
    padding: [u8; 0x18],
    pub FirstPage: u64,
    pub TotalPresentPages: u64,
    pub Pages: u64,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct LIST_ENTRY {
    pub Flink: usize,
    pub Blink: usize,
}


#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct PEB {
    pub Reserved1: [u8; 2],
    pub BeingDebugged: u8,
    pub Reserved2: [u8; 1],
    padding: u32,
    pub Reserved3: [usize; 2],
    pub Ldr: usize,
    pub ProcessParameters: usize,
    pub Reserved4: [usize; 3],
    pub AtlThunkSListPtr: usize,
    pub Reserved5: usize,
    pub Reserved6: u32,
    pub Reserved7: usize,
    pub Reserved8: u32,
    pub AtlThunkSListPtr32: u32,
    pub Reserved9: [usize; 45],
    pub Reserved10: [u8; 96],
    pub PostProcessInitRoutine: usize,
    pub Reserved11: [u8; 128],
    pub Reserved12: [usize; 1],
    pub SessionId: u32,
}


#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [u8; 8],
    pub Reserved2: [usize; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct _KPROCESS {
    fill1: [u8; 0x20],
    pub DirectoryTableBase: u64,
    fill2: [u8; 0x408],
}

/*
    [+0x000] Header           [Type: _DISPATCHER_HEADER]
    [+0x018] ProfileListHead  [Type: _LIST_ENTRY]
    [+0x028] DirectoryTableBase : 0x18a96e000 [Type: unsigned __int64]
    [+0x030] ThreadListHead   [Type: _LIST_ENTRY]
    [+0x040] ProcessLock      : 0x0 [Type: unsigned long]
    [+0x044] ProcessTimerDelay : 0x0 [Type: unsigned long]
    [+0x048] DeepFreezeStartTime : 0x0 [Type: unsigned __int64]
    [+0x050] Affinity         [Type: _KAFFINITY_EX]
    [+0x158] ReadyListHead    [Type: _LIST_ENTRY]
    [+0x168] SwapListEntry    [Type: _SINGLE_LIST_ENTRY]
    [+0x170] ActiveProcessors [Type: _KAFFINITY_EX]
    [+0x278 ( 0: 0)] AutoAlignment    : 0x0 [Type: unsigned long]
    [+0x278 ( 1: 1)] DisableBoost     : 0x0 [Type: unsigned long]
    [+0x278 ( 2: 2)] DisableQuantum   : 0x0 [Type: unsigned long]
    [+0x278 ( 3: 3)] DeepFreeze       : 0x0 [Type: unsigned long]
    [+0x278 ( 4: 4)] TimerVirtualization : 0x0 [Type: unsigned long]
    [+0x278 ( 5: 5)] CheckStackExtents : 0x1 [Type: unsigned long]
    [+0x278 ( 6: 6)] CacheIsolationEnabled : 0x0 [Type: unsigned long]
    [+0x278 (10: 7)] PpmPolicy        : 0x0 [Type: unsigned long]
    [+0x278 (11:11)] VaSpaceDeleted   : 0x0 [Type: unsigned long]
    [+0x278 (12:12)] MultiGroup       : 0x0 [Type: unsigned long]
    [+0x278 (31:13)] ReservedFlags    : 0x0 [Type: unsigned long]
    [+0x278] ProcessFlags     : 32 [Type: long]
    [+0x27c] ActiveGroupsMask : 0x1 [Type: unsigned long]
    [+0x280] BasePriority     : 8 [Type: char]
    [+0x281] QuantumReset     : 6 [Type: char]
    [+0x282] Visited          : 0 [Type: char]
    [+0x283] Flags            [Type: _KEXECUTE_OPTIONS]
    [+0x284] ThreadSeed       [Type: unsigned short [32]]
    [+0x2c4] IdealProcessor   [Type: unsigned short [32]]
    [+0x304] IdealNode        [Type: unsigned short [32]]
    [+0x344] IdealGlobalNode  : 0x0 [Type: unsigned short]
    [+0x346] Spare1           : 0x0 [Type: unsigned short]
    [+0x348] StackCount       [Type: _KSTACK_COUNT]
    [+0x350] ProcessListEntry [Type: _LIST_ENTRY]
    [+0x360] CycleTime        : 0x20ab0b7 [Type: unsigned __int64]
    [+0x368] ContextSwitches  : 0x26 [Type: unsigned __int64]
    [+0x370] SchedulingGroup  : 0x0 [Type: _KSCHEDULING_GROUP *]
    [+0x378] FreezeCount      : 0x0 [Type: unsigned long]
    [+0x37c] KernelTime       : 0x2 [Type: unsigned long]
    [+0x380] UserTime         : 0x0 [Type: unsigned long]
    [+0x384] ReadyTime        : 0x6 [Type: unsigned long]
    [+0x388] UserDirectoryTableBase : 0x0 [Type: unsigned __int64]
    [+0x390] AddressPolicy    : 0x0 [Type: unsigned char]
    [+0x391] Spare2           [Type: unsigned char [71]]
    [+0x3d8] InstrumentationCallback : 0x0 [Type: void *]
    [+0x3e0] SecureState      [Type: <unnamed-tag>]
    [+0x3e8] KernelWaitTime   : 0x0 [Type: unsigned __int64]
    [+0x3f0] UserWaitTime     : 0x3eaa [Type: unsigned __int64]
    [+0x3f8] LastRebalanceQpc : 0x649d1088 [Type: unsigned __int64]
    [+0x400] PerProcessorCycleTimes : 0x9340 [Type: void *]
    [+0x408] ExtendedFeatureDisableMask : 0x0 [Type: unsigned __int64]
    [+0x410] PrimaryGroup     : 0x0 [Type: unsigned short]
    [+0x412] Spare3           [Type: unsigned short [3]]
    [+0x418] UserCetLogging   : 0x0 [Type: void *]
    [+0x420] CpuPartitionList [Type: _LIST_ENTRY]
    [+0x430] EndPadding       [Type: unsigned __int64 [1]]

*/

#[derive(Debug, PackedSize, EncodeLE, DecodeLE, Clone, Copy)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct _EPROCESS {
    pub pcb: _KPROCESS,
    ProcessLock: u64,
    pub UniqueProcessId: u64,
    pub ActiveProcessLinks: LIST_ENTRY,
    RundownProtect: [u8; 0x18],
    anonymous_union: u32,
    anonymous_union2: u32,
    CreateTime: u64,
    ProcessQuotaUsage: u64,
    ProcessQuotaPeak: u64,
    PeakVirtualSize: u64,
    VirtualSize: u64,
    SessionProcessLinks: LIST_ENTRY,
    anonymous_union3: u64,
    Token: usize,
    MmReserved: u64,
    AddressCreationLock: u64,
    PageTableCommitmentLock: u64,
    RotateInProgress: u64,
    ForkInProgress: u64,
    CommitChargeJob: u64,
    CloneRoot: usize,
    NumberOfPrivatePages: u64,
    NumberOfLockedPages: u64,
    Win32Process: u64,
    Job: u64,
    SectionObject: u64,
    SectionBaseAddress: u64,
    Cookie: u64,
    WorkingSetWatch: u64,
    Win32WindowStation: u64,
    InheritedFromUniqueProcessId: u64,
    OwnerProcessId: u64,
    pub Peb: usize,
    Session: usize,
    Spare1: usize,
    QuotaBlock: usize,
    ObjectTable: usize,
    DebugPort: usize,
    WoW64Process: usize,
    DeviceMap: usize,
    EtwDataSource: usize,
    PageDirectoryPte: usize,
    ImageFilePointer: usize,
    pub ImageFileName: [u8; 15],
}

/*
   +0x000 Pcb              : _KPROCESS
   +0x438 ProcessLock      : _EX_PUSH_LOCK
   +0x440 UniqueProcessId  : 0x00000000`0000006c Void
   +0x448 ActiveProcessLinks : _LIST_ENTRY [ 0xffff800c`04c53488 - 0xffff800c`03eea488 ]
   +0x458 RundownProtect   : _EX_RUNDOWN_REF
   +0x460 Flags2           : 0xd000
   +0x460 JobNotReallyActive : 0y0
   +0x460 AccountingFolded : 0y0
   +0x460 NewProcessReported : 0y0
   +0x460 ExitProcessReported : 0y0
   +0x460 ReportCommitChanges : 0y0
   +0x460 LastReportMemory : 0y0
   +0x460 ForceWakeCharge  : 0y0
   +0x460 CrossSessionCreate : 0y0
   +0x460 NeedsHandleRundown : 0y0
   +0x460 RefTraceEnabled  : 0y0
   +0x460 PicoCreated      : 0y0
   +0x460 EmptyJobEvaluated : 0y0
   +0x460 DefaultPagePriority : 0y101
   +0x460 PrimaryTokenFrozen : 0y1
   +0x460 ProcessVerifierTarget : 0y0
   +0x460 RestrictSetThreadContext : 0y0
   +0x460 AffinityPermanent : 0y0
   +0x460 AffinityUpdateEnable : 0y0
   +0x460 PropagateNode    : 0y0
   +0x460 ExplicitAffinity : 0y0
   +0x460 ProcessExecutionState : 0y00
   +0x460 EnableReadVmLogging : 0y0
   +0x460 EnableWriteVmLogging : 0y0
   +0x460 FatalAccessTerminationRequested : 0y0
   +0x460 DisableSystemAllowedCpuSet : 0y0
   +0x460 ProcessStateChangeRequest : 0y00
   +0x460 ProcessStateChangeInProgress : 0y0
   +0x460 InPrivate        : 0y0
   +0x464 Flags            : 0x14440c01
   +0x464 CreateReported   : 0y1
   +0x464 NoDebugInherit   : 0y0
   +0x464 ProcessExiting   : 0y0
   +0x464 ProcessDelete    : 0y0
   +0x464 ManageExecutableMemoryWrites : 0y0
   +0x464 VmDeleted        : 0y0
   +0x464 OutswapEnabled   : 0y0
   +0x464 Outswapped       : 0y0
   +0x464 FailFastOnCommitFail : 0y0
   +0x464 Wow64VaSpace4Gb  : 0y0
   +0x464 AddressSpaceInitialized : 0y11
   +0x464 SetTimerResolution : 0y0
   +0x464 BreakOnTermination : 0y0
   +0x464 DeprioritizeViews : 0y0
   +0x464 WriteWatch       : 0y0
   +0x464 ProcessInSession : 0y0
   +0x464 OverrideAddressSpace : 0y0
   +0x464 HasAddressSpace  : 0y1
   +0x464 LaunchPrefetched : 0y0
   +0x464 Reserved         : 0y0
   +0x464 VmTopDown        : 0y0
   +0x464 ImageNotifyDone  : 0y1
   +0x464 PdeUpdateNeeded  : 0y0
   +0x464 VdmAllowed       : 0y0
   +0x464 ProcessRundown   : 0y0
   +0x464 ProcessInserted  : 0y1
   +0x464 DefaultIoPriority : 0y010
   +0x464 ProcessSelfDelete : 0y0
   +0x464 SetTimerResolutionLink : 0y0
   +0x468 CreateTime       : _LARGE_INTEGER 0x01da6066`9f4d0373
   +0x470 ProcessQuotaUsage : [2] 0x2970
   +0x480 ProcessQuotaPeak : [2] 0x2970
   +0x490 PeakVirtualSize  : 0x5b0c000
   +0x498 VirtualSize      : 0x5b0c000
   +0x4a0 SessionProcessLinks : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0x4b0 ExceptionPortData : (null)
   +0x4b0 ExceptionPortValue : 0
   +0x4b0 ExceptionPortState : 0y000
   +0x4b8 Token            : _EX_FAST_REF
   +0x4c0 MmReserved       : 0
   +0x4c8 AddressCreationLock : _EX_PUSH_LOCK
   +0x4d0 PageTableCommitmentLock : _EX_PUSH_LOCK
   +0x4d8 RotateInProgress : (null)
   +0x4e0 ForkInProgress   : (null)
   +0x4e8 CommitChargeJob  : (null)
   +0x4f0 CloneRoot        : _RTL_AVL_TREE
   +0x4f8 NumberOfPrivatePages : 0x982
   +0x500 NumberOfLockedPages : 0
   +0x508 Win32Process     : (null)
   +0x510 Job              : (null)
   +0x518 SectionObject    : (null)
   +0x520 SectionBaseAddress : (null)
   +0x528 Cookie           : 0
   +0x530 WorkingSetWatch  : (null)
   +0x538 Win32WindowStation : (null)
   +0x540 InheritedFromUniqueProcessId : 0x00000000`00000004 Void
   +0x548 OwnerProcessId   : 6
   +0x550 Peb              : (null)
   +0x558 Session          : (null)
   +0x560 Spare1           : (null)
   +0x568 QuotaBlock       : 0xfffff803`4e86acc0 _EPROCESS_QUOTA_BLOCK
   +0x570 ObjectTable      : 0xffffbf8c`1da8b240 _HANDLE_TABLE
   +0x578 DebugPort        : (null)
   +0x580 WoW64Process     : (null)
   +0x588 DeviceMap        : _EX_FAST_REF
   +0x590 EtwDataSource    : (null)
   +0x598 PageDirectoryPte : 0
   +0x5a0 ImageFilePointer : (null)
   +0x5a8 ImageFileName    : [15]  "Registry"
   +0x5b7 PriorityClass    : 0x2 ''
   +0x5b8 SecurityPort     : (null)
   +0x5c0 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x5c8 JobLinks         : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0x5d8 HighestUserAddress : 0x00007fff`ffff0000 Void
   +0x5e0 ThreadListHead   : _LIST_ENTRY [ 0xffff800c`03f295b8 - 0xffff800c`08be65f8 ]
   +0x5f0 ActiveThreads    : 4
   +0x5f4 ImagePathHash    : 0
   +0x5f8 DefaultHardErrorProcessing : 5
   +0x5fc LastThreadExitStatus : 0n0
   +0x600 PrefetchTrace    : _EX_FAST_REF
   +0x608 LockedPagesList  : (null)
   +0x610 ReadOperationCount : _LARGE_INTEGER 0x4
   +0x618 WriteOperationCount : _LARGE_INTEGER 0x0
   +0x620 OtherOperationCount : _LARGE_INTEGER 0x8a
   +0x628 ReadTransferCount : _LARGE_INTEGER 0x800
   +0x630 WriteTransferCount : _LARGE_INTEGER 0x0
   +0x638 OtherTransferCount : _LARGE_INTEGER 0xef3
   +0x640 CommitChargeLimit : 0
   +0x648 CommitCharge     : 0x988
   +0x650 CommitChargePeak : 0xacf
   +0x680 Vm               : _MMSUPPORT_FULL
   +0x7c0 MmProcessLinks   : _LIST_ENTRY [ 0xffff800c`04c53800 - 0xffff800c`03eea800 ]
   +0x7d0 ModifiedPageCount : 0x252f
   +0x7d4 ExitStatus       : 0n259
   +0x7d8 VadRoot          : _RTL_AVL_TREE
   +0x7e0 VadHint          : 0xffff800c`089b4880 Void
   +0x7e8 VadCount         : 0x4e
   +0x7f0 VadPhysicalPages : 0
   +0x7f8 VadPhysicalPagesLimit : 0
   +0x800 AlpcContext      : _ALPC_PROCESS_CONTEXT
   +0x820 TimerResolutionLink : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0x830 TimerResolutionStackRecord : (null)
   +0x838 RequestedTimerResolution : 0
   +0x83c SmallestTimerResolution : 0
   +0x840 ExitTime         : _LARGE_INTEGER 0x0
   +0x848 InvertedFunctionTable : (null)
   +0x850 InvertedFunctionTableLock : _EX_PUSH_LOCK
   +0x858 ActiveThreadsHighWatermark : 0xb
   +0x85c LargePrivateVadCount : 0
   +0x860 ThreadListLock   : _EX_PUSH_LOCK
   +0x868 WnfContext       : (null)
   +0x870 ServerSilo       : (null)
   +0x878 SignatureLevel   : 0 ''
   +0x879 SectionSignatureLevel : 0 ''
   +0x87a Protection       : _PS_PROTECTION
   +0x87b HangCount        : 0y000
   +0x87b GhostCount       : 0y000
   +0x87b PrefilterException : 0y0
   +0x87c Flags3           : 0x404001
   +0x87c Minimal          : 0y1
   +0x87c ReplacingPageRoot : 0y0
   +0x87c Crashed          : 0y0
   +0x87c JobVadsAreTracked : 0y0
   +0x87c VadTrackingDisabled : 0y0
   +0x87c AuxiliaryProcess : 0y0
   +0x87c SubsystemProcess : 0y0
   +0x87c IndirectCpuSets  : 0y0
   +0x87c RelinquishedCommit : 0y0
   +0x87c HighGraphicsPriority : 0y0
   +0x87c CommitFailLogged : 0y0
   +0x87c ReserveFailLogged : 0y0
   +0x87c SystemProcess    : 0y0
   +0x87c HideImageBaseAddresses : 0y0
   +0x87c AddressPolicyFrozen : 0y1
   +0x87c ProcessFirstResume : 0y0
   +0x87c ForegroundExternal : 0y0
   +0x87c ForegroundSystem : 0y0
   +0x87c HighMemoryPriority : 0y0
   +0x87c EnableProcessSuspendResumeLogging : 0y0
   +0x87c EnableThreadSuspendResumeLogging : 0y0
   +0x87c SecurityDomainChanged : 0y0
   +0x87c SecurityFreezeComplete : 0y1
   +0x87c VmProcessorHost  : 0y0
   +0x87c VmProcessorHostTransition : 0y0
   +0x87c AltSyscall       : 0y0
   +0x87c TimerResolutionIgnore : 0y0
   +0x87c DisallowUserTerminate : 0y0
   +0x87c EnableProcessRemoteExecProtectVmLogging : 0y0
   +0x87c EnableProcessLocalExecProtectVmLogging : 0y0
   +0x87c MemoryCompressionProcess : 0y0
   +0x880 DeviceAsid       : 0n0
   +0x888 SvmData          : (null)
   +0x890 SvmProcessLock   : _EX_PUSH_LOCK
   +0x898 SvmLock          : 0
   +0x8a0 SvmProcessDeviceListHead : _LIST_ENTRY [ 0xffff800c`03f25920 - 0xffff800c`03f25920 ]
   +0x8b0 LastFreezeInterruptTime : 0
   +0x8b8 DiskCounters     : 0xffff800c`03f25c00 _PROCESS_DISK_COUNTERS
   +0x8c0 PicoContext      : (null)
   +0x8c8 EnclaveTable     : (null)
   +0x8d0 EnclaveNumber    : 0
   +0x8d8 EnclaveLock      : _EX_PUSH_LOCK
   +0x8e0 HighPriorityFaultsAllowed : 0
   +0x8e8 EnergyContext    : 0xffff800c`03f25c28 _PO_PROCESS_ENERGY_CONTEXT
   +0x8f0 VmContext        : (null)
   +0x8f8 SequenceNumber   : 2
   +0x900 CreateInterruptTime : 0x6d2823
   +0x908 CreateUnbiasedInterruptTime : 0x6d2823
   +0x910 TotalUnbiasedFrozenTime : 0
   +0x918 LastAppStateUpdateTime : 0x6d2823
   +0x920 LastAppStateUptime : 0y0000000000000000000000000000000000000000000000000000000000000 (0)
   +0x920 LastAppState     : 0y000
   +0x928 SharedCommitCharge : 0
   +0x930 SharedCommitLock : _EX_PUSH_LOCK
   +0x938 SharedCommitLinks : _LIST_ENTRY [ 0xffff800c`03f259b8 - 0xffff800c`03f259b8 ]
   +0x948 AllowedCpuSets   : 0
   +0x950 DefaultCpuSets   : 0
   +0x948 AllowedCpuSetsIndirect : (null)
   +0x950 DefaultCpuSetsIndirect : (null)
   +0x958 DiskIoAttribution : (null)
   +0x960 DxgProcess       : (null)
   +0x968 Win32KFilterSet  : 0
   +0x96c Machine          : 0x8664
   +0x96e Spare0           : 0
   +0x970 ProcessTimerDelay : _PS_INTERLOCKED_TIMER_DELAY_VALUES
   +0x978 KTimerSets       : 0
   +0x97c KTimer2Sets      : 0
   +0x980 ThreadTimerSets  : 0
   +0x988 VirtualTimerListLock : 0
   +0x990 VirtualTimerListHead : _LIST_ENTRY [ 0xffff800c`03f25a10 - 0xffff800c`03f25a10 ]
   +0x9a0 WakeChannel      : _WNF_STATE_NAME
   +0x9a0 WakeInfo         : _PS_PROCESS_WAKE_INFORMATION
   +0x9d0 MitigationFlags  : 0x20
   +0x9d0 MitigationFlagsValues : <unnamed-tag>
   +0x9d4 MitigationFlags2 : 0x40000000
   +0x9d4 MitigationFlags2Values : <unnamed-tag>
   +0x9d8 PartitionObject  : 0xffff800c`03ec1af0 Void
   +0x9e0 SecurityDomain   : 0x00000001`00000001
   +0x9e8 ParentSecurityDomain : 0
   +0x9f0 CoverageSamplerContext : (null)
   +0x9f8 MmHotPatchContext : (null)
   +0xa00 IdealProcessorAssignmentBlock : _KE_IDEAL_PROCESSOR_ASSIGNMENT_BLOCK
   +0xb18 DynamicEHContinuationTargetsTree : _RTL_AVL_TREE
   +0xb20 DynamicEHContinuationTargetsLock : _EX_PUSH_LOCK
   +0xb28 DynamicEnforcedCetCompatibleRanges : _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
   +0xb38 DisabledComponentFlags : 0
   +0xb3c PageCombineSequence : 0n1
   +0xb40 EnableOptionalXStateFeaturesLock : _EX_PUSH_LOCK
   +0xb48 PathRedirectionHashes : (null)
   +0xb50 SyscallProvider  : (null)
   +0xb58 SyscallProviderProcessLinks : _LIST_ENTRY [ 0x00000000`00000000 - 0x00000000`00000000 ]
   +0xb68 SyscallProviderDispatchContext : _PSP_SYSCALL_PROVIDER_DISPATCH_CONTEXT
   +0xb70 MitigationFlags3 : 0
   +0xb70 MitigationFlags3Values : <unnamed-tag>

*/
