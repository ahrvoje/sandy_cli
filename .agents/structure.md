# Sandy CLI - Method Call Structure

Every function defined in `src/`, classified by Sandy call depth.
Only references to Sandy functions defined inside `src/` are counted; external/system APIs and third-party code are excluded.

**Level definition:**
- **Level 1** - calls only external/system APIs (Win32, CRT, STL, toml11), no Sandy methods
- **Level N** - references at least one Sandy method from Level 1-(N-1) and no higher level
- Callback and thread-proc references are counted as Sandy call edges when a Sandy function is passed by name

Format: `File > Method` or `File > Method(params)` for overloads - Sandy refs: `File > Method`

---

## Level 1 - 72 methods

### Sandbox.h
- `Sandbox.h > ResetEmergencyCleanupState` - leaf method
- `Sandbox.h > ConfigureEmergencyCleanupState` - leaf method
- `Sandbox.h > SnapshotEmergencyCleanupState` - leaf method

### SandboxACL.h
- `SandboxACL.h > AceRemovalResult::Succeeded` - leaf method
- `SandboxACL.h > AclMutexGuard::~AclMutexGuard` - leaf method
- `SandboxACL.h > RegistryToWin32Path` - leaf method
- `SandboxACL.h > AccessMask` - leaf method
- `SandboxACL.h > RegistryAccessMask` - leaf method
- `SandboxACL.h > IsMissingSecurityTargetError` - leaf method

### SandboxCLI.h
- `SandboxCLI.h > PrintUsage` - leaf method
- `SandboxCLI.h > PrintContainerToml` - leaf method
- `SandboxCLI.h > PrintRestrictedToml` - leaf method
- `SandboxCLI.h > QuoteArg` - leaf method

### SandboxCapabilities.h
- `SandboxCapabilities.h > FreeCapabilities` - leaf method
- `SandboxCapabilities.h > FreeAttributeList` - leaf method

### SandboxCleanup.h
- `SandboxCleanup.h > CleanupTaskName` - leaf method
- `SandboxCleanup.h > EnumSandyProfiles` - leaf method

### SandboxConfig.h
- `SandboxConfig.h > GetInheritedWorkdir` - leaf method

### SandboxDryRun.h
- `SandboxDryRun.h > TomlQuotedValue` - leaf method

### SandboxEnvironment.h
- `SandboxEnvironment.h > BuildEnvironmentBlock` - leaf method

### SandboxGrants.h
- `SandboxGrants.h > ResetGrantTrackingHealth` - leaf method
- `SandboxGrants.h > GrantTrackingHealthy` - leaf method
- `SandboxGrants.h > ResetGrantMetadataPreservation` - leaf method
- `SandboxGrants.h > ResetDeferredCleanupRequest` - leaf method
- `SandboxGrants.h > PreserveGrantMetadataRequested` - leaf method
- `SandboxGrants.h > DeferredCleanupRequested` - leaf method
- `SandboxGrants.h > EndStagingGrantCapture` - leaf method
- `SandboxGrants.h > AbortStagingGrantCapture` - leaf method
- `SandboxGrants.h > ValidateSidPrefix` - leaf method
- `SandboxGrants.h > GetCurrentProcessCreationTime` - leaf method
- `SandboxGrants.h > IsProcessAlive` - leaf method
- `SandboxGrants.h > ReadPidAndCtime` - leaf method

### SandboxGuard.h
- `SandboxGuard.h > SandboxGuard::Add` - leaf method
- `SandboxGuard.h > SandboxGuard::RunAll` - leaf method

### SandboxProcess.h
- `SandboxProcess.h > CloseHandleIfValid` - leaf method
- `SandboxProcess.h > GetSystemDirectoryPath` - leaf method
- `SandboxProcess.h > DrainHiddenProcessPipe` - leaf method
- `SandboxProcess.h > TimeoutThread` - leaf method
- `SandboxProcess.h > NeedJobTracking` - leaf method
- `SandboxProcess.h > WaitForJobTreeExit` - leaf method

### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > RecoveryLedgerPresence::Any` - leaf method
- `SandboxRecoveryLedger.h > GetRecoveryLedgerKey` - leaf method

### SandboxRegistry.h
- `SandboxRegistry.h > WriteRegSz` - leaf method
- `SandboxRegistry.h > TryWriteRegSz` - leaf method
- `SandboxRegistry.h > ReadRegSz` - leaf method
- `SandboxRegistry.h > WriteRegDword` - leaf method
- `SandboxRegistry.h > TryWriteRegDword` - leaf method
- `SandboxRegistry.h > TryWriteRegQword` - leaf method
- `SandboxRegistry.h > ReadRegDword` - leaf method
- `SandboxRegistry.h > ReadRegSzEnum` - leaf method
- `SandboxRegistry.h > DeleteRegTreeBestEffort` - leaf method

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > ReadStagingPidAndCtime` - leaf method
- `SandboxSavedProfile.h > ReadTomlFileText` - leaf method
- `SandboxSavedProfile.h > ProfileExists` - leaf method

### SandboxStatus.h
- `SandboxStatus.h > HandleExplain` - leaf method

### SandboxTypes.h
- `SandboxTypes.h > GenerateInstanceId` - leaf method
- `SandboxTypes.h > ContainerNameFromId` - leaf method
- `SandboxTypes.h > NormalizeFsPath` - leaf method
- `SandboxTypes.h > NormalizeLookupKey` - leaf method
- `SandboxTypes.h > IsCrashExitCode` - leaf method
- `SandboxTypes.h > AppContainerMissing` - leaf method
- `SandboxTypes.h > AccessTag` - leaf method
- `SandboxTypes.h > AccessLevelName` - leaf method
- `SandboxTypes.h > ParseAccessTag` - leaf method
- `SandboxTypes.h > AllocateInstanceSid` - leaf method
- `SandboxTypes.h > GetSystemErrorMessage` - leaf method
- `SandboxTypes.h > SandyLogger::Timestamp` - leaf method
- `SandboxTypes.h > SandyLogger::IsActive` - leaf method

### TomlAdapter.h
- `TomlAdapter.h > ParseResult::ok` - leaf method
- `TomlAdapter.h > Utf8ToWide` - leaf method
- `TomlAdapter.h > WideToUtf8` - leaf method
- `TomlAdapter.h > ConvertLiteralNewlines` - leaf method

## Level 2 - 25 methods

### Sandbox.h
- `Sandbox.h > PathDepth` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`
- `Sandbox.h > IsPathUnder` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`

### SandboxCLI.h
- `SandboxCLI.h > CollectArgs` - Sandy refs: `SandboxCLI.h > QuoteArg`

### SandboxDryRun.h
- `SandboxDryRun.h > PrintFolderEntries` - Sandy refs: `SandboxTypes.h > AccessLevelName`
- `SandboxDryRun.h > PrintFolderToml` - Sandy refs: `SandboxDryRun.h > TomlQuotedValue`, `SandboxTypes.h > AccessLevelName`

### SandboxEnvironment.h
- `SandboxEnvironment.h > PrintConfigSummary` - Sandy refs: `SandboxTypes.h > AccessTag`

### SandboxGrants.h
- `SandboxGrants.h > BeginStagingGrantCapture` - Sandy refs: `SandboxGrants.h > ResetGrantTrackingHealth`
- `SandboxGrants.h > ParseGrantRecord` - Sandy refs: `SandboxGrants.h > ValidateSidPrefix`, `SandboxTypes.h > NormalizeFsPath`
- `SandboxGrants.h > SnapshotGrantLedgers` - Sandy refs: `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > ReadPidAndCtime`, `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`, `SandboxRegistry.h > ReadRegSz`
- `SandboxGrants.h > GetSavedProfileContainerNames` - Sandy refs: `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > NormalizeLookupKey`

### SandboxGuard.h
- `SandboxGuard.h > SandboxGuard::~SandboxGuard` - Sandy refs: `SandboxGuard.h > SandboxGuard::RunAll`

### SandboxProcess.h
- `SandboxProcess.h > AbortLaunchedChild` - Sandy refs: `SandboxProcess.h > CloseHandleIfValid`, `SandboxProcess.h > WaitForJobTreeExit`
- `SandboxProcess.h > ReleaseLaunchedChildHandles` - Sandy refs: `SandboxProcess.h > CloseHandleIfValid`

### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > GetGrantsRegKey` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`
- `SandboxRecoveryLedger.h > GetTransientContainerRegKey` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`
- `SandboxRecoveryLedger.h > RecoveryLedgerExists` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`

### SandboxRegistry.h
- `SandboxRegistry.h > DeleteRegTreeIfExists` - Sandy refs: `SandboxRegistry.h > DeleteRegTreeBestEffort`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > WriteConfigToRegistry` - Sandy refs: `SandboxRegistry.h > TryWriteRegSz`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxTypes.h > AccessLevelName`
- `SandboxSavedProfile.h > EnumSavedProfiles` - Sandy refs: `SandboxRegistry.h > ReadRegSz`

### SandboxTypes.h
- `SandboxTypes.h > SandyLogger::Start` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::Stop` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::LogConfig` - Sandy refs: `SandboxTypes.h > AccessTag`, `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::Log` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::LogSummary` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`

### TomlAdapter.h
- `TomlAdapter.h > FlattenTable` - Sandy refs: `TomlAdapter.h > Utf8ToWide`

## Level 3 - 14 methods

### SandboxCapabilities.h
- `SandboxCapabilities.h > BuildAttributeList` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`

### SandboxDryRun.h
- `SandboxDryRun.h > HandleDryRun` - Sandy refs: `SandboxDryRun.h > PrintFolderEntries`
- `SandboxDryRun.h > HandlePrintConfig` - Sandy refs: `SandboxDryRun.h > TomlQuotedValue`, `SandboxDryRun.h > PrintFolderToml`

### SandboxEnvironment.h
- `SandboxEnvironment.h > LogEnvironmentState` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`
- `SandboxEnvironment.h > LogStdinMode` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`

### SandboxGrants.h
- `SandboxGrants.h > SnapshotTransientContainerLedgers` - Sandy refs: `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > ReadPidAndCtime`, `SandboxRecoveryLedger.h > GetTransientContainerRegKey`, `SandboxRegistry.h > ReadRegSz`
- `SandboxGrants.h > ClearPersistedGrants` - Sandy refs: `SandboxRecoveryLedger.h > GetGrantsRegKey`, `SandboxRegistry.h > DeleteRegTreeBestEffort`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxGrants.h > GetLiveContainerNames` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxTypes.h > NormalizeLookupKey`
- `SandboxGrants.h > GetLiveProfileNames` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxTypes.h > NormalizeLookupKey`

### SandboxProcess.h
- `SandboxProcess.h > SetupStdinHandle` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`

### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > QueryRecoveryLedgerPresence` - Sandy refs: `SandboxRecoveryLedger.h > RecoveryLedgerExists`

### SandboxTypes.h
- `SandboxTypes.h > SandyLogger::LogFmt` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`
- `SandboxTypes.h > SandyLogger::~SandyLogger` - Sandy refs: `SandboxTypes.h > SandyLogger::Stop`

### TomlAdapter.h
- `TomlAdapter.h > ParseUtf8` - Sandy refs: `TomlAdapter.h > Utf8ToWide`, `TomlAdapter.h > FlattenTable`

## Level 4 - 30 methods

### Sandbox.h
- `Sandbox.h > SetupAppContainer` - Sandy refs: `SandboxGuard.h > SandboxGuard::Add`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxACL.h
- `SandboxACL.h > AclMutexGuard::Acquire` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > TreeSecurityProgress` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > RollbackAceBySid` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > RemoveSidFromDaclDetailed` - Sandy refs: `SandboxACL.h > IsMissingSecurityTargetError`, `SandboxTypes.h > GetSystemErrorMessage`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxCapabilities.h
- `SandboxCapabilities.h > BuildCapabilities` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxCleanup.h
- `SandboxCleanup.h > HasOtherLiveContainerUsers` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxCleanup.h > WarnStaleRegistryEntries` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxGrants.h > SnapshotTransientContainerLedgers`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > SandyLogger::IsActive`
- `SandboxCleanup.h > LogSandyIdentity` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxConfig.h
- `SandboxConfig.h > MapConfig` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > SandyLogger::IsActive`, `TomlAdapter.h > ParseResult::ok`

### SandboxGrants.h
- `SandboxGrants.h > MarkGrantTrackingFailure` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RequestGrantMetadataPreservation` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RequestDeferredCleanup` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > HardenRegistryKeyAgainstRestricted` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > ClearTransientContainerCleanup` - Sandy refs: `SandboxRecoveryLedger.h > GetTransientContainerRegKey`, `SandboxRegistry.h > DeleteRegTreeBestEffort`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > FindTransientContainerCleanupInstanceIds` - Sandy refs: `SandboxGrants.h > SnapshotTransientContainerLedgers`, `SandboxTypes.h > NormalizeLookupKey`
- `SandboxGrants.h > DeleteTransientContainerNow` - Sandy refs: `SandboxTypes.h > AppContainerMissing`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > ClearLiveState` - Sandy refs: `SandboxGrants.h > ClearPersistedGrants`

### SandboxProcess.h
- `SandboxProcess.h > RunHiddenProcessDetailed` - Sandy refs: `SandboxProcess.h > DrainHiddenProcessPipe`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > LaunchChildProcess` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > AssignJobObject` - Sandy refs: `SandboxProcess.h > NeedJobTracking`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > WaitForChildExit` - Sandy refs: `SandboxProcess.h > WaitForJobTreeExit`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > StartTimeoutWatchdog` - Sandy refs: `SandboxProcess.h > TimeoutThread`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > ShouldRetainCleanupTask` - Sandy refs: `SandboxRecoveryLedger.h > RecoveryLedgerPresence::Any`, `SandboxRecoveryLedger.h > QueryRecoveryLedgerPresence`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > DeleteProfileRegistryState` - Sandy refs: `SandboxRegistry.h > DeleteRegTreeBestEffort`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxSavedProfile.h > ReadConfigFromRegistry` - Sandy refs: `SandboxRegistry.h > ReadRegSz`, `SandboxRegistry.h > ReadRegDword`, `SandboxTypes.h > NormalizeFsPath`, `SandboxTypes.h > ParseAccessTag`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxToken.h
- `SandboxToken.h > CreateRestrictedSandboxToken` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxToken.h > BuildAclWithoutSidAces` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxToken.h > GrantDesktopAccess` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`

### TomlAdapter.h
- `TomlAdapter.h > Parse` - Sandy refs: `TomlAdapter.h > WideToUtf8`, `TomlAdapter.h > ConvertLiteralNewlines`, `TomlAdapter.h > ParseUtf8`

## Level 5 - 20 methods

### Sandbox.h
- `Sandbox.h > SetupRestrictedToken` - Sandy refs: `SandboxGuard.h > SandboxGuard::Add`, `SandboxToken.h > CreateRestrictedSandboxToken`, `SandboxTypes.h > AllocateInstanceSid`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxACL.h
- `SandboxACL.h > AclMutexGuard::AclMutexGuard(const std::wstring&)` - Sandy refs: `SandboxACL.h > AclMutexGuard::Acquire`
- `SandboxACL.h > AclMutexGuard::AclMutexGuard(const wchar_t*)` - Sandy refs: `SandboxACL.h > AclMutexGuard::Acquire`
- `SandboxACL.h > GrantObjectAccess` - Sandy refs: `SandboxACL.h > AccessMask`, `SandboxACL.h > RegistryAccessMask`, `SandboxACL.h > RollbackAceBySid`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > DenyObjectAccess` - Sandy refs: `SandboxACL.h > AccessMask`, `SandboxACL.h > RollbackAceBySid`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > RemoveSidFromDacl` - Sandy refs: `SandboxACL.h > RemoveSidFromDaclDetailed`

### SandboxConfig.h
- `SandboxConfig.h > ParseConfig` - Sandy refs: `SandboxConfig.h > MapConfig`, `TomlAdapter.h > Parse`
- `SandboxConfig.h > LoadConfig` - Sandy refs: `SandboxConfig.h > MapConfig`, `TomlAdapter.h > ParseUtf8`

### SandboxGrants.h
- `SandboxGrants.h > InitializeRunLedger` - Sandy refs: `SandboxGrants.h > MarkGrantTrackingFailure`, `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxRecoveryLedger.h > GetGrantsRegKey`
- `SandboxGrants.h > RecordGrant` - Sandy refs: `SandboxGrants.h > MarkGrantTrackingFailure`, `SandboxRecoveryLedger.h > GetGrantsRegKey`, `SandboxTypes.h > NormalizeFsPath`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > PersistTransientContainerCleanup` - Sandy refs: `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxRecoveryLedger.h > GetTransientContainerRegKey`, `SandboxRegistry.h > TryWriteRegSz`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxRegistry.h > TryWriteRegQword`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > ClearTransientContainerCleanupByContainerName` - Sandy refs: `SandboxGrants.h > ClearTransientContainerCleanup`, `SandboxGrants.h > FindTransientContainerCleanupInstanceIds`
- `SandboxGrants.h > RestoreTransientContainers` - Sandy refs: `SandboxGrants.h > SnapshotTransientContainerLedgers`, `SandboxGrants.h > ClearTransientContainerCleanup`, `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > PersistLiveState` - Sandy refs: `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxRecoveryLedger.h > GetGrantsRegKey`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RestoreGrantsFromKey` - Sandy refs: `SandboxACL.h > AceRemovalResult::Succeeded`, `SandboxACL.h > RemoveSidFromDaclDetailed`, `SandboxGrants.h > ParseGrantRecord`, `SandboxRegistry.h > ReadRegSzEnum`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxProcess.h
- `SandboxProcess.h > RunHiddenProcess` - Sandy refs: `SandboxProcess.h > RunHiddenProcessDetailed`
- `SandboxProcess.h > RunSchtasksCapture` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcessDetailed`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > LoadSavedProfile` - Sandy refs: `SandboxRegistry.h > ReadRegSz`, `SandboxSavedProfile.h > ReadConfigFromRegistry`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxToken.h
- `SandboxToken.h > RevokeDesktopAccess` - Sandy refs: `SandboxToken.h > BuildAclWithoutSidAces`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxToken.h > RevokeDesktopAccessForSid` - Sandy refs: `SandboxToken.h > BuildAclWithoutSidAces`, `SandboxTypes.h > SandyLogger::LogFmt`

## Level 6 - 13 methods

### Sandbox.h
- `Sandbox.h > RecordGrantCallback` - Sandy refs: `SandboxGrants.h > RecordGrant`

### SandboxCleanup.h
- `SandboxCleanup.h > ListCleanupTasks` - Sandy refs: `SandboxProcess.h > RunSchtasksCapture`
- `SandboxCleanup.h > AddLoopbackExemption` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`
- `SandboxCleanup.h > RemoveLoopbackExemption` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`
- `SandboxCleanup.h > ForceDisableLoopback(const std::wstring&)` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > ForceDisableLoopback(const std::vector<std::wstring>&)` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxDryRun.h
- `SandboxDryRun.h > HandleDryRunCreateProfile` - Sandy refs: `SandboxConfig.h > ParseConfig`, `SandboxSavedProfile.h > ReadTomlFileText`, `SandboxSavedProfile.h > ProfileExists`, `SandboxTypes.h > AccessTag`

### SandboxGrants.h
- `SandboxGrants.h > PersistTransientContainerCleanupForOrphanedContainer` - Sandy refs: `SandboxGrants.h > PersistTransientContainerCleanup`, `SandboxGrants.h > FindTransientContainerCleanupInstanceIds`
- `SandboxGrants.h > TeardownTransientContainerForCurrentRun` - Sandy refs: `SandboxGrants.h > RequestGrantMetadataPreservation`, `SandboxGrants.h > RequestDeferredCleanup`, `SandboxGrants.h > PersistTransientContainerCleanup`, `SandboxGrants.h > ClearTransientContainerCleanup`, `SandboxGrants.h > DeleteTransientContainerNow`
- `SandboxGrants.h > RevokeAllGrants` - Sandy refs: `SandboxACL.h > RemoveSidFromDacl`, `SandboxGrants.h > PreserveGrantMetadataRequested`, `SandboxGrants.h > ClearPersistedGrants`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RestoreStaleGrants` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxGrants.h > PersistTransientContainerCleanup`, `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > RestoreTransientContainers`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`, `SandboxRegistry.h > DeleteRegTreeBestEffort`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxProcess.h
- `SandboxProcess.h > RunSchtasks` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > HandleProfileInfo` - Sandy refs: `SandboxSavedProfile.h > LoadSavedProfile`, `SandboxTypes.h > AccessTag`

## Level 7 - 12 methods

### Sandbox.h
- `Sandbox.h > ApplyAccessPipeline` - Sandy refs: `Sandbox.h > RecordGrantCallback`, `Sandbox.h > PathDepth`, `Sandbox.h > IsPathUnder`, `SandboxACL.h > AccessMask`, `SandboxACL.h > GrantObjectAccess`, `SandboxACL.h > DenyObjectAccess`, `SandboxACL.h > RemoveSidFromDacl`, `SandboxTypes.h > AccessTag`, `SandboxTypes.h > GetSystemErrorMessage`, `SandboxTypes.h > SandyLogger::LogFmt`
- `Sandbox.h > GrantRegistryAccess` - Sandy refs: `Sandbox.h > RecordGrantCallback`, `SandboxACL.h > RegistryToWin32Path`, `SandboxACL.h > GrantObjectAccess`, `SandboxTypes.h > GetSystemErrorMessage`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxCleanup.h
- `SandboxCleanup.h > CreateCleanupTask` - Sandy refs: `SandboxCleanup.h > CleanupTaskName`, `SandboxProcess.h > RunSchtasks`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > DeleteCleanupTask` - Sandy refs: `SandboxCleanup.h > CleanupTaskName`, `SandboxProcess.h > RunSchtasks`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > DeleteStaleCleanupTasks` - Sandy refs: `SandboxCleanup.h > ListCleanupTasks`, `SandboxProcess.h > RunSchtasks`, `SandboxRecoveryLedger.h > RecoveryLedgerPresence::Any`, `SandboxRecoveryLedger.h > QueryRecoveryLedgerPresence`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > EnableRunLoopback` - Sandy refs: `SandboxCleanup.h > AddLoopbackExemption`
- `SandboxCleanup.h > EnsureProfileLoopback` - Sandy refs: `SandboxCleanup.h > AddLoopbackExemption`
- `SandboxCleanup.h > DisableLoopback` - Sandy refs: `SandboxCleanup.h > HasOtherLiveContainerUsers`, `SandboxCleanup.h > RemoveLoopbackExemption`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > DisableLoopbackForContainer` - Sandy refs: `SandboxCleanup.h > RemoveLoopbackExemption`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxCleanup.h > CleanupStaleStartupState` - Sandy refs: `SandboxCleanup.h > ForceDisableLoopback(const std::vector<std::wstring>&)`, `SandboxCleanup.h > EnumSandyProfiles`, `SandboxGrants.h > GetLiveContainerNames`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::Log`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > TeardownPersistentProfileContainer` - Sandy refs: `SandboxCleanup.h > RemoveLoopbackExemption`, `SandboxTypes.h > AppContainerMissing`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxStatus.h
- `SandboxStatus.h > HandleStatus` - Sandy refs: `SandboxCleanup.h > ListCleanupTasks`, `SandboxCleanup.h > EnumSandyProfiles`, `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxSavedProfile.h > EnumSavedProfiles`

## Level 8 - 4 methods

### SandboxCleanup.h
- `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun` - Sandy refs: `SandboxCleanup.h > CleanupTaskName`, `SandboxCleanup.h > DeleteCleanupTask`, `SandboxGrants.h > DeferredCleanupRequested`, `SandboxRecoveryLedger.h > ShouldRetainCleanupTask`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > HandleCreateProfile` - Sandy refs: `Sandbox.h > ApplyAccessPipeline`, `Sandbox.h > GrantRegistryAccess`, `SandboxCleanup.h > EnsureProfileLoopback`, `SandboxConfig.h > ParseConfig`, `SandboxGrants.h > GrantTrackingHealthy`, `SandboxGrants.h > BeginStagingGrantCapture`, `SandboxGrants.h > EndStagingGrantCapture`, `SandboxGrants.h > AbortStagingGrantCapture`, `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxRegistry.h > TryWriteRegSz`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxRegistry.h > TryWriteRegQword`, `SandboxSavedProfile.h > TeardownPersistentProfileContainer`, `SandboxSavedProfile.h > DeleteProfileRegistryState`, `SandboxSavedProfile.h > ReadTomlFileText`, `SandboxSavedProfile.h > WriteConfigToRegistry`, `SandboxToken.h > GrantDesktopAccess`, `SandboxToken.h > RevokeDesktopAccessForSid`, `SandboxTypes.h > AllocateInstanceSid`, `SandboxTypes.h > SandyLogger::Timestamp`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxSavedProfile.h > CleanStagingProfiles` - Sandy refs: `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxRegistry.h > ReadRegSz`, `SandboxRegistry.h > ReadRegDword`, `SandboxSavedProfile.h > TeardownPersistentProfileContainer`, `SandboxSavedProfile.h > DeleteProfileRegistryState`, `SandboxSavedProfile.h > ReadStagingPidAndCtime`, `SandboxToken.h > RevokeDesktopAccessForSid`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxSavedProfile.h > HandleDeleteProfile` - Sandy refs: `SandboxCleanup.h > DisableLoopbackForContainer`, `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > GetLiveContainerNames`, `SandboxGrants.h > GetLiveProfileNames`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxRegistry.h > ReadRegSz`, `SandboxRegistry.h > ReadRegDword`, `SandboxSavedProfile.h > TeardownPersistentProfileContainer`, `SandboxSavedProfile.h > DeleteProfileRegistryState`, `SandboxSavedProfile.h > ReadStagingPidAndCtime`, `SandboxToken.h > RevokeDesktopAccessForSid`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::LogFmt`

## Level 9 - 4 methods

### Sandbox.h
- `Sandbox.h > RunPipeline` - Sandy refs: `Sandbox.h > ApplyAccessPipeline`, `Sandbox.h > GrantRegistryAccess`, `Sandbox.h > SetupAppContainer`, `Sandbox.h > SetupRestrictedToken`, `Sandbox.h > ConfigureEmergencyCleanupState`, `SandboxCapabilities.h > BuildCapabilities`, `SandboxCapabilities.h > FreeCapabilities`, `SandboxCapabilities.h > BuildAttributeList`, `SandboxCapabilities.h > FreeAttributeList`, `SandboxCleanup.h > CreateCleanupTask`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `SandboxCleanup.h > EnableRunLoopback`, `SandboxCleanup.h > DisableLoopback`, `SandboxEnvironment.h > BuildEnvironmentBlock`, `SandboxEnvironment.h > LogEnvironmentState`, `SandboxEnvironment.h > LogStdinMode`, `SandboxEnvironment.h > PrintConfigSummary`, `SandboxGrants.h > ResetGrantTrackingHealth`, `SandboxGrants.h > GrantTrackingHealthy`, `SandboxGrants.h > InitializeRunLedger`, `SandboxGrants.h > TeardownTransientContainerForCurrentRun`, `SandboxGrants.h > RevokeAllGrants`, `SandboxGuard.h > SandboxGuard::Add`, `SandboxGuard.h > SandboxGuard::RunAll`, `SandboxProcess.h > CloseHandleIfValid`, `SandboxProcess.h > AbortLaunchedChild`, `SandboxProcess.h > ReleaseLaunchedChildHandles`, `SandboxProcess.h > SetupStdinHandle`, `SandboxProcess.h > LaunchChildProcess`, `SandboxProcess.h > NeedJobTracking`, `SandboxProcess.h > AssignJobObject`, `SandboxProcess.h > WaitForChildExit`, `SandboxProcess.h > StartTimeoutWatchdog`, `SandboxToken.h > GrantDesktopAccess`, `SandboxToken.h > RevokeDesktopAccess`, `SandboxTypes.h > IsCrashExitCode`, `SandboxTypes.h > SandyLogger::Stop`, `SandboxTypes.h > SandyLogger::LogConfig`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > SandyLogger::LogSummary`, `SandboxTypes.h > SandyLogger::IsActive`
- `Sandbox.h > BeginRunSession` - Sandy refs: `SandboxCleanup.h > DeleteStaleCleanupTasks`, `SandboxCleanup.h > CleanupStaleStartupState`, `SandboxCleanup.h > WarnStaleRegistryEntries`, `SandboxCleanup.h > LogSandyIdentity`, `SandboxGrants.h > ResetGrantMetadataPreservation`, `SandboxGrants.h > ResetDeferredCleanupRequest`, `SandboxGrants.h > RestoreStaleGrants`, `SandboxSavedProfile.h > CleanStagingProfiles`, `SandboxTypes.h > SandyLogger::Log`
- `Sandbox.h > CleanupSandbox` - Sandy refs: `Sandbox.h > ResetEmergencyCleanupState`, `Sandbox.h > SnapshotEmergencyCleanupState`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `SandboxCleanup.h > DisableLoopback`, `SandboxGrants.h > TeardownTransientContainerForCurrentRun`, `SandboxGrants.h > RevokeAllGrants`, `SandboxProcess.h > WaitForJobTreeExit`, `SandboxToken.h > RevokeDesktopAccess`, `SandboxTypes.h > SandyLogger::Stop`, `SandboxTypes.h > SandyLogger::Log`

### SandboxStatus.h
- `SandboxStatus.h > HandleCleanup` - Sandy refs: `SandboxCleanup.h > DeleteStaleCleanupTasks`, `SandboxCleanup.h > ForceDisableLoopback(const std::vector<std::wstring>&)`, `SandboxCleanup.h > EnumSandyProfiles`, `SandboxGrants.h > ClearTransientContainerCleanupByContainerName`, `SandboxGrants.h > PersistTransientContainerCleanupForOrphanedContainer`, `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > GetLiveContainerNames`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxGrants.h > RestoreStaleGrants`, `SandboxRegistry.h > DeleteRegTreeIfExists`, `SandboxSavedProfile.h > CleanStagingProfiles`, `SandboxTypes.h > NormalizeLookupKey`

## Level 10 - 3 methods

### Sandbox.h
- `Sandbox.h > RunSandboxed` - Sandy refs: `Sandbox.h > ResetEmergencyCleanupState`, `Sandbox.h > RunPipeline`, `Sandbox.h > BeginRunSession`, `SandboxConfig.h > GetInheritedWorkdir`, `SandboxTypes.h > GenerateInstanceId`, `SandboxTypes.h > ContainerNameFromId`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > RunWithProfile` - Sandy refs: `Sandbox.h > ResetEmergencyCleanupState`, `Sandbox.h > RunPipeline`, `Sandbox.h > BeginRunSession`, `SandboxCleanup.h > CreateCleanupTask`, `SandboxCleanup.h > DeleteCleanupTask`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `SandboxConfig.h > GetInheritedWorkdir`, `SandboxGrants.h > PersistLiveState`, `SandboxGrants.h > ClearLiveState`, `SandboxToken.h > CreateRestrictedSandboxToken`, `SandboxTypes.h > GenerateInstanceId`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### sandy.cpp
- `sandy.cpp > ConsoleCtrlHandler` - Sandy refs: `Sandbox.h > CleanupSandbox`, `SandboxTypes.h > SandyLogger::Stop`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

## Level 11 - 1 method

### sandy.cpp
- `sandy.cpp > RunMain` - Sandy refs: `Sandbox.h > RunSandboxed`, `SandboxCLI.h > PrintUsage`, `SandboxCLI.h > PrintContainerToml`, `SandboxCLI.h > PrintRestrictedToml`, `SandboxCLI.h > CollectArgs`, `SandboxConfig.h > ParseConfig`, `SandboxConfig.h > LoadConfig`, `SandboxDryRun.h > HandleDryRun`, `SandboxDryRun.h > HandleDryRunCreateProfile`, `SandboxDryRun.h > HandlePrintConfig`, `SandboxSavedProfile.h > HandleCreateProfile`, `SandboxSavedProfile.h > CleanStagingProfiles`, `SandboxSavedProfile.h > LoadSavedProfile`, `SandboxSavedProfile.h > HandleDeleteProfile`, `SandboxSavedProfile.h > HandleProfileInfo`, `SandboxSavedProfile.h > RunWithProfile`, `SandboxStatus.h > HandleStatus`, `SandboxStatus.h > HandleCleanup`, `SandboxStatus.h > HandleExplain`, `SandboxTypes.h > SandyLogger::Start`, `SandboxTypes.h > SandyLogger::Stop`

## Level 12 - 1 method

### sandy.cpp
- `sandy.cpp > wmain` - Sandy refs: `Sandbox.h > CleanupSandbox`, `SandboxTypes.h > SandyLogger::LogFmt`, `sandy.cpp > ConsoleCtrlHandler`, `sandy.cpp > RunMain`
