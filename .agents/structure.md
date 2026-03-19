# Sandy CLI - Method Call Structure

Every function defined in `src/`, classified by Sandy call depth.

**Level definition:**
- **Level 1** - calls only external/system APIs (Win32, CRT, STL), no Sandy methods
- **Level N** - references at least one Sandy method from Level 1-(N-1) and no higher level
- Callback and thread-proc references are counted as Sandy call edges when a Sandy function is passed by name

Format: `File > Method` or `File > Method(params)` for overloads - Sandy refs: `File > Method`

---

## Level 1 - 72 methods

### Sandbox.h
- `Sandbox.h > ConfigureEmergencyCleanupState` - leaf method
- `Sandbox.h > ResetEmergencyCleanupState` - leaf method
- `Sandbox.h > SnapshotEmergencyCleanupState` - leaf method

### SandboxACL.h
- `SandboxACL.h > AccessMask` - leaf method
- `SandboxACL.h > AceRemovalResult::Succeeded` - leaf method
- `SandboxACL.h > AclMutexGuard::~AclMutexGuard` - leaf method
- `SandboxACL.h > IsMissingSecurityTargetError` - leaf method
- `SandboxACL.h > RegistryToWin32Path` - leaf method

### SandboxCLI.h
- `SandboxCLI.h > PrintContainerToml` - leaf method
- `SandboxCLI.h > PrintRestrictedToml` - leaf method
- `SandboxCLI.h > PrintUsage` - leaf method
- `SandboxCLI.h > QuoteArg` - leaf method

### SandboxCapabilities.h
- `SandboxCapabilities.h > FreeAttributeList` - leaf method
- `SandboxCapabilities.h > FreeCapabilities` - leaf method

### SandboxCleanup.h
- `SandboxCleanup.h > CleanupTaskName` - leaf method
- `SandboxCleanup.h > EnumSandyProfiles` - leaf method

### SandboxConfig.h
- `SandboxConfig.h > GetInheritedWorkdir` - leaf method

### SandboxDynamic.h
- `SandboxDynamic.h > GetFileLastWriteTime` - leaf method
- `SandboxDynamic.h > ToLower` - leaf method

### SandboxEnvironment.h
- `SandboxEnvironment.h > BuildEnvironmentBlock` - leaf method

### SandboxGrants.h
- `SandboxGrants.h > AbortStagingGrantCapture` - leaf method
- `SandboxGrants.h > DeferredCleanupRequested` - leaf method
- `SandboxGrants.h > EndStagingGrantCapture` - leaf method
- `SandboxGrants.h > GetCurrentProcessCreationTime` - leaf method
- `SandboxGrants.h > GrantTrackingHealthy` - leaf method
- `SandboxGrants.h > HardenRegistryKeyAgainstRestricted` - leaf method
- `SandboxGrants.h > IsProcessAlive` - leaf method
- `SandboxGrants.h > PreserveGrantMetadataRequested` - leaf method
- `SandboxGrants.h > ReadPidAndCtime` - leaf method
- `SandboxGrants.h > ResetDeferredCleanupRequest` - leaf method
- `SandboxGrants.h > ResetGrantMetadataPreservation` - leaf method
- `SandboxGrants.h > ResetGrantTrackingHealth` - leaf method
- `SandboxGrants.h > ValidateSidPrefix` - leaf method

### SandboxGuard.h
- `SandboxGuard.h > SandboxGuard::Add` - leaf method
- `SandboxGuard.h > SandboxGuard::RunAll` - leaf method

### SandboxProcess.h
- `SandboxProcess.h > CloseHandleIfValid` - leaf method
- `SandboxProcess.h > DrainHiddenProcessPipe` - leaf method
- `SandboxProcess.h > GetSystemDirectoryPath` - leaf method
- `SandboxProcess.h > NeedJobTracking` - leaf method
- `SandboxProcess.h > TimeoutThread` - leaf method
- `SandboxProcess.h > WaitForJobTreeExit` - leaf method

### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > GetRecoveryLedgerKey` - leaf method
- `SandboxRecoveryLedger.h > RecoveryLedgerPresence::Any` - leaf method

### SandboxRegistry.h
- `SandboxRegistry.h > DeleteRegTreeBestEffort` - leaf method
- `SandboxRegistry.h > ReadRegDword` - leaf method
- `SandboxRegistry.h > ReadRegSz` - leaf method
- `SandboxRegistry.h > ReadRegSzEnum` - leaf method
- `SandboxRegistry.h > TryWriteRegDword` - leaf method
- `SandboxRegistry.h > TryWriteRegQword` - leaf method
- `SandboxRegistry.h > TryWriteRegSz` - leaf method
- `SandboxRegistry.h > WriteRegDword` - leaf method
- `SandboxRegistry.h > WriteRegSz` - leaf method

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > ProfileExists` - leaf method
- `SandboxSavedProfile.h > ReadTomlFileText` - leaf method

### SandboxStatus.h
- `SandboxStatus.h > HandleExplain` - leaf method

### SandboxTypes.h
- `SandboxTypes.h > AccessLevelName` - leaf method
- `SandboxTypes.h > AccessTag` - leaf method
- `SandboxTypes.h > AllocateInstanceSid` - leaf method
- `SandboxTypes.h > AppContainerMissing` - leaf method
- `SandboxTypes.h > ContainerNameFromId` - leaf method
- `SandboxTypes.h > GenerateInstanceId` - leaf method
- `SandboxTypes.h > GetSystemErrorMessage` - leaf method
- `SandboxTypes.h > IsCrashExitCode` - leaf method
- `SandboxTypes.h > NormalizeFsPath` - leaf method
- `SandboxTypes.h > NormalizeLookupKey` - leaf method
- `SandboxTypes.h > ParseAccessTag` - leaf method
- `SandboxTypes.h > SandyLogger::IsActive` - leaf method
- `SandboxTypes.h > SandyLogger::Timestamp` - leaf method

### TomlParser.h
- `TomlParser.h > ConvertLiteralNewlines` - leaf method
- `TomlParser.h > ParseResult::ok` - leaf method
- `TomlParser.h > Trim` - leaf method
- `TomlParser.h > UnescapeDQ` - leaf method

## Level 2 - 32 methods

### Sandbox.h
- `Sandbox.h > IsPathUnder` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`
- `Sandbox.h > PathDepth` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`

### SandboxCLI.h
- `SandboxCLI.h > CollectArgs` - Sandy refs: `SandboxCLI.h > QuoteArg`

### SandboxCleanup.h
- `SandboxCleanup.h > HasOtherLiveContainerUsers` - Sandy refs: `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > ReadPidAndCtime`, `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`, `SandboxRegistry.h > ReadRegSz`

### SandboxDryRun.h
- `SandboxDryRun.h > PrintFolderEntries` - Sandy refs: `SandboxTypes.h > AccessLevelName`
- `SandboxDryRun.h > PrintFolderToml` - Sandy refs: `SandboxTypes.h > AccessLevelName`

### SandboxDynamic.h
- `SandboxDynamic.h > BuildGrantKeySet` - Sandy refs: `SandboxDynamic.h > ToLower`, `SandboxTypes.h > NormalizeFsPath`
- `SandboxDynamic.h > BuildRegKeySet` - Sandy refs: `SandboxDynamic.h > ToLower`

### SandboxEnvironment.h
- `SandboxEnvironment.h > PrintConfigSummary` - Sandy refs: `SandboxTypes.h > AccessTag`

### SandboxGrants.h
- `SandboxGrants.h > BeginStagingGrantCapture` - Sandy refs: `SandboxGrants.h > ResetGrantTrackingHealth`
- `SandboxGrants.h > GetLiveContainerNames` - Sandy refs: `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > ReadPidAndCtime`, `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`, `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > NormalizeLookupKey`
- `SandboxGrants.h > GetLiveProfileNames` - Sandy refs: `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > ReadPidAndCtime`, `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`, `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > NormalizeLookupKey`
- `SandboxGrants.h > GetSavedProfileContainerNames` - Sandy refs: `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > NormalizeLookupKey`
- `SandboxGrants.h > ParseGrantRecord` - Sandy refs: `SandboxGrants.h > ValidateSidPrefix`, `SandboxTypes.h > NormalizeFsPath`

### SandboxGuard.h
- `SandboxGuard.h > SandboxGuard::~SandboxGuard` - Sandy refs: `SandboxGuard.h > SandboxGuard::RunAll`

### SandboxProcess.h
- `SandboxProcess.h > AbortLaunchedChild` - Sandy refs: `SandboxProcess.h > CloseHandleIfValid`
- `SandboxProcess.h > ReleaseLaunchedChildHandles` - Sandy refs: `SandboxProcess.h > CloseHandleIfValid`

### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > GetGrantsRegKey` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`
- `SandboxRecoveryLedger.h > GetTransientContainerRegKey` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`
- `SandboxRecoveryLedger.h > RecoveryLedgerExists` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`

### SandboxRegistry.h
- `SandboxRegistry.h > DeleteRegTreeIfExists` - Sandy refs: `SandboxRegistry.h > DeleteRegTreeBestEffort`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > EnumSavedProfiles` - Sandy refs: `SandboxRegistry.h > ReadRegSz`
- `SandboxSavedProfile.h > ReadConfigFromRegistry` - Sandy refs: `SandboxRegistry.h > ReadRegDword`, `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > NormalizeFsPath`, `SandboxTypes.h > ParseAccessTag`
- `SandboxSavedProfile.h > WriteConfigToRegistry` - Sandy refs: `SandboxRegistry.h > TryWriteRegDword`, `SandboxRegistry.h > TryWriteRegSz`, `SandboxTypes.h > AccessLevelName`

### SandboxTypes.h
- `SandboxTypes.h > SandyLogger::Log` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::LogConfig` - Sandy refs: `SandboxTypes.h > AccessTag`, `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::LogSummary` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::Start` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::Stop` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`

### TomlParser.h
- `TomlParser.h > ExtractQuotedStrings` - Sandy refs: `TomlParser.h > UnescapeDQ`
- `TomlParser.h > StripInlineComment` - Sandy refs: `TomlParser.h > Trim`
- `TomlParser.h > StripQuotes` - Sandy refs: `TomlParser.h > UnescapeDQ`

## Level 3 - 17 methods

### SandboxACL.h
- `SandboxACL.h > GrantObjectAccess` - Sandy refs: `SandboxACL.h > AccessMask`, `SandboxTypes.h > SandyLogger::Log`

### SandboxCapabilities.h
- `SandboxCapabilities.h > BuildAttributeList` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`
- `SandboxCapabilities.h > BuildCapabilities` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`

### SandboxCleanup.h
- `SandboxCleanup.h > WarnStaleRegistryEntries` - Sandy refs: `SandboxTypes.h > SandyLogger::IsActive`, `SandboxTypes.h > SandyLogger::Log`

### SandboxDryRun.h
- `SandboxDryRun.h > HandleDryRun` - Sandy refs: `SandboxDryRun.h > PrintFolderEntries`
- `SandboxDryRun.h > HandlePrintConfig` - Sandy refs: `SandboxDryRun.h > PrintFolderToml`

### SandboxDynamic.h
- `SandboxDynamic.h > WarnImmutableChanges` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`

### SandboxEnvironment.h
- `SandboxEnvironment.h > LogEnvironmentState` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`
- `SandboxEnvironment.h > LogStdinMode` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`

### SandboxGrants.h
- `SandboxGrants.h > ClearPersistedGrants` - Sandy refs: `SandboxRecoveryLedger.h > GetGrantsRegKey`, `SandboxRegistry.h > DeleteRegTreeBestEffort`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxGrants.h > FindTransientContainerCleanupInstanceIds` - Sandy refs: `SandboxRecoveryLedger.h > GetTransientContainerRegKey`, `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > NormalizeLookupKey`

### SandboxProcess.h
- `SandboxProcess.h > SetupStdinHandle` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`

### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > QueryRecoveryLedgerPresence` - Sandy refs: `SandboxRecoveryLedger.h > RecoveryLedgerExists`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > LoadSavedProfile` - Sandy refs: `SandboxRegistry.h > ReadRegSz`, `SandboxSavedProfile.h > ReadConfigFromRegistry`

### SandboxTypes.h
- `SandboxTypes.h > SandyLogger::LogFmt` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`
- `SandboxTypes.h > SandyLogger::~SandyLogger` - Sandy refs: `SandboxTypes.h > SandyLogger::Stop`

### TomlParser.h
- `TomlParser.h > Parse` - Sandy refs: `TomlParser.h > ConvertLiteralNewlines`, `TomlParser.h > ExtractQuotedStrings`, `TomlParser.h > StripInlineComment`, `TomlParser.h > StripQuotes`, `TomlParser.h > Trim`

## Level 4 - 26 methods

### Sandbox.h
- `Sandbox.h > SetupAppContainer` - Sandy refs: `SandboxGuard.h > SandboxGuard::Add`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxACL.h
- `SandboxACL.h > AclMutexGuard::Acquire` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > DenyObjectAccess` - Sandy refs: `SandboxACL.h > AccessMask`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > RemoveSidFromDaclDetailed` - Sandy refs: `SandboxACL.h > IsMissingSecurityTargetError`, `SandboxTypes.h > GetSystemErrorMessage`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > TreeSecurityProgress` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxCleanup.h
- `SandboxCleanup.h > LogSandyIdentity` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxConfig.h
- `SandboxConfig.h > MapConfig` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`, `SandboxTypes.h > SandyLogger::IsActive`, `SandboxTypes.h > SandyLogger::LogFmt`, `TomlParser.h > ParseResult::ok`

### SandboxGrants.h
- `SandboxGrants.h > ClearLiveState` - Sandy refs: `SandboxGrants.h > ClearPersistedGrants`
- `SandboxGrants.h > ClearTransientContainerCleanup` - Sandy refs: `SandboxRecoveryLedger.h > GetTransientContainerRegKey`, `SandboxRegistry.h > DeleteRegTreeBestEffort`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > DeleteTransientContainerNow` - Sandy refs: `SandboxTypes.h > AppContainerMissing`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > MarkGrantTrackingFailure` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > PersistLiveState` - Sandy refs: `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxRecoveryLedger.h > GetGrantsRegKey`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > PersistTransientContainerCleanup` - Sandy refs: `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxRecoveryLedger.h > GetTransientContainerRegKey`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxRegistry.h > TryWriteRegQword`, `SandboxRegistry.h > TryWriteRegSz`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RequestDeferredCleanup` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RequestGrantMetadataPreservation` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxProcess.h
- `SandboxProcess.h > AssignJobObject` - Sandy refs: `SandboxProcess.h > NeedJobTracking`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > LaunchChildProcess` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > RunHiddenProcessDetailed` - Sandy refs: `SandboxProcess.h > DrainHiddenProcessPipe`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > StartTimeoutWatchdog` - Sandy refs: `SandboxProcess.h > TimeoutThread`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > WaitForChildExit` - Sandy refs: `SandboxProcess.h > WaitForJobTreeExit`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > ShouldRetainCleanupTask` - Sandy refs: `SandboxRecoveryLedger.h > QueryRecoveryLedgerPresence`, `SandboxRecoveryLedger.h > RecoveryLedgerPresence::Any`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > DeleteProfileRegistryState` - Sandy refs: `SandboxRegistry.h > DeleteRegTreeBestEffort`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxSavedProfile.h > HandleProfileInfo` - Sandy refs: `SandboxSavedProfile.h > LoadSavedProfile`, `SandboxTypes.h > AccessTag`

### SandboxToken.h
- `SandboxToken.h > BuildAclWithoutSidAces` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxToken.h > CreateRestrictedSandboxToken` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxToken.h > GrantDesktopAccess` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`

## Level 5 - 16 methods

### Sandbox.h
- `Sandbox.h > SetupRestrictedToken` - Sandy refs: `SandboxGuard.h > SandboxGuard::Add`, `SandboxToken.h > CreateRestrictedSandboxToken`, `SandboxTypes.h > AllocateInstanceSid`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxACL.h
- `SandboxACL.h > AclMutexGuard::AclMutexGuard(const std::wstring&)` - Sandy refs: `SandboxACL.h > AclMutexGuard::Acquire`
- `SandboxACL.h > AclMutexGuard::AclMutexGuard(const wchar_t* fixedName)` - Sandy refs: `SandboxACL.h > AclMutexGuard::Acquire`
- `SandboxACL.h > RemoveSidFromDacl` - Sandy refs: `SandboxACL.h > RemoveSidFromDaclDetailed`

### SandboxConfig.h
- `SandboxConfig.h > ParseConfig` - Sandy refs: `SandboxConfig.h > MapConfig`, `TomlParser.h > Parse`

### SandboxGrants.h
- `SandboxGrants.h > ClearTransientContainerCleanupByContainerName` - Sandy refs: `SandboxGrants.h > ClearTransientContainerCleanup`, `SandboxGrants.h > FindTransientContainerCleanupInstanceIds`
- `SandboxGrants.h > InitializeRunLedger` - Sandy refs: `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxGrants.h > MarkGrantTrackingFailure`, `SandboxRecoveryLedger.h > GetGrantsRegKey`
- `SandboxGrants.h > PersistTransientContainerCleanupForOrphanedContainer` - Sandy refs: `SandboxGrants.h > FindTransientContainerCleanupInstanceIds`, `SandboxGrants.h > PersistTransientContainerCleanup`
- `SandboxGrants.h > RecordGrant` - Sandy refs: `SandboxGrants.h > MarkGrantTrackingFailure`, `SandboxRecoveryLedger.h > GetGrantsRegKey`, `SandboxTypes.h > NormalizeFsPath`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxGrants.h > RestoreGrantsFromKey` - Sandy refs: `SandboxACL.h > AceRemovalResult::Succeeded`, `SandboxACL.h > RemoveSidFromDaclDetailed`, `SandboxGrants.h > ParseGrantRecord`, `SandboxRegistry.h > ReadRegSzEnum`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RestoreTransientContainers` - Sandy refs: `SandboxGrants.h > ClearTransientContainerCleanup`, `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxRecoveryLedger.h > GetTransientContainerRegKey`, `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > TeardownTransientContainerForCurrentRun` - Sandy refs: `SandboxGrants.h > ClearTransientContainerCleanup`, `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > PersistTransientContainerCleanup`, `SandboxGrants.h > RequestDeferredCleanup`, `SandboxGrants.h > RequestGrantMetadataPreservation`

### SandboxProcess.h
- `SandboxProcess.h > RunHiddenProcess` - Sandy refs: `SandboxProcess.h > RunHiddenProcessDetailed`
- `SandboxProcess.h > RunSchtasksCapture` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcessDetailed`

### SandboxToken.h
- `SandboxToken.h > RevokeDesktopAccess` - Sandy refs: `SandboxToken.h > BuildAclWithoutSidAces`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxToken.h > RevokeDesktopAccessForSid` - Sandy refs: `SandboxToken.h > BuildAclWithoutSidAces`, `SandboxTypes.h > SandyLogger::LogFmt`

## Level 6 - 12 methods

### Sandbox.h
- `Sandbox.h > RecordGrantCallback` - Sandy refs: `SandboxGrants.h > RecordGrant`

### SandboxCleanup.h
- `SandboxCleanup.h > AddLoopbackExemption` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`
- `SandboxCleanup.h > ForceDisableLoopback(const std::vector<std::wstring>& containerNames)` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxCleanup.h > ForceDisableLoopback(const std::wstring& containerName)` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > ListCleanupTasks` - Sandy refs: `SandboxProcess.h > RunSchtasksCapture`
- `SandboxCleanup.h > RemoveLoopbackExemption` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`

### SandboxConfig.h
- `SandboxConfig.h > LoadConfig` - Sandy refs: `SandboxConfig.h > ParseConfig`

### SandboxDryRun.h
- `SandboxDryRun.h > HandleDryRunCreateProfile` - Sandy refs: `SandboxConfig.h > ParseConfig`, `SandboxSavedProfile.h > ProfileExists`, `SandboxSavedProfile.h > ReadTomlFileText`, `SandboxTypes.h > AccessTag`

### SandboxDynamic.h
- `SandboxDynamic.h > RevokePathEntries` - Sandy refs: `SandboxACL.h > RemoveSidFromDacl`, `SandboxTypes.h > NormalizeFsPath`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxGrants.h
- `SandboxGrants.h > RestoreStaleGrants` - Sandy refs: `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > PersistTransientContainerCleanup`, `SandboxGrants.h > ReadPidAndCtime`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxGrants.h > RestoreTransientContainers`, `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`, `SandboxRegistry.h > DeleteRegTreeBestEffort`, `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RevokeAllGrants` - Sandy refs: `SandboxACL.h > RemoveSidFromDacl`, `SandboxGrants.h > ClearPersistedGrants`, `SandboxGrants.h > PreserveGrantMetadataRequested`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxProcess.h
- `SandboxProcess.h > RunSchtasks` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`

## Level 7 - 13 methods

### Sandbox.h
- `Sandbox.h > ApplyAccessPipeline` - Sandy refs: `Sandbox.h > IsPathUnder`, `Sandbox.h > PathDepth`, `Sandbox.h > RecordGrantCallback`, `SandboxACL.h > AccessMask`, `SandboxACL.h > DenyObjectAccess`, `SandboxACL.h > GrantObjectAccess`, `SandboxACL.h > RemoveSidFromDacl`, `SandboxTypes.h > AccessTag`, `SandboxTypes.h > GetSystemErrorMessage`, `SandboxTypes.h > SandyLogger::LogFmt`
- `Sandbox.h > DynamicWatcherThread` - Sandy refs: `Sandbox.h > IsPathUnder`, `Sandbox.h > RecordGrantCallback`, `SandboxACL.h > DenyObjectAccess`, `SandboxACL.h > GrantObjectAccess`, `SandboxACL.h > RegistryToWin32Path`, `SandboxACL.h > RemoveSidFromDacl`, `SandboxConfig.h > LoadConfig`, `SandboxDynamic.h > BuildGrantKeySet`, `SandboxDynamic.h > BuildRegKeySet`, `SandboxDynamic.h > GetFileLastWriteTime`, `SandboxDynamic.h > RevokePathEntries`, `SandboxDynamic.h > ToLower`, `SandboxDynamic.h > WarnImmutableChanges`, `SandboxGrants.h > GrantTrackingHealthy`, `SandboxGrants.h > ResetGrantTrackingHealth`, `SandboxTypes.h > AccessTag`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `Sandbox.h > GrantRegistryAccess` - Sandy refs: `Sandbox.h > RecordGrantCallback`, `SandboxACL.h > GrantObjectAccess`, `SandboxACL.h > RegistryToWin32Path`, `SandboxTypes.h > GetSystemErrorMessage`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxCleanup.h
- `SandboxCleanup.h > CleanupStaleStartupState` - Sandy refs: `SandboxCleanup.h > EnumSandyProfiles`, `SandboxCleanup.h > ForceDisableLoopback(const std::vector<std::wstring>& containerNames)`, `SandboxGrants.h > GetLiveContainerNames`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > CreateCleanupTask` - Sandy refs: `SandboxCleanup.h > CleanupTaskName`, `SandboxProcess.h > RunSchtasks`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > DeleteCleanupTask` - Sandy refs: `SandboxCleanup.h > CleanupTaskName`, `SandboxProcess.h > RunSchtasks`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > DeleteStaleCleanupTasks` - Sandy refs: `SandboxCleanup.h > ListCleanupTasks`, `SandboxProcess.h > RunSchtasks`, `SandboxRecoveryLedger.h > QueryRecoveryLedgerPresence`, `SandboxRecoveryLedger.h > RecoveryLedgerPresence::Any`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > DisableLoopback` - Sandy refs: `SandboxCleanup.h > HasOtherLiveContainerUsers`, `SandboxCleanup.h > RemoveLoopbackExemption`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > DisableLoopbackForContainer` - Sandy refs: `SandboxCleanup.h > RemoveLoopbackExemption`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxCleanup.h > EnableRunLoopback` - Sandy refs: `SandboxCleanup.h > AddLoopbackExemption`
- `SandboxCleanup.h > EnsureProfileLoopback` - Sandy refs: `SandboxCleanup.h > AddLoopbackExemption`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > TeardownPersistentProfileContainer` - Sandy refs: `SandboxCleanup.h > RemoveLoopbackExemption`, `SandboxTypes.h > AppContainerMissing`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxStatus.h
- `SandboxStatus.h > HandleStatus` - Sandy refs: `SandboxCleanup.h > EnumSandyProfiles`, `SandboxCleanup.h > ListCleanupTasks`, `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > ReadPidAndCtime`, `SandboxSavedProfile.h > EnumSavedProfiles`

## Level 8 - 4 methods

### SandboxCleanup.h
- `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun` - Sandy refs: `SandboxCleanup.h > CleanupTaskName`, `SandboxCleanup.h > DeleteCleanupTask`, `SandboxGrants.h > DeferredCleanupRequested`, `SandboxRecoveryLedger.h > ShouldRetainCleanupTask`, `SandboxTypes.h > SandyLogger::LogFmt`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > CleanStagingProfiles` - Sandy refs: `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxRegistry.h > ReadRegSz`, `SandboxSavedProfile.h > DeleteProfileRegistryState`, `SandboxSavedProfile.h > TeardownPersistentProfileContainer`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxSavedProfile.h > HandleCreateProfile` - Sandy refs: `Sandbox.h > ApplyAccessPipeline`, `Sandbox.h > GrantRegistryAccess`, `SandboxCleanup.h > EnsureProfileLoopback`, `SandboxConfig.h > ParseConfig`, `SandboxGrants.h > AbortStagingGrantCapture`, `SandboxGrants.h > BeginStagingGrantCapture`, `SandboxGrants.h > EndStagingGrantCapture`, `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > GrantTrackingHealthy`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxRegistry.h > TryWriteRegQword`, `SandboxRegistry.h > TryWriteRegSz`, `SandboxSavedProfile.h > DeleteProfileRegistryState`, `SandboxSavedProfile.h > ReadTomlFileText`, `SandboxSavedProfile.h > TeardownPersistentProfileContainer`, `SandboxSavedProfile.h > WriteConfigToRegistry`, `SandboxToken.h > GrantDesktopAccess`, `SandboxTypes.h > AllocateInstanceSid`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxSavedProfile.h > HandleDeleteProfile` - Sandy refs: `SandboxCleanup.h > DisableLoopbackForContainer`, `SandboxGrants.h > GetLiveContainerNames`, `SandboxGrants.h > GetLiveProfileNames`, `SandboxGrants.h > IsProcessAlive`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxRegistry.h > ReadRegDword`, `SandboxRegistry.h > ReadRegSz`, `SandboxSavedProfile.h > DeleteProfileRegistryState`, `SandboxSavedProfile.h > TeardownPersistentProfileContainer`, `SandboxToken.h > RevokeDesktopAccessForSid`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::LogFmt`

## Level 9 - 4 methods

### Sandbox.h
- `Sandbox.h > BeginRunSession` - Sandy refs: `SandboxCleanup.h > CleanupStaleStartupState`, `SandboxCleanup.h > CreateCleanupTask`, `SandboxCleanup.h > DeleteStaleCleanupTasks`, `SandboxCleanup.h > LogSandyIdentity`, `SandboxCleanup.h > WarnStaleRegistryEntries`, `SandboxGrants.h > ResetDeferredCleanupRequest`, `SandboxGrants.h > ResetGrantMetadataPreservation`, `SandboxGrants.h > RestoreStaleGrants`, `SandboxSavedProfile.h > CleanStagingProfiles`, `SandboxTypes.h > SandyLogger::Log`
- `Sandbox.h > CleanupSandbox` - Sandy refs: `Sandbox.h > ResetEmergencyCleanupState`, `Sandbox.h > SnapshotEmergencyCleanupState`, `SandboxCleanup.h > DisableLoopback`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `SandboxGrants.h > RevokeAllGrants`, `SandboxGrants.h > TeardownTransientContainerForCurrentRun`, `SandboxProcess.h > WaitForJobTreeExit`, `SandboxToken.h > RevokeDesktopAccess`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::Stop`
- `Sandbox.h > RunPipeline` - Sandy refs: `Sandbox.h > ApplyAccessPipeline`, `Sandbox.h > ConfigureEmergencyCleanupState`, `Sandbox.h > DynamicWatcherThread`, `Sandbox.h > GrantRegistryAccess`, `Sandbox.h > SetupAppContainer`, `Sandbox.h > SetupRestrictedToken`, `SandboxCapabilities.h > BuildAttributeList`, `SandboxCapabilities.h > BuildCapabilities`, `SandboxCapabilities.h > FreeAttributeList`, `SandboxCapabilities.h > FreeCapabilities`, `SandboxCleanup.h > DisableLoopback`, `SandboxCleanup.h > EnableRunLoopback`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `SandboxEnvironment.h > BuildEnvironmentBlock`, `SandboxEnvironment.h > LogEnvironmentState`, `SandboxEnvironment.h > LogStdinMode`, `SandboxEnvironment.h > PrintConfigSummary`, `SandboxGrants.h > GrantTrackingHealthy`, `SandboxGrants.h > InitializeRunLedger`, `SandboxGrants.h > ResetGrantTrackingHealth`, `SandboxGrants.h > RevokeAllGrants`, `SandboxGrants.h > TeardownTransientContainerForCurrentRun`, `SandboxGuard.h > SandboxGuard::Add`, `SandboxGuard.h > SandboxGuard::RunAll`, `SandboxProcess.h > AbortLaunchedChild`, `SandboxProcess.h > AssignJobObject`, `SandboxProcess.h > CloseHandleIfValid`, `SandboxProcess.h > LaunchChildProcess`, `SandboxProcess.h > NeedJobTracking`, `SandboxProcess.h > ReleaseLaunchedChildHandles`, `SandboxProcess.h > SetupStdinHandle`, `SandboxProcess.h > StartTimeoutWatchdog`, `SandboxProcess.h > WaitForChildExit`, `SandboxToken.h > GrantDesktopAccess`, `SandboxToken.h > RevokeDesktopAccess`, `SandboxTypes.h > IsCrashExitCode`, `SandboxTypes.h > SandyLogger::IsActive`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogConfig`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > SandyLogger::LogSummary`, `SandboxTypes.h > SandyLogger::Stop`

### SandboxStatus.h
- `SandboxStatus.h > HandleCleanup` - Sandy refs: `SandboxCleanup.h > DeleteStaleCleanupTasks`, `SandboxCleanup.h > EnumSandyProfiles`, `SandboxCleanup.h > ForceDisableLoopback(const std::vector<std::wstring>& containerNames)`, `SandboxGrants.h > ClearTransientContainerCleanupByContainerName`, `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > GetLiveContainerNames`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxGrants.h > PersistTransientContainerCleanupForOrphanedContainer`, `SandboxGrants.h > RestoreStaleGrants`, `SandboxRegistry.h > DeleteRegTreeIfExists`, `SandboxSavedProfile.h > CleanStagingProfiles`, `SandboxTypes.h > NormalizeLookupKey`

## Level 10 - 3 methods

### Sandbox.h
- `Sandbox.h > RunSandboxed` - Sandy refs: `Sandbox.h > BeginRunSession`, `Sandbox.h > ResetEmergencyCleanupState`, `Sandbox.h > RunPipeline`, `SandboxConfig.h > GetInheritedWorkdir`, `SandboxTypes.h > ContainerNameFromId`, `SandboxTypes.h > GenerateInstanceId`

### SandboxSavedProfile.h
- `SandboxSavedProfile.h > RunWithProfile` - Sandy refs: `Sandbox.h > BeginRunSession`, `Sandbox.h > ResetEmergencyCleanupState`, `Sandbox.h > RunPipeline`, `SandboxCleanup.h > DeleteCleanupTask`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `SandboxConfig.h > GetInheritedWorkdir`, `SandboxGrants.h > ClearLiveState`, `SandboxGrants.h > PersistLiveState`, `SandboxToken.h > CreateRestrictedSandboxToken`, `SandboxTypes.h > GenerateInstanceId`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`

### sandy.cpp
- `sandy.cpp > ConsoleCtrlHandler` - Sandy refs: `Sandbox.h > CleanupSandbox`, `SandboxTypes.h > SandyLogger::LogFmt`

## Level 11 - 1 method

### sandy.cpp
- `sandy.cpp > RunMain` - Sandy refs: `Sandbox.h > RunSandboxed`, `SandboxCLI.h > CollectArgs`, `SandboxCLI.h > PrintContainerToml`, `SandboxCLI.h > PrintRestrictedToml`, `SandboxCLI.h > PrintUsage`, `SandboxConfig.h > LoadConfig`, `SandboxConfig.h > ParseConfig`, `SandboxDryRun.h > HandleDryRun`, `SandboxDryRun.h > HandleDryRunCreateProfile`, `SandboxDryRun.h > HandlePrintConfig`, `SandboxSavedProfile.h > HandleCreateProfile`, `SandboxSavedProfile.h > HandleDeleteProfile`, `SandboxSavedProfile.h > HandleProfileInfo`, `SandboxSavedProfile.h > LoadSavedProfile`, `SandboxSavedProfile.h > RunWithProfile`, `SandboxStatus.h > HandleCleanup`, `SandboxStatus.h > HandleExplain`, `SandboxStatus.h > HandleStatus`, `SandboxTypes.h > SandyLogger::Start`, `SandboxTypes.h > SandyLogger::Stop`

## Level 12 - 1 method

### sandy.cpp
- `sandy.cpp > wmain` - Sandy refs: `Sandbox.h > CleanupSandbox`, `SandboxTypes.h > SandyLogger::LogFmt`, `sandy.cpp > ConsoleCtrlHandler`, `sandy.cpp > RunMain`
