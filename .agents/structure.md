# Sandy CLI - Method Call Structure

Every function defined in `src/`, classified by Sandy call depth.
Only references to Sandy functions defined inside `src/` are counted; external/system APIs and third-party code are excluded.

**Level definition:**
- **Level 1** - calls only external/system APIs (Win32, CRT, STL, toml11), no Sandy methods
- **Level N** - references at least one Sandy method from Level 1-(N-1) and no higher level
- Callback and thread-proc references are counted as Sandy call edges when a Sandy function is passed by name

Format: `File > Method` or `File > Method(params)` for overloads - Sandy refs: `File > Method`

---

## Level 1 - 128 methods

### Sandbox.h
- `Sandbox.h > CollectDenyPaths` - leaf method
- `Sandbox.h > SidToStringOrEmpty` - leaf method
- `Sandbox.h > ResetEmergencyCleanupState` - leaf method
- `Sandbox.h > ConfigureEmergencyCleanupState` - leaf method
- `Sandbox.h > SnapshotEmergencyCleanupState` - leaf method
- `Sandbox.h > CloseLaunchStdinHandle` - leaf method
### SandboxACL.h
- `SandboxACL.h > AceRemovalResult::Succeeded` - leaf method
- `SandboxACL.h > AclMutexGuard::~AclMutexGuard` - leaf method
- `SandboxACL.h > RegistryToWin32Path` - leaf method
- `SandboxACL.h > AccessMask` - leaf method
- `SandboxACL.h > RegistryAccessMask` - leaf method
- `SandboxACL.h > WriteDaclToObject` - leaf method
- `SandboxACL.h > IsMissingSecurityTargetError` - leaf method
### SandboxCapabilities.h
- `SandboxCapabilities.h > FreeCapabilities` - leaf method
- `SandboxCapabilities.h > FreeAttributeList` - leaf method
### SandboxCleanup.h
- `SandboxCleanup.h > CleanupTaskName` - leaf method
- `SandboxCleanup.h > CleanupTaskStateJsonName` - leaf method
- `SandboxCleanup.h > CleanupTaskStateTextLabel` - leaf method
- `SandboxCleanup.h > TryParseCleanupTaskNameFromCsvLine` - leaf method
- `SandboxCleanup.h > EnumSandyProfiles` - leaf method
### SandboxCLI.h
- `SandboxCLI.h > PrintUsage` - leaf method
- `SandboxCLI.h > PrintContainerToml` - leaf method
- `SandboxCLI.h > PrintRestrictedToml` - leaf method
- `SandboxCLI.h > QuoteArg` - leaf method
### SandboxConfig.h
- `SandboxConfig.h > GetInheritedWorkdir` - leaf method
- `SandboxConfig.h > ReadTomlFileUtf8` - leaf method
- `SandboxConfig.h > FolderAccessKeyMap` - leaf method
- `SandboxConfig.h > RequireScalarValue` - leaf method
- `SandboxConfig.h > PrivilegeBoolKeyMap` - leaf method
- `SandboxConfig.h > RegistryArrayKeyMap` - leaf method
- `SandboxConfig.h > LimitKeyMap` - leaf method
- `SandboxConfig.h > IsAbsoluteFilesystemPath` - leaf method
- `SandboxConfig.h > ReportConfiguredPathValidationError` - leaf method
- `SandboxConfig.h > ValidateRegistryPathPrefixes` - leaf method
- `SandboxConfig.h > ValidateScalarPathLength` - leaf method
- `SandboxConfig.h > ValidateFolderEntryPathLengths` - leaf method
### SandboxConfigRender.h
- `SandboxConfigRender.h > TomlQuotedValue` - leaf method
### SandboxEnvironment.h
- `SandboxEnvironment.h > IsEssentialEnvironmentVar` - leaf method
- `SandboxEnvironment.h > IsExplicitlyPassedEnvironmentVar` - leaf method
- `SandboxEnvironment.h > CollectCurrentEnvironmentSnapshot` - leaf method
- `SandboxEnvironment.h > SortEnvironmentVarsForWindows` - leaf method
- `SandboxEnvironment.h > AppendSerializedEnvironmentEntry` - leaf method
- `SandboxEnvironment.h > StdinSummaryLabel` - leaf method
- `SandboxEnvironment.h > PrintSummaryLimits` - leaf method
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
- `SandboxProcess.h > HiddenProcessLogTarget` - leaf method
- `SandboxProcess.h > TimeoutThread` - leaf method
- `SandboxProcess.h > NeedJobTracking` - leaf method
- `SandboxProcess.h > WaitForJobTreeExit` - leaf method
### SandboxProfileRegistry.h
- `SandboxProfileRegistry.h > OpenSavedProfileRegistryKey` - leaf method
- `SandboxProfileRegistry.h > EnumSavedProfileRegistryNames` - leaf method
### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > RecoveryLedgerBlocksCleanup` - leaf method
- `SandboxRecoveryLedger.h > RecoveryLedgerLivenessJsonName` - leaf method
- `SandboxRecoveryLedger.h > RecoveryLedgerLivenessTextLabel` - leaf method
- `SandboxRecoveryLedger.h > RecoveryLedgerPresence::Any` - leaf method
- `SandboxRecoveryLedger.h > GetRecoveryLedgerKey` - leaf method
- `SandboxRecoveryLedger.h > GetRecoveryLedgerParentKey` - leaf method
### SandboxRegistry.h
- `SandboxRegistry.h > WriteRegSz` - leaf method
- `SandboxRegistry.h > TryWriteRegSz` - leaf method
- `SandboxRegistry.h > ReadRegSz` - leaf method
- `SandboxRegistry.h > WriteRegDword` - leaf method
- `SandboxRegistry.h > TryWriteRegDword` - leaf method
- `SandboxRegistry.h > TryWriteRegQword` - leaf method
- `SandboxRegistry.h > ReadRegDword` - leaf method
- `SandboxRegistry.h > TryReadRegDword` - leaf method
- `SandboxRegistry.h > ReadRegSzEnum` - leaf method
- `SandboxRegistry.h > DeleteRegTreeBestEffort` - leaf method
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > ReadStagingPidAndCtime` - leaf method
- `SandboxSavedProfile.h > BuildIndexedValueName` - leaf method
- `SandboxSavedProfile.h > GrantScopeSuffix` - leaf method
- `SandboxSavedProfile.h > FreeProfileCreateSid` - leaf method
- `SandboxSavedProfile.h > ClearTrackedAclGrantInventory` - leaf method
- `SandboxSavedProfile.h > ValidateProfileCreateName` - leaf method
- `SandboxSavedProfile.h > PrintCreatedProfileSummary` - leaf method
### SandboxStatus.h
- `SandboxStatus.h > HasVisibleStatusState` - leaf method
- `SandboxStatus.h > EscapeStatusJson` - leaf method
- `SandboxStatus.h > CleanupTaskLedgerSourceLabel` - leaf method
- `SandboxStatus.h > HandleExplain` - leaf method
### SandboxToken.h
- `SandboxToken.h > DesktopGrantSidStringOrEmpty` - leaf method
- `SandboxToken.h > TrackDesktopGrant` - leaf method
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
- `SandboxTypes.h > IsRestrictedTokenMode` - leaf method
- `SandboxTypes.h > TokenModeName` - leaf method
- `SandboxTypes.h > TokenModeSummaryLabel` - leaf method
- `SandboxTypes.h > TryParseTokenMode` - leaf method
- `SandboxTypes.h > LanModeRegistryName` - leaf method
- `SandboxTypes.h > LanModePhrase` - leaf method
- `SandboxTypes.h > LanModeTomlDisplayValue` - leaf method
- `SandboxTypes.h > TryParseLanModeConfigValue` - leaf method
- `SandboxTypes.h > TryParseLanModeRegistryValue` - leaf method
- `SandboxTypes.h > SandyLogger::Timestamp` - leaf method
- `SandboxTypes.h > SandyLogger::StdinLogValue` - leaf method
- `SandboxTypes.h > SandyLogger::WriteConfigHeaderUnlocked` - leaf method
- `SandboxTypes.h > SandyLogger::WriteRegistryEntriesUnlocked` - leaf method
- `SandboxTypes.h > SandyLogger::WriteLimitsSectionUnlocked` - leaf method
- `SandboxTypes.h > SandyLogger::TryFormatLogMessage` - leaf method
- `SandboxTypes.h > SandyLogger::IsActive` - leaf method
### TomlAdapter.h
- `TomlAdapter.h > ParseResult::ok` - leaf method
- `TomlAdapter.h > Utf8ToWide` - leaf method
- `TomlAdapter.h > WideToUtf8` - leaf method
- `TomlAdapter.h > ConvertLiteralNewlines` - leaf method
### sandy.cpp
- `sandy.cpp > StampLogPath` - leaf method

## Level 2 - 52 methods

### Sandbox.h
- `Sandbox.h > PathDepth` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`
- `Sandbox.h > IsPathUnder` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`
- `Sandbox.h > MapChildExitToSandyExit` - Sandy refs: `SandboxTypes.h > IsCrashExitCode`
### SandboxCLI.h
- `SandboxCLI.h > CollectArgs` - Sandy refs: `SandboxCLI.h > QuoteArg`
### SandboxConfig.h
- `SandboxConfig.h > ReadTomlFileText` - Sandy refs: `SandboxConfig.h > ReadTomlFileUtf8`, `TomlAdapter.h > Utf8ToWide`
- `SandboxConfig.h > ParseFolderRuleSection` - Sandy refs: `SandboxConfig.h > FolderAccessKeyMap`
- `SandboxConfig.h > TryParseBoolValue` - Sandy refs: `SandboxConfig.h > RequireScalarValue`
- `SandboxConfig.h > AppendStringArrayValues` - Sandy refs: `TomlAdapter.h > ParseResult::ok`
- `SandboxConfig.h > TryParseBoundedNonNegativeInteger` - Sandy refs: `SandboxConfig.h > RequireScalarValue`
- `SandboxConfig.h > GetConfiguredPathValidationError` - Sandy refs: `SandboxConfig.h > IsAbsoluteFilesystemPath`
- `SandboxConfig.h > NormalizeConfigFilesystemPaths` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`
- `SandboxConfig.h > ValidateConfigSanityLimits` - Sandy refs: `SandboxConfig.h > ValidateScalarPathLength`, `SandboxConfig.h > ValidateFolderEntryPathLengths`
### SandboxConfigRender.h
- `SandboxConfigRender.h > PrintFolderToml` - Sandy refs: `SandboxTypes.h > AccessLevelName`, `SandboxConfigRender.h > TomlQuotedValue`
### SandboxDryRun.h
- `SandboxDryRun.h > PrintFolderEntries` - Sandy refs: `SandboxTypes.h > AccessLevelName`
### SandboxEnvironment.h
- `SandboxEnvironment.h > ShouldKeepEnvironmentVar` - Sandy refs: `SandboxEnvironment.h > IsEssentialEnvironmentVar`, `SandboxEnvironment.h > IsExplicitlyPassedEnvironmentVar`
- `SandboxEnvironment.h > SerializeEnvironmentBlock` - Sandy refs: `SandboxEnvironment.h > AppendSerializedEnvironmentEntry`
- `SandboxEnvironment.h > NetworkSummaryLabel` - Sandy refs: `SandboxTypes.h > IsRestrictedTokenMode`
- `SandboxEnvironment.h > PrintSummaryHeader` - Sandy refs: `SandboxTypes.h > TokenModeSummaryLabel`
- `SandboxEnvironment.h > PrintSummaryFolders` - Sandy refs: `SandboxTypes.h > AccessTag`
- `SandboxEnvironment.h > PrintSummaryRegistry` - Sandy refs: `SandboxTypes.h > IsRestrictedTokenMode`
### SandboxGrants.h
- `SandboxGrants.h > BeginStagingGrantCapture` - Sandy refs: `SandboxGrants.h > ResetGrantTrackingHealth`
- `SandboxGrants.h > ParseGrantRecord` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`, `SandboxGrants.h > ValidateSidPrefix`
- `SandboxGrants.h > ResolveRecoveryLedgerLiveness` - Sandy refs: `SandboxGrants.h > IsProcessAlive`
### SandboxGuard.h
- `SandboxGuard.h > SandboxGuard::~SandboxGuard` - Sandy refs: `SandboxGuard.h > SandboxGuard::RunAll`
### SandboxProcess.h
- `SandboxProcess.h > AbortLaunchedChild` - Sandy refs: `SandboxProcess.h > WaitForJobTreeExit`, `SandboxProcess.h > CloseHandleIfValid`
- `SandboxProcess.h > ReleaseLaunchedChildHandles` - Sandy refs: `SandboxProcess.h > CloseHandleIfValid`
- `SandboxProcess.h > CloseHiddenProcessHandles` - Sandy refs: `SandboxProcess.h > CloseHandleIfValid`
- `SandboxProcess.h > CloseHiddenProcessOutputWriter` - Sandy refs: `SandboxProcess.h > CloseHandleIfValid`
- `SandboxProcess.h > FinalizeHiddenProcessOutput` - Sandy refs: `SandboxProcess.h > DrainHiddenProcessPipe`
### SandboxProfileRegistry.h
- `SandboxProfileRegistry.h > ReadSavedProfileRegistrySummary` - Sandy refs: `SandboxRegistry.h > ReadRegSz`, `SandboxRegistry.h > TryReadRegDword`
### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > OpenRecoveryLedgerKey` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`
- `SandboxRecoveryLedger.h > EnumRecoveryLedgerInstanceIds` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerParentKey`
- `SandboxRecoveryLedger.h > GetGrantsRegKey` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`
- `SandboxRecoveryLedger.h > GetTransientContainerRegKey` - Sandy refs: `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`
### SandboxRegistry.h
- `SandboxRegistry.h > DeleteRegTreeIfExists` - Sandy refs: `SandboxRegistry.h > DeleteRegTreeBestEffort`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > ProfileExists` - Sandy refs: `SandboxProfileRegistry.h > OpenSavedProfileRegistryKey`
- `SandboxSavedProfile.h > SerializeFolderEntry` - Sandy refs: `SandboxTypes.h > AccessLevelName`, `SandboxSavedProfile.h > GrantScopeSuffix`
- `SandboxSavedProfile.h > TryDeserializeFolderEntry` - Sandy refs: `SandboxTypes.h > ParseAccessTag`, `SandboxTypes.h > NormalizeFsPath`
- `SandboxSavedProfile.h > WriteIndexedStringValues` - Sandy refs: `TomlAdapter.h > ParseResult::ok`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxSavedProfile.h > BuildIndexedValueName`, `SandboxRegistry.h > TryWriteRegSz`
- `SandboxSavedProfile.h > CreateProfileIdentity` - Sandy refs: `SandboxTypes.h > AllocateInstanceSid`, `SandboxSavedProfile.h > FreeProfileCreateSid`
- `SandboxSavedProfile.h > PersistProfileCreateIdentity` - Sandy refs: `TomlAdapter.h > ParseResult::ok`, `SandboxRegistry.h > TryWriteRegSz`
### SandboxStatus.h
- `SandboxStatus.h > PrintStatusJson` - Sandy refs: `SandboxStatus.h > EscapeStatusJson`, `SandboxRecoveryLedger.h > RecoveryLedgerLivenessJsonName`, `SandboxCleanup.h > CleanupTaskStateJsonName`
- `SandboxStatus.h > PrintStatusText` - Sandy refs: `SandboxRecoveryLedger.h > RecoveryLedgerLivenessTextLabel`, `SandboxRecoveryLedger.h > RecoveryLedgerLivenessJsonName`, `SandboxCleanup.h > CleanupTaskStateTextLabel`, `SandboxStatus.h > CleanupTaskLedgerSourceLabel`, `SandboxStatus.h > HasVisibleStatusState`
### SandboxTypes.h
- `SandboxTypes.h > IsAppContainerFamilyTokenMode` - Sandy refs: `SandboxTypes.h > IsRestrictedTokenMode`
- `SandboxTypes.h > SandyLogger::Start` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::Stop` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::WriteAccessSectionUnlocked` - Sandy refs: `SandboxTypes.h > AccessTag`
- `SandboxTypes.h > SandyLogger::WriteRegistrySectionUnlocked` - Sandy refs: `SandboxTypes.h > SandyLogger::WriteRegistryEntriesUnlocked`
- `SandboxTypes.h > SandyLogger::WritePrivilegesSectionUnlocked` - Sandy refs: `SandboxTypes.h > SandyLogger::StdinLogValue`, `SandboxTypes.h > LanModePhrase`
- `SandboxTypes.h > SandyLogger::WriteLogLineUnlocked` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
- `SandboxTypes.h > SandyLogger::LogSummary` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`
### TomlAdapter.h
- `TomlAdapter.h > FlattenTable` - Sandy refs: `TomlAdapter.h > Utf8ToWide`

## Level 3 - 19 methods

### Sandbox.h
- `Sandbox.h > AppendPipelineEntries` - Sandy refs: `Sandbox.h > PathDepth`
- `Sandbox.h > IsPathUnderAny` - Sandy refs: `Sandbox.h > IsPathUnder`
### SandboxConfig.h
- `SandboxConfig.h > ValidateConfiguredPath` - Sandy refs: `SandboxConfig.h > GetConfiguredPathValidationError`, `SandboxConfig.h > ReportConfiguredPathValidationError`
- `SandboxConfig.h > ValidateModeSpecificConfig` - Sandy refs: `SandboxTypes.h > IsAppContainerFamilyTokenMode`, `SandboxTypes.h > IsRestrictedTokenMode`
### SandboxConfigRender.h
- `SandboxConfigRender.h > PrintResolvedConfig` - Sandy refs: `SandboxTypes.h > IsRestrictedTokenMode`, `SandboxTypes.h > TokenModeName`, `SandboxConfigRender.h > TomlQuotedValue`, `SandboxConfigRender.h > PrintFolderToml`, `SandboxTypes.h > LanModeTomlDisplayValue`
### SandboxDryRun.h
- `SandboxDryRun.h > HandleDryRun` - Sandy refs: `SandboxTypes.h > IsRestrictedTokenMode`, `SandboxTypes.h > TokenModeName`, `SandboxDryRun.h > PrintFolderEntries`, `SandboxTypes.h > LanModeTomlDisplayValue`
### SandboxEnvironment.h
- `SandboxEnvironment.h > FilterEnvironmentVars` - Sandy refs: `SandboxEnvironment.h > ShouldKeepEnvironmentVar`
- `SandboxEnvironment.h > PrintSummaryPrivileges` - Sandy refs: `SandboxTypes.h > IsRestrictedTokenMode`, `SandboxEnvironment.h > NetworkSummaryLabel`, `SandboxEnvironment.h > StdinSummaryLabel`
### SandboxGrants.h
- `SandboxGrants.h > SnapshotGrantLedgers` - Sandy refs: `SandboxRecoveryLedger.h > EnumRecoveryLedgerInstanceIds`, `SandboxRecoveryLedger.h > OpenRecoveryLedgerKey`, `SandboxGrants.h > ReadPidAndCtime`, `SandboxRegistry.h > ReadRegSz`, `SandboxGrants.h > ResolveRecoveryLedgerLiveness`
- `SandboxGrants.h > SnapshotTransientContainerLedgers` - Sandy refs: `SandboxRecoveryLedger.h > EnumRecoveryLedgerInstanceIds`, `SandboxRecoveryLedger.h > OpenRecoveryLedgerKey`, `SandboxGrants.h > ReadPidAndCtime`, `SandboxRegistry.h > ReadRegSz`, `SandboxGrants.h > ResolveRecoveryLedgerLiveness`
### SandboxProfileRegistry.h
- `SandboxProfileRegistry.h > EnumSavedProfileRegistrySummaries` - Sandy refs: `SandboxProfileRegistry.h > EnumSavedProfileRegistryNames`, `SandboxProfileRegistry.h > OpenSavedProfileRegistryKey`, `SandboxProfileRegistry.h > ReadSavedProfileRegistrySummary`
### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > RecoveryLedgerExists` - Sandy refs: `SandboxRecoveryLedger.h > OpenRecoveryLedgerKey`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > WriteIndexedFolderEntries` - Sandy refs: `TomlAdapter.h > ParseResult::ok`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxSavedProfile.h > BuildIndexedValueName`, `SandboxRegistry.h > TryWriteRegSz`, `SandboxSavedProfile.h > SerializeFolderEntry`
### SandboxTypes.h
- `SandboxTypes.h > SandyLogger::LogConfig` - Sandy refs: `SandboxTypes.h > SandyLogger::Timestamp`, `SandboxTypes.h > SandyLogger::WriteConfigHeaderUnlocked`, `SandboxTypes.h > SandyLogger::WriteAccessSectionUnlocked`, `SandboxTypes.h > SandyLogger::WriteRegistrySectionUnlocked`, `SandboxTypes.h > SandyLogger::WritePrivilegesSectionUnlocked`, `SandboxTypes.h > SandyLogger::WriteLimitsSectionUnlocked`
- `SandboxTypes.h > SandyLogger::RecordFormattingDiagnostic` - Sandy refs: `SandboxTypes.h > SandyLogger::WriteLogLineUnlocked`
- `SandboxTypes.h > SandyLogger::Log` - Sandy refs: `SandboxTypes.h > SandyLogger::WriteLogLineUnlocked`
- `SandboxTypes.h > SandyLogger::~SandyLogger` - Sandy refs: `SandboxTypes.h > SandyLogger::Stop`
### TomlAdapter.h
- `TomlAdapter.h > ParseUtf8` - Sandy refs: `TomlAdapter.h > FlattenTable`, `TomlAdapter.h > Utf8ToWide`
### sandy.cpp
- `sandy.cpp > ParseRunMainOptions` - Sandy refs: `SandboxCLI.h > CollectArgs`, `SandboxCLI.h > PrintUsage`

## Level 4 - 17 methods

### Sandbox.h
- `Sandbox.h > BuildAccessPipeline` - Sandy refs: `Sandbox.h > AppendPipelineEntries`
### SandboxCapabilities.h
- `SandboxCapabilities.h > BuildAttributeList` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`
### SandboxDryRun.h
- `SandboxDryRun.h > HandlePrintConfig` - Sandy refs: `SandboxConfigRender.h > PrintResolvedConfig`
### SandboxEnvironment.h
- `SandboxEnvironment.h > BuildEnvironmentBlock` - Sandy refs: `SandboxEnvironment.h > CollectCurrentEnvironmentSnapshot`, `SandboxEnvironment.h > FilterEnvironmentVars`, `SandboxEnvironment.h > SortEnvironmentVarsForWindows`, `SandboxEnvironment.h > SerializeEnvironmentBlock`
- `SandboxEnvironment.h > LogEnvironmentState` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`
- `SandboxEnvironment.h > LogStdinMode` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`
- `SandboxEnvironment.h > PrintConfigSummary` - Sandy refs: `SandboxEnvironment.h > PrintSummaryHeader`, `SandboxEnvironment.h > PrintSummaryFolders`, `SandboxEnvironment.h > PrintSummaryRegistry`, `SandboxEnvironment.h > PrintSummaryPrivileges`, `SandboxEnvironment.h > PrintSummaryLimits`
### SandboxGrants.h
- `SandboxGrants.h > ClearPersistedGrants` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `SandboxRecoveryLedger.h > GetGrantsRegKey`, `SandboxRegistry.h > DeleteRegTreeBestEffort`
- `SandboxGrants.h > FindTransientContainerCleanupInstanceIds` - Sandy refs: `SandboxTypes.h > NormalizeLookupKey`, `SandboxGrants.h > SnapshotTransientContainerLedgers`
- `SandboxGrants.h > GetLiveContainerNames` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxRecoveryLedger.h > RecoveryLedgerBlocksCleanup`, `SandboxTypes.h > NormalizeLookupKey`
- `SandboxGrants.h > GetLiveProfileNames` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxRecoveryLedger.h > RecoveryLedgerBlocksCleanup`, `SandboxTypes.h > NormalizeLookupKey`
- `SandboxGrants.h > GetSavedProfileContainerNames` - Sandy refs: `SandboxProfileRegistry.h > EnumSavedProfileRegistrySummaries`, `SandboxTypes.h > NormalizeLookupKey`
### SandboxProcess.h
- `SandboxProcess.h > SetupStdinHandle` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`
### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > QueryRecoveryLedgerPresence` - Sandy refs: `SandboxRecoveryLedger.h > RecoveryLedgerExists`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > WriteConfigToRegistry` - Sandy refs: `TomlAdapter.h > ParseResult::ok`, `SandboxRegistry.h > TryWriteRegSz`, `SandboxTypes.h > TokenModeName`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxTypes.h > LanModeRegistryName`, `SandboxSavedProfile.h > WriteIndexedFolderEntries`, `SandboxSavedProfile.h > WriteIndexedStringValues`
### SandboxTypes.h
- `SandboxTypes.h > SandyLogger::LogFmt` - Sandy refs: `TomlAdapter.h > ParseResult::ok`, `SandboxTypes.h > SandyLogger::TryFormatLogMessage`, `SandboxTypes.h > SandyLogger::RecordFormattingDiagnostic`, `SandboxTypes.h > SandyLogger::Log`
### TomlAdapter.h
- `TomlAdapter.h > Parse` - Sandy refs: `TomlAdapter.h > ConvertLiteralNewlines`, `TomlAdapter.h > WideToUtf8`, `TomlAdapter.h > ParseUtf8`

## Level 5 - 38 methods

### Sandbox.h
- `Sandbox.h > LogAccessPipelinePlan` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `Sandbox.h > CollectDenyPaths`, `Sandbox.h > IsPathUnderAny`, `SandboxTypes.h > AccessTag`
- `Sandbox.h > SetupAppContainer` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxGuard.h > SandboxGuard::Add`, `SandboxTypes.h > SandyLogger::Log`, `TomlAdapter.h > ParseResult::ok`
- `Sandbox.h > ValidateRestrictedTokenIntegrity` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `Sandbox.h > LogChildExitClassification` - Sandy refs: `SandboxTypes.h > SandyLogger::LogSummary`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > IsCrashExitCode`, `SandboxTypes.h > SandyLogger::LogFmt`
### SandboxACL.h
- `SandboxACL.h > AclMutexGuard::Acquire` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > TreeSecurityProgress` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxACL.h > RollbackAceBySid` - Sandy refs: `SandboxACL.h > WriteDaclToObject`, `SandboxTypes.h > SandyLogger::LogFmt`
### SandboxCapabilities.h
- `SandboxCapabilities.h > BuildCapabilities` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
### SandboxCleanup.h
- `SandboxCleanup.h > HasOtherLiveContainerUsers` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxCleanup.h > BuildSandyContainerInventory` - Sandy refs: `SandboxGrants.h > GetLiveContainerNames`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxCleanup.h > EnumSandyProfiles`, `SandboxTypes.h > NormalizeLookupKey`
- `SandboxCleanup.h > WarnStaleRegistryEntries` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxGrants.h > SnapshotTransientContainerLedgers`, `SandboxTypes.h > SandyLogger::IsActive`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxCleanup.h > LogSandyIdentity` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
### SandboxConfig.h
- `SandboxConfig.h > ValidateFolderEntryPaths` - Sandy refs: `SandboxConfig.h > IsAbsoluteFilesystemPath`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::IsActive`, `SandboxTypes.h > SandyLogger::LogFmt`
### SandboxGrants.h
- `SandboxGrants.h > MarkGrantTrackingFailure` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RequestGrantMetadataPreservation` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > RequestDeferredCleanup` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > HardenRegistryKeyAgainstRestricted` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > ClearTransientContainerCleanup` - Sandy refs: `SandboxRecoveryLedger.h > GetTransientContainerRegKey`, `SandboxRegistry.h > DeleteRegTreeBestEffort`, `TomlAdapter.h > ParseResult::ok`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > DeleteTransientContainerNow` - Sandy refs: `TomlAdapter.h > ParseResult::ok`, `SandboxTypes.h > AppContainerMissing`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > ClearLiveState` - Sandy refs: `SandboxGrants.h > ClearPersistedGrants`
### SandboxProcess.h
- `SandboxProcess.h > SetupHiddenProcessCapture` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > LaunchHiddenProcessInstance` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxProcess.h > HiddenProcessLogTarget`
- `SandboxProcess.h > AttachHiddenProcessJob` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxProcess.h > CloseHandleIfValid`
- `SandboxProcess.h > WaitForHiddenProcessCompletion` - Sandy refs: `SandboxProcess.h > FinalizeHiddenProcessOutput`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > TerminateHiddenProcessForTimeout` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > LaunchChildProcess` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxProcess.h > AssignJobObject` - Sandy refs: `SandboxProcess.h > NeedJobTracking`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxProcess.h > WaitForChildExit` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxProcess.h > WaitForJobTreeExit`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxProcess.h > StartTimeoutWatchdog` - Sandy refs: `SandboxProcess.h > TimeoutThread`, `SandboxTypes.h > SandyLogger::LogFmt`
### SandboxRecoveryLedger.h
- `SandboxRecoveryLedger.h > ShouldRetainCleanupTask` - Sandy refs: `SandboxRecoveryLedger.h > QueryRecoveryLedgerPresence`, `SandboxRecoveryLedger.h > RecoveryLedgerPresence::Any`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > DeleteProfileRegistryState` - Sandy refs: `SandboxRegistry.h > DeleteRegTreeBestEffort`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxSavedProfile.h > ReadIndexedStringValues` - Sandy refs: `SandboxRegistry.h > ReadRegDword`, `SandboxSavedProfile.h > BuildIndexedValueName`, `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxSavedProfile.h > ReadIndexedFolderEntries` - Sandy refs: `SandboxRegistry.h > ReadRegDword`, `SandboxSavedProfile.h > BuildIndexedValueName`, `SandboxRegistry.h > ReadRegSz`, `SandboxSavedProfile.h > TryDeserializeFolderEntry`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxSavedProfile.h > CommitCreatedProfile` - Sandy refs: `SandboxRegistry.h > TryWriteRegSz`, `SandboxTypes.h > SandyLogger::Timestamp`, `SandboxSavedProfile.h > WriteConfigToRegistry`
- `SandboxSavedProfile.h > ShouldRollbackStagingProfile` - Sandy refs: `SandboxProfileRegistry.h > OpenSavedProfileRegistryKey`, `SandboxSavedProfile.h > ReadStagingPidAndCtime`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxGrants.h > IsProcessAlive`
- `SandboxSavedProfile.h > LogIncompleteStagingRollback` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`
### SandboxToken.h
- `SandboxToken.h > CreateRestrictedSandboxToken` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `TomlAdapter.h > ParseResult::ok`
- `SandboxToken.h > BuildAclWithoutSidAces` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`

## Level 6 - 20 methods

### Sandbox.h
- `Sandbox.h > SetupRestrictedToken` - Sandy refs: `SandboxTypes.h > AllocateInstanceSid`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxGuard.h > SandboxGuard::Add`, `SandboxToken.h > CreateRestrictedSandboxToken`, `SandboxTypes.h > SandyLogger::Log`, `TomlAdapter.h > ParseResult::ok`
- `Sandbox.h > PrepareLaunchState` - Sandy refs: `SandboxCapabilities.h > BuildCapabilities`, `SandboxTypes.h > SandyLogger::Log`, `SandboxCapabilities.h > FreeCapabilities`, `SandboxGuard.h > SandboxGuard::Add`, `SandboxCapabilities.h > BuildAttributeList`, `SandboxCapabilities.h > FreeAttributeList`, `SandboxEnvironment.h > LogStdinMode`, `SandboxEnvironment.h > BuildEnvironmentBlock`, `SandboxEnvironment.h > LogEnvironmentState`, `SandboxTypes.h > SandyLogger::IsActive`, `SandboxEnvironment.h > PrintConfigSummary`, `SandboxProcess.h > SetupStdinHandle`
- `Sandbox.h > StartManagedChild` - Sandy refs: `SandboxProcess.h > LaunchChildProcess`, `Sandbox.h > CloseLaunchStdinHandle`, `SandboxProcess.h > AssignJobObject`, `SandboxProcess.h > NeedJobTracking`, `SandboxTypes.h > SandyLogger::Log`, `SandboxProcess.h > CloseHandleIfValid`, `SandboxProcess.h > StartTimeoutWatchdog`
- `Sandbox.h > WaitForManagedChild` - Sandy refs: `SandboxProcess.h > WaitForChildExit`
### SandboxACL.h
- `SandboxACL.h > AclMutexGuard::AclMutexGuard(const std::wstring&)` - Sandy refs: `SandboxACL.h > AclMutexGuard::Acquire`
- `SandboxACL.h > AclMutexGuard::AclMutexGuard(const wchar_t* fixedName)` - Sandy refs: `SandboxACL.h > AclMutexGuard::Acquire`
### SandboxConfig.h
- `SandboxConfig.h > MapConfig` - Sandy refs: `TomlAdapter.h > ParseResult::ok`, `SandboxConfig.h > RequireScalarValue`, `SandboxTypes.h > TryParseTokenMode`, `SandboxConfig.h > TryParseBoolValue`, `SandboxConfig.h > ParseFolderRuleSection`, `SandboxConfig.h > RegistryArrayKeyMap`, `SandboxConfig.h > AppendStringArrayValues`, `SandboxConfig.h > PrivilegeBoolKeyMap`, `SandboxTypes.h > TryParseLanModeConfigValue`, `SandboxConfig.h > LimitKeyMap`, `SandboxConfig.h > TryParseBoundedNonNegativeInteger`, `SandboxConfig.h > ValidateModeSpecificConfig`, `SandboxConfig.h > NormalizeConfigFilesystemPaths`, `SandboxConfig.h > ValidateConfiguredPath`, `SandboxConfig.h > ValidateFolderEntryPaths`, `SandboxConfig.h > ValidateRegistryPathPrefixes`, `SandboxConfig.h > ValidateConfigSanityLimits`
### SandboxGrants.h
- `SandboxGrants.h > InitializeRunLedger` - Sandy refs: `SandboxRecoveryLedger.h > GetGrantsRegKey`, `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > MarkGrantTrackingFailure`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`
- `SandboxGrants.h > RecordGrant` - Sandy refs: `SandboxTypes.h > NormalizeFsPath`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxGrants.h > MarkGrantTrackingFailure`, `SandboxRecoveryLedger.h > GetGrantsRegKey`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxGrants.h > PersistTransientContainerCleanup` - Sandy refs: `SandboxRecoveryLedger.h > GetTransientContainerRegKey`, `TomlAdapter.h > ParseResult::ok`, `SandboxRegistry.h > TryWriteRegQword`, `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxRegistry.h > TryWriteRegSz`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxGrants.h > ClearTransientContainerCleanupByContainerName` - Sandy refs: `SandboxGrants.h > FindTransientContainerCleanupInstanceIds`, `SandboxGrants.h > ClearTransientContainerCleanup`
- `SandboxGrants.h > RestoreTransientContainers` - Sandy refs: `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxGrants.h > SnapshotTransientContainerLedgers`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxGrants.h > ClearTransientContainerCleanup`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxGrants.h > DeleteTransientContainerNow`
- `SandboxGrants.h > PersistLiveState` - Sandy refs: `SandboxRecoveryLedger.h > GetGrantsRegKey`, `TomlAdapter.h > ParseResult::ok`, `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxTypes.h > SandyLogger::LogFmt`
### SandboxProcess.h
- `SandboxProcess.h > RunHiddenProcessDetailed` - Sandy refs: `SandboxProcess.h > HiddenProcessLogTarget`, `SandboxProcess.h > SetupHiddenProcessCapture`, `SandboxProcess.h > LaunchHiddenProcessInstance`, `SandboxProcess.h > CloseHiddenProcessHandles`, `SandboxProcess.h > CloseHiddenProcessOutputWriter`, `SandboxProcess.h > AttachHiddenProcessJob`, `SandboxProcess.h > WaitForHiddenProcessCompletion`, `SandboxProcess.h > TerminateHiddenProcessForTimeout`, `SandboxProcess.h > FinalizeHiddenProcessOutput`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > ReadConfigFromRegistry` - Sandy refs: `SandboxRegistry.h > ReadRegSz`, `SandboxTypes.h > TryParseTokenMode`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > NormalizeFsPath`, `SandboxConfig.h > GetConfiguredPathValidationError`, `SandboxRegistry.h > ReadRegDword`, `SandboxTypes.h > TryParseLanModeRegistryValue`, `SandboxRegistry.h > TryReadRegDword`, `SandboxTypes.h > SandyLogger::Log`, `SandboxSavedProfile.h > ReadIndexedFolderEntries`, `SandboxSavedProfile.h > ReadIndexedStringValues`
- `SandboxSavedProfile.h > BeginProfileCreationTransaction` - Sandy refs: `SandboxGrants.h > HardenRegistryKeyAgainstRestricted`, `SandboxRegistry.h > TryWriteRegDword`, `SandboxRegistry.h > TryWriteRegQword`, `SandboxGrants.h > GetCurrentProcessCreationTime`, `SandboxSavedProfile.h > DeleteProfileRegistryState`
- `SandboxSavedProfile.h > AbortUncommittedProfileCreation` - Sandy refs: `SandboxSavedProfile.h > FreeProfileCreateSid`, `SandboxSavedProfile.h > DeleteProfileRegistryState`
- `SandboxSavedProfile.h > FinalizeProfileCreateRollback` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxSavedProfile.h > DeleteProfileRegistryState`
- `SandboxSavedProfile.h > CollectRollbackEligibleStagingProfiles` - Sandy refs: `SandboxProfileRegistry.h > EnumSavedProfileRegistrySummaries`, `SandboxSavedProfile.h > ShouldRollbackStagingProfile`
- `SandboxSavedProfile.h > FinalizeStagingRollbackMetadata` - Sandy refs: `SandboxSavedProfile.h > DeleteProfileRegistryState`, `SandboxTypes.h > SandyLogger::LogFmt`

## Level 7 - 15 methods

### Sandbox.h
- `Sandbox.h > RecordGrantCallback` - Sandy refs: `SandboxGrants.h > RecordGrant`
- `Sandbox.h > ResolveRunIdentity` - Sandy refs: `Sandbox.h > SetupRestrictedToken`, `Sandbox.h > SetupAppContainer`, `TomlAdapter.h > ParseResult::ok`
### SandboxACL.h
- `SandboxACL.h > GrantObjectAccess` - Sandy refs: `SandboxACL.h > AclMutexGuard::AclMutexGuard(const std::wstring&)`, `SandboxACL.h > AclMutexGuard::AclMutexGuard(const wchar_t* fixedName)`, `SandboxACL.h > RegistryAccessMask`, `SandboxACL.h > AccessMask`, `SandboxACL.h > WriteDaclToObject`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxACL.h > RollbackAceBySid`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxACL.h > DenyObjectAccess` - Sandy refs: `SandboxACL.h > AclMutexGuard::AclMutexGuard(const std::wstring&)`, `SandboxACL.h > AclMutexGuard::AclMutexGuard(const wchar_t* fixedName)`, `SandboxACL.h > AccessMask`, `SandboxACL.h > WriteDaclToObject`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxACL.h > RollbackAceBySid`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxACL.h > RemoveSidFromDaclDetailed` - Sandy refs: `SandboxACL.h > AclMutexGuard::AclMutexGuard(const std::wstring&)`, `SandboxACL.h > AclMutexGuard::AclMutexGuard(const wchar_t* fixedName)`, `SandboxACL.h > IsMissingSecurityTargetError`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > GetSystemErrorMessage`, `SandboxACL.h > WriteDaclToObject`
### SandboxConfig.h
- `SandboxConfig.h > ParseConfig` - Sandy refs: `SandboxConfig.h > MapConfig`, `TomlAdapter.h > Parse`
- `SandboxConfig.h > ParseConfigFileText` - Sandy refs: `SandboxConfig.h > MapConfig`, `TomlAdapter.h > ParseUtf8`, `TomlAdapter.h > WideToUtf8`
- `SandboxConfig.h > LoadConfig` - Sandy refs: `SandboxConfig.h > ReadTomlFileUtf8`, `SandboxConfig.h > MapConfig`, `TomlAdapter.h > ParseUtf8`
### SandboxGrants.h
- `SandboxGrants.h > PersistTransientContainerCleanupForOrphanedContainer` - Sandy refs: `SandboxGrants.h > FindTransientContainerCleanupInstanceIds`, `SandboxGrants.h > PersistTransientContainerCleanup`
- `SandboxGrants.h > TeardownTransientContainerForCurrentRun` - Sandy refs: `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > ClearTransientContainerCleanup`, `SandboxGrants.h > RequestDeferredCleanup`, `SandboxGrants.h > PersistTransientContainerCleanup`, `SandboxGrants.h > RequestGrantMetadataPreservation`
### SandboxProcess.h
- `SandboxProcess.h > RunHiddenProcess` - Sandy refs: `SandboxProcess.h > RunHiddenProcessDetailed`
- `SandboxProcess.h > RunSchtasksCapture` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcessDetailed`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > LoadSavedProfile` - Sandy refs: `SandboxProfileRegistry.h > OpenSavedProfileRegistryKey`, `SandboxProfileRegistry.h > ReadSavedProfileRegistrySummary`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxRegistry.h > ReadRegSz`, `SandboxSavedProfile.h > ReadConfigFromRegistry`, `SandboxTypes.h > TokenModeName`
### SandboxToken.h
- `SandboxToken.h > ApplyDesktopGrantToObject` - Sandy refs: `SandboxACL.h > AclMutexGuard::AclMutexGuard(const std::wstring&)`, `SandboxACL.h > AclMutexGuard::AclMutexGuard(const wchar_t* fixedName)`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxToken.h > TrackDesktopGrant`
- `SandboxToken.h > RemoveDesktopSidAcesFromObject` - Sandy refs: `SandboxACL.h > AclMutexGuard::AclMutexGuard(const std::wstring&)`, `SandboxACL.h > AclMutexGuard::AclMutexGuard(const wchar_t* fixedName)`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxToken.h > BuildAclWithoutSidAces`

## Level 8 - 19 methods

### Sandbox.h
- `Sandbox.h > ApplyDenyPipelineEntry` - Sandy refs: `SandboxACL.h > DenyObjectAccess`, `Sandbox.h > RecordGrantCallback`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > AccessTag`, `SandboxTypes.h > GetSystemErrorMessage`, `SandboxACL.h > AccessMask`
- `Sandbox.h > GrantRegistryAccess` - Sandy refs: `SandboxACL.h > RegistryToWin32Path`, `SandboxACL.h > GrantObjectAccess`, `Sandbox.h > RecordGrantCallback`, `TomlAdapter.h > ParseResult::ok`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > GetSystemErrorMessage`
### SandboxACL.h
- `SandboxACL.h > RemoveSidFromDacl` - Sandy refs: `SandboxACL.h > RemoveSidFromDaclDetailed`
### SandboxCleanup.h
- `SandboxCleanup.h > BuildCleanupTaskInventory` - Sandy refs: `SandboxProcess.h > RunSchtasksCapture`, `SandboxCleanup.h > TryParseCleanupTaskNameFromCsvLine`, `SandboxRecoveryLedger.h > QueryRecoveryLedgerPresence`, `SandboxRecoveryLedger.h > RecoveryLedgerPresence::Any`
- `SandboxCleanup.h > AddLoopbackExemption` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`, `TomlAdapter.h > ParseResult::ok`
- `SandboxCleanup.h > RemoveLoopbackExemption` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`
- `SandboxCleanup.h > ForceDisableLoopback(const std::wstring& containerName)` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > ForceDisableLoopback(const std::vector<std::wstring>& containerNames)` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > SandyLogger::Log`
### SandboxDryRun.h
- `SandboxDryRun.h > HandleDryRunCreateProfile` - Sandy refs: `SandboxSavedProfile.h > ProfileExists`, `SandboxConfig.h > ReadTomlFileText`, `SandboxConfig.h > ParseConfigFileText`, `SandboxTypes.h > IsRestrictedTokenMode`, `SandboxTypes.h > IsAppContainerFamilyTokenMode`, `SandboxTypes.h > TokenModeName`, `SandboxTypes.h > AccessTag`
### SandboxGrants.h
- `SandboxGrants.h > RestoreGrantsFromKey` - Sandy refs: `SandboxRegistry.h > ReadRegSzEnum`, `SandboxGrants.h > ParseGrantRecord`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxACL.h > RemoveSidFromDaclDetailed`, `SandboxACL.h > AceRemovalResult::Succeeded`
### SandboxProcess.h
- `SandboxProcess.h > RunSchtasks` - Sandy refs: `SandboxProcess.h > GetSystemDirectoryPath`, `SandboxProcess.h > RunHiddenProcess`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > LoadProfileCreateConfig` - Sandy refs: `SandboxConfig.h > ReadTomlFileText`, `SandboxConfig.h > ParseConfigFileText`, `SandboxTypes.h > IsAppContainerFamilyTokenMode`, `SandboxTypes.h > TokenModeName`
- `SandboxSavedProfile.h > EnumSavedProfiles` - Sandy refs: `SandboxProfileRegistry.h > EnumSavedProfileRegistrySummaries`, `SandboxSavedProfile.h > LoadSavedProfile`, `SandboxTypes.h > TokenModeName`
- `SandboxSavedProfile.h > HandleProfileInfo` - Sandy refs: `SandboxSavedProfile.h > LoadSavedProfile`, `SandboxTypes.h > TokenModeName`, `SandboxTypes.h > IsRestrictedTokenMode`, `SandboxConfigRender.h > PrintResolvedConfig`
### SandboxToken.h
- `SandboxToken.h > GrantWindowStationAccess` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxToken.h > ApplyDesktopGrantToObject`
- `SandboxToken.h > GrantDefaultDesktopAccess` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `TomlAdapter.h > ParseResult::ok`, `SandboxToken.h > ApplyDesktopGrantToObject`
- `SandboxToken.h > RevokeWindowStationAccess` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxToken.h > RemoveDesktopSidAcesFromObject`
- `SandboxToken.h > RevokeDefaultDesktopAccess` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `TomlAdapter.h > ParseResult::ok`, `SandboxToken.h > RemoveDesktopSidAcesFromObject`
### sandy.cpp
- `sandy.cpp > LoadConfiguredSandbox` - Sandy refs: `SandboxConfig.h > ParseConfig`, `SandboxConfig.h > LoadConfig`

## Level 9 - 16 methods

### Sandbox.h
- `Sandbox.h > ApplyAllowPipelineEntry` - Sandy refs: `Sandbox.h > IsPathUnderAny`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxACL.h > RemoveSidFromDacl`, `SandboxACL.h > GrantObjectAccess`, `Sandbox.h > RecordGrantCallback`, `SandboxTypes.h > AccessTag`, `SandboxTypes.h > GetSystemErrorMessage`, `SandboxACL.h > AccessMask`
### SandboxCleanup.h
- `SandboxCleanup.h > CreateCleanupTask` - Sandy refs: `SandboxCleanup.h > CleanupTaskName`, `SandboxProcess.h > RunSchtasks`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > DeleteCleanupTask` - Sandy refs: `SandboxCleanup.h > CleanupTaskName`, `SandboxProcess.h > RunSchtasks`, `SandboxTypes.h > SandyLogger::Log`
- `SandboxCleanup.h > DeleteStaleCleanupTasks` - Sandy refs: `SandboxCleanup.h > BuildCleanupTaskInventory`, `SandboxProcess.h > RunSchtasks`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxCleanup.h > EnableRunLoopback` - Sandy refs: `SandboxCleanup.h > AddLoopbackExemption`
- `SandboxCleanup.h > EnsureProfileLoopback` - Sandy refs: `SandboxCleanup.h > AddLoopbackExemption`
- `SandboxCleanup.h > DisableLoopback` - Sandy refs: `SandboxCleanup.h > HasOtherLiveContainerUsers`, `SandboxTypes.h > SandyLogger::Log`, `SandboxCleanup.h > RemoveLoopbackExemption`
- `SandboxCleanup.h > DisableLoopbackForContainer` - Sandy refs: `SandboxCleanup.h > RemoveLoopbackExemption`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxCleanup.h > CleanupStaleStartupState` - Sandy refs: `SandboxCleanup.h > BuildSandyContainerInventory`, `SandboxCleanup.h > ForceDisableLoopback(const std::vector<std::wstring>& containerNames)`, `SandboxTypes.h > SandyLogger::Log`
### SandboxGrants.h
- `SandboxGrants.h > RevokeAllGrants` - Sandy refs: `SandboxACL.h > RemoveSidFromDacl`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxGrants.h > PreserveGrantMetadataRequested`, `SandboxTypes.h > SandyLogger::Log`, `SandboxGrants.h > ClearPersistedGrants`
- `SandboxGrants.h > RestoreStaleGrants` - Sandy refs: `SandboxGrants.h > RestoreTransientContainers`, `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxTypes.h > SandyLogger::Log`, `SandboxGrants.h > GetSavedProfileContainerNames`, `SandboxRecoveryLedger.h > GetRecoveryLedgerKey`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > PersistTransientContainerCleanup`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxRegistry.h > DeleteRegTreeBestEffort`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > TeardownPersistentProfileContainer` - Sandy refs: `SandboxCleanup.h > RemoveLoopbackExemption`, `SandboxTypes.h > AppContainerMissing`, `SandboxTypes.h > SandyLogger::LogFmt`
### SandboxStatus.h
- `SandboxStatus.h > BuildStatusSnapshot` - Sandy refs: `SandboxGrants.h > SnapshotGrantLedgers`, `SandboxGrants.h > SnapshotTransientContainerLedgers`, `SandboxCleanup.h > BuildCleanupTaskInventory`, `SandboxCleanup.h > BuildSandyContainerInventory`, `SandboxSavedProfile.h > EnumSavedProfiles`
### SandboxToken.h
- `SandboxToken.h > GrantDesktopAccess` - Sandy refs: `SandboxToken.h > DesktopGrantSidStringOrEmpty`, `SandboxToken.h > GrantWindowStationAccess`, `SandboxToken.h > GrantDefaultDesktopAccess`
- `SandboxToken.h > RevokeDesktopAccess` - Sandy refs: `TomlAdapter.h > ParseResult::ok`, `SandboxToken.h > RevokeDefaultDesktopAccess`, `SandboxToken.h > RevokeWindowStationAccess`
- `SandboxToken.h > RevokeDesktopAccessForSid` - Sandy refs: `SandboxToken.h > RevokeWindowStationAccess`, `SandboxToken.h > RevokeDefaultDesktopAccess`

## Level 10 - 9 methods

### Sandbox.h
- `Sandbox.h > ExecuteAccessPipeline` - Sandy refs: `Sandbox.h > SidToStringOrEmpty`, `TomlAdapter.h > ParseResult::ok`, `Sandbox.h > ApplyDenyPipelineEntry`, `Sandbox.h > ApplyAllowPipelineEntry`
- `Sandbox.h > EnsureRestrictedDesktopAccess` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `SandboxToken.h > GrantDesktopAccess`, `SandboxGuard.h > SandboxGuard::Add`, `SandboxToken.h > RevokeDesktopAccess`
- `Sandbox.h > EnsureAppContainerLoopback` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `TomlAdapter.h > ParseResult::ok`, `SandboxCleanup.h > EnableRunLoopback`, `SandboxGuard.h > SandboxGuard::Add`, `SandboxCleanup.h > DisableLoopback`
### SandboxCleanup.h
- `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun` - Sandy refs: `SandboxRecoveryLedger.h > ShouldRetainCleanupTask`, `SandboxGrants.h > DeferredCleanupRequested`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxCleanup.h > CleanupTaskName`, `SandboxCleanup.h > DeleteCleanupTask`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > RollbackProfileCreateHostState` - Sandy refs: `SandboxToken.h > RevokeDesktopAccessForSid`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxSavedProfile.h > TeardownPersistentProfileContainer`, `SandboxSavedProfile.h > ClearTrackedAclGrantInventory`
- `SandboxSavedProfile.h > CleanupStagingProfileDesktop` - Sandy refs: `SandboxRegistry.h > ReadRegSz`, `SandboxRegistry.h > ReadRegDword`, `TomlAdapter.h > ParseResult::ok`, `SandboxToken.h > RevokeDesktopAccessForSid`, `SandboxTypes.h > SandyLogger::LogFmt`
- `SandboxSavedProfile.h > CleanupStagingProfileContainer` - Sandy refs: `SandboxRegistry.h > ReadRegSz`, `SandboxSavedProfile.h > TeardownPersistentProfileContainer`
- `SandboxSavedProfile.h > HandleDeleteProfile` - Sandy refs: `SandboxProfileRegistry.h > OpenSavedProfileRegistryKey`, `SandboxProfileRegistry.h > ReadSavedProfileRegistrySummary`, `SandboxGrants.h > GetLiveProfileNames`, `SandboxTypes.h > NormalizeLookupKey`, `SandboxGrants.h > GetLiveContainerNames`, `SandboxSavedProfile.h > ReadStagingPidAndCtime`, `SandboxGrants.h > IsProcessAlive`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxToken.h > RevokeDesktopAccessForSid`, `SandboxCleanup.h > DisableLoopbackForContainer`, `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxSavedProfile.h > TeardownPersistentProfileContainer`, `SandboxSavedProfile.h > DeleteProfileRegistryState`
### SandboxStatus.h
- `SandboxStatus.h > HandleStatus` - Sandy refs: `SandboxStatus.h > BuildStatusSnapshot`, `SandboxStatus.h > PrintStatusJson`, `SandboxStatus.h > PrintStatusText`

## Level 11 - 6 methods

### Sandbox.h
- `Sandbox.h > ApplyAccessPipeline` - Sandy refs: `Sandbox.h > BuildAccessPipeline`, `Sandbox.h > LogAccessPipelinePlan`, `Sandbox.h > ExecuteAccessPipeline`
- `Sandbox.h > AbortBeforeLaunch` - Sandy refs: `SandboxGrants.h > TeardownTransientContainerForCurrentRun`, `SandboxGuard.h > SandboxGuard::RunAll`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::Stop`
- `Sandbox.h > AbortAfterChildLaunch` - Sandy refs: `SandboxProcess.h > AbortLaunchedChild`, `SandboxGrants.h > TeardownTransientContainerForCurrentRun`, `SandboxGuard.h > SandboxGuard::RunAll`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::Stop`
- `Sandbox.h > FinalizeCompletedRun` - Sandy refs: `Sandbox.h > LogChildExitClassification`, `SandboxProcess.h > ReleaseLaunchedChildHandles`, `SandboxTypes.h > SandyLogger::Log`, `SandboxGrants.h > TeardownTransientContainerForCurrentRun`, `SandboxGuard.h > SandboxGuard::RunAll`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxTypes.h > SandyLogger::Stop`, `Sandbox.h > MapChildExitToSandyExit`
- `Sandbox.h > CleanupSandbox` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `Sandbox.h > SnapshotEmergencyCleanupState`, `SandboxProcess.h > WaitForJobTreeExit`, `SandboxTypes.h > SandyLogger::Stop`, `SandboxToken.h > RevokeDesktopAccess`, `SandboxGrants.h > RevokeAllGrants`, `SandboxCleanup.h > DisableLoopback`, `SandboxGrants.h > TeardownTransientContainerForCurrentRun`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`, `Sandbox.h > ResetEmergencyCleanupState`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > RollbackStagingProfileHostState` - Sandy refs: `SandboxGrants.h > RestoreGrantsFromKey`, `SandboxSavedProfile.h > CleanupStagingProfileDesktop`, `SandboxSavedProfile.h > CleanupStagingProfileContainer`

## Level 12 - 5 methods

### Sandbox.h
- `Sandbox.h > ApplyRunOwnedGrantPhase` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `SandboxGrants.h > InitializeRunLedger`, `SandboxCleanup.h > CreateCleanupTask`, `SandboxGrants.h > ResetGrantTrackingHealth`, `SandboxGuard.h > SandboxGuard::Add`, `SandboxGrants.h > RevokeAllGrants`, `Sandbox.h > ApplyAccessPipeline`, `Sandbox.h > GrantRegistryAccess`, `SandboxGrants.h > GrantTrackingHealthy`, `SandboxTypes.h > SandyLogger::LogFmt`
- `Sandbox.h > HandleLaunchFailure` - Sandy refs: `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogSummary`, `Sandbox.h > AbortBeforeLaunch`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > ApplyProfileCreateGrantPhase` - Sandy refs: `SandboxGrants.h > BeginStagingGrantCapture`, `Sandbox.h > ApplyAccessPipeline`, `Sandbox.h > GrantRegistryAccess`, `SandboxCleanup.h > EnsureProfileLoopback`, `SandboxTypes.h > SandyLogger::Log`, `SandboxToken.h > GrantDesktopAccess`, `SandboxGrants.h > GrantTrackingHealthy`, `SandboxGrants.h > AbortStagingGrantCapture`, `TomlAdapter.h > ParseResult::ok`, `SandboxGrants.h > EndStagingGrantCapture`
- `SandboxSavedProfile.h > RollbackStagingProfile` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxProfileRegistry.h > OpenSavedProfileRegistryKey`, `SandboxSavedProfile.h > RollbackStagingProfileHostState`, `SandboxSavedProfile.h > LogIncompleteStagingRollback`, `SandboxSavedProfile.h > FinalizeStagingRollbackMetadata`
### sandy.cpp
- `sandy.cpp > ConsoleCtrlHandler` - Sandy refs: `SandboxTypes.h > SandyLogger::LogFmt`, `Sandbox.h > CleanupSandbox`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::Stop`

## Level 13 - 3 methods

### Sandbox.h
- `Sandbox.h > RunPipeline` - Sandy refs: `Sandbox.h > ResolveRunIdentity`, `Sandbox.h > ConfigureEmergencyCleanupState`, `SandboxTypes.h > SandyLogger::LogFmt`, `Sandbox.h > ApplyRunOwnedGrantPhase`, `Sandbox.h > AbortBeforeLaunch`, `Sandbox.h > EnsureRestrictedDesktopAccess`, `Sandbox.h > EnsureAppContainerLoopback`, `Sandbox.h > PrepareLaunchState`, `SandboxTypes.h > SandyLogger::LogConfig`, `Sandbox.h > ValidateRestrictedTokenIntegrity`, `Sandbox.h > CloseLaunchStdinHandle`, `Sandbox.h > StartManagedChild`, `Sandbox.h > HandleLaunchFailure`, `SandboxTypes.h > SandyLogger::Log`, `Sandbox.h > AbortAfterChildLaunch`, `Sandbox.h > WaitForManagedChild`, `Sandbox.h > FinalizeCompletedRun`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > HandleCreateProfile` - Sandy refs: `SandboxSavedProfile.h > ValidateProfileCreateName`, `SandboxSavedProfile.h > LoadProfileCreateConfig`, `SandboxSavedProfile.h > BeginProfileCreationTransaction`, `SandboxSavedProfile.h > CreateProfileIdentity`, `SandboxSavedProfile.h > DeleteProfileRegistryState`, `SandboxSavedProfile.h > PersistProfileCreateIdentity`, `SandboxSavedProfile.h > AbortUncommittedProfileCreation`, `SandboxSavedProfile.h > ApplyProfileCreateGrantPhase`, `TomlAdapter.h > ParseResult::ok`, `SandboxSavedProfile.h > RollbackProfileCreateHostState`, `SandboxSavedProfile.h > FinalizeProfileCreateRollback`, `SandboxSavedProfile.h > FreeProfileCreateSid`, `SandboxSavedProfile.h > CommitCreatedProfile`, `SandboxSavedProfile.h > ClearTrackedAclGrantInventory`, `SandboxSavedProfile.h > PrintCreatedProfileSummary`
- `SandboxSavedProfile.h > CleanStagingProfiles` - Sandy refs: `SandboxSavedProfile.h > CollectRollbackEligibleStagingProfiles`, `SandboxSavedProfile.h > RollbackStagingProfile`

## Level 14 - 3 methods

### Sandbox.h
- `Sandbox.h > BeginRunSession` - Sandy refs: `SandboxGrants.h > ResetGrantMetadataPreservation`, `SandboxGrants.h > ResetDeferredCleanupRequest`, `SandboxCleanup.h > CleanupStaleStartupState`, `SandboxSavedProfile.h > CleanStagingProfiles`, `SandboxGrants.h > RestoreStaleGrants`, `SandboxCleanup.h > DeleteStaleCleanupTasks`, `SandboxCleanup.h > WarnStaleRegistryEntries`, `SandboxCleanup.h > LogSandyIdentity`, `SandboxTypes.h > SandyLogger::Log`
### SandboxStatus.h
- `SandboxStatus.h > HandleCleanup` - Sandy refs: `SandboxCleanup.h > BuildSandyContainerInventory`, `SandboxCleanup.h > ForceDisableLoopback(const std::vector<std::wstring>& containerNames)`, `SandboxGrants.h > RestoreStaleGrants`, `SandboxSavedProfile.h > CleanStagingProfiles`, `SandboxCleanup.h > DeleteStaleCleanupTasks`, `SandboxGrants.h > DeleteTransientContainerNow`, `SandboxGrants.h > ClearTransientContainerCleanupByContainerName`, `SandboxGrants.h > PersistTransientContainerCleanupForOrphanedContainer`, `SandboxRegistry.h > DeleteRegTreeIfExists`
### sandy.cpp
- `sandy.cpp > RunCreateProfileMode` - Sandy refs: `SandboxCLI.h > PrintUsage`, `SandboxTypes.h > SandyLogger::Start`, `SandboxDryRun.h > HandleDryRunCreateProfile`, `SandboxSavedProfile.h > HandleCreateProfile`, `SandboxTypes.h > SandyLogger::Stop`

## Level 15 - 3 methods

### Sandbox.h
- `Sandbox.h > RunSandboxed` - Sandy refs: `Sandbox.h > ResetEmergencyCleanupState`, `SandboxTypes.h > GenerateInstanceId`, `SandboxConfig.h > GetInheritedWorkdir`, `Sandbox.h > BeginRunSession`, `SandboxTypes.h > ContainerNameFromId`, `Sandbox.h > RunPipeline`
### SandboxSavedProfile.h
- `SandboxSavedProfile.h > RunWithProfile` - Sandy refs: `Sandbox.h > ResetEmergencyCleanupState`, `SandboxTypes.h > GenerateInstanceId`, `SandboxConfig.h > GetInheritedWorkdir`, `Sandbox.h > BeginRunSession`, `SandboxTypes.h > SandyLogger::Log`, `SandboxTypes.h > SandyLogger::LogFmt`, `SandboxCleanup.h > DeleteCleanupTask`, `SandboxToken.h > CreateRestrictedSandboxToken`, `SandboxGrants.h > PersistLiveState`, `SandboxCleanup.h > CreateCleanupTask`, `Sandbox.h > RunPipeline`, `SandboxGrants.h > ClearLiveState`, `SandboxCleanup.h > FinalizeCleanupTaskForCurrentRun`
### sandy.cpp
- `sandy.cpp > HandleStandaloneCliAction` - Sandy refs: `SandboxCLI.h > PrintUsage`, `SandboxCLI.h > PrintContainerToml`, `SandboxCLI.h > PrintRestrictedToml`, `SandboxStatus.h > HandleCleanup`

## Level 16 - 3 methods

### sandy.cpp
- `sandy.cpp > HandleImmediateCliAction` - Sandy refs: `sandy.cpp > HandleStandaloneCliAction`, `SandboxStatus.h > HandleStatus`, `SandboxStatus.h > HandleExplain`, `SandboxSavedProfile.h > HandleProfileInfo`, `SandboxSavedProfile.h > HandleDeleteProfile`
- `sandy.cpp > RunSavedProfileMode` - Sandy refs: `SandboxCLI.h > PrintUsage`, `SandboxSavedProfile.h > CleanStagingProfiles`, `SandboxSavedProfile.h > LoadSavedProfile`, `SandboxTypes.h > SandyLogger::Start`, `SandboxSavedProfile.h > RunWithProfile`, `SandboxTypes.h > SandyLogger::Stop`
- `sandy.cpp > RunConfigDrivenMode` - Sandy refs: `SandboxCLI.h > PrintUsage`, `sandy.cpp > StampLogPath`, `SandboxTypes.h > SandyLogger::Start`, `sandy.cpp > LoadConfiguredSandbox`, `SandboxDryRun.h > HandlePrintConfig`, `SandboxDryRun.h > HandleDryRun`, `Sandbox.h > RunSandboxed`

## Level 17 - 1 method

### sandy.cpp
- `sandy.cpp > RunMain` - Sandy refs: `sandy.cpp > HandleImmediateCliAction`, `sandy.cpp > ParseRunMainOptions`, `sandy.cpp > RunCreateProfileMode`, `sandy.cpp > RunSavedProfileMode`, `sandy.cpp > RunConfigDrivenMode`

## Level 18 - 1 method

### sandy.cpp
- `sandy.cpp > wmain` - Sandy refs: `sandy.cpp > ConsoleCtrlHandler`, `sandy.cpp > RunMain`, `SandboxTypes.h > SandyLogger::LogFmt`, `Sandbox.h > CleanupSandbox`
