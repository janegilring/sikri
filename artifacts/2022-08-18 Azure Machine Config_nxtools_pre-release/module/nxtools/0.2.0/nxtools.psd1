@{

    # Script module or binary module file associated with this manifest.
    RootModule           = 'nxtools.psm1'

    # Version number of this module.
    ModuleVersion        = '0.2.0'

    # Supported PSEditions
    CompatiblePSEditions = @('Core')

    # ID used to uniquely identify this module
    GUID                 = 'b3f15f9d-94f2-44ce-8491-6a5dbb585c44'

    # Author of this module
    Author               = 'Gael Colas'

    # Company or vendor of this module
    CompanyName          = 'Microsoft'

    # Copyright statement for this module
    Copyright            = '(c) Microsoft. All rights reserved.'

    # Description of the functionality provided by this module
    Description          = 'Collection of Posix tools wrappers.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '6.2'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # ClrVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @()

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport    = @('Compress-nxArchive','Expand-nxArchive','Add-nxFileLine','Invoke-nxFileContentReplace','Remove-nxFileLine','Compare-nxMode','Get-nxChildItem','Get-nxItem','Set-nxGroupOwnership','Set-nxMode','Set-nxOwner','Find-nxAptPackageFromCache','Install-nxAptPackage','Remove-nxAptPackage','Update-nxAptPackageCache','Get-nxDpkgPackage','Get-nxDpkgPackageInstalled','Find-nxYumPackage','Get-nxYumPackage','Get-nxYumPackageInstalled','Install-nxYumPackage','Remove-nxYumPackage','Find-nxPackage','Get-nxPackage','Get-nxPackageInstalled','Get-nxSupportedPackageType','Install-nxPackage','Remove-nxPackage','Disable-nxService','Enable-nxService','Get-nxService','Restart-nxService','Start-nxService','Stop-nxService','Get-nxDistributionInfo','Get-nxKernelInfo','Get-nxLinuxStandardBaseRelease','Add-nxLocalGroupMember','Add-nxLocalUserToGroup','Disable-nxLocalUser','Enable-nxLocalUser','Get-nxEtcShadow','Get-nxLocalGroup','Get-nxLocalUser','Get-nxLocalUserMemberOf','New-nxLocalGroup','New-nxLocalUser','Remove-nxLocalGroup','Remove-nxLocalGroupMember','Remove-nxLocalUser','Set-nxLocalGroup','Set-nxLocalGroupGID','Set-nxLocalGroupMember','Set-nxLocalUser')

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = ''

    # Variables to export from this module
    VariablesToExport    = ''

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = '*'

    # DSC resources to export from this module
    DscResourcesToExport = @('nxFile','nxGroup','nxUser','nxPackage','nxFileLine','nxFileContentReplace','nxService','GC_LinuxGroup','GC_msid110','GC_msid121','GC_msid232','GC_InstalledApplicationLinux','GC_NotInstalledApplicationLinux','GC_LinuxLogAnalyticsAgent')

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    # FileList = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('linux', 'sysadmin', 'helper')

            # A URL to the license for this module.
            LicenseUri   = 'https://github.com/Azure/nxtools/blob/main/LICENSE'

            # A URL to the main website for this project.
            ProjectUri   = 'https://github.com/Azure/nxtools/'

            # A URL to an icon representing this module.
            IconUri      = ''

            # ReleaseNotes of this module
            ReleaseNotes = '## [0.2.0-fix0001] - 2022-08-17

### Added

- Added KitchenCI tests for the packages on ubuntu-18.04, debian-10, and centos-7.5.
- Added the `Functions` test suite for Kitchen-Pester.
- Added `[nxFileLine]` and `[nxFileContentReplace]` DSC Resources to manage file content.
- Added examples for DSC Resources.
- Added GC Packages to the GitHub release publish step.
- Added cmdlets for Packages:
    - `Get-nxPackageInstalled`: Getting the installed package basic info, automatically finding the Package Manager.
    - `Get-nxYumPackageInstalled`: Getting the installed yum/rpm package basic info.
    - `Get-nxDpkgPackageInstalled`: Getting the installed dpkg/apt package basic info.
    - `Get-nxPackage`: Getting the installed package detailed info, automatically finding the Package Manager.
    - `Get-nxYumPackage`: Getting the installed yum/rpm package detailed info.
    - `Get-nxDpkgPackage`: Getting the installed dpkg/apt package detailed info.

- Added the DSC Resources classes
    - `nxUser`
    - `nxGroup`
    - `nxFile`
    - `nxArchive`
    - `nxPackage`
    - `nxFileLine`
    - `nxFileContentReplace`

- Added GC policy config for creating GC packages
    - InstalledApplicationLinux
    - NotInstalledApplicationLinux
    - linuxGroupsMustExclude
    - linuxGroupsMustInclude
    - msid110
    - msid121
    - msid232

### Fixed

- Fixed the issue on centos/red hat where the MODE contains a trailing `.`.
- Fixed HQRM style non-compliance.

### Removed

- Disabling changelog tests because of the way the private repo fetches and errors on the `git diff`.

'

            # Prerelease string of this module
            Prerelease   = 'fix0001'

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    DefaultCommandPrefix = ''

}
