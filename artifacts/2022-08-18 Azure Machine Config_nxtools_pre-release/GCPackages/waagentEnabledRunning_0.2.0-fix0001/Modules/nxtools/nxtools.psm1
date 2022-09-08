using namespace System.Collections
#Region '.\prefix.ps1' 0
Import-Module -Name $PSScriptRoot\Modules\PSNativeCmdDevKit -ErrorAction Stop
Import-Module -Name $PSScriptRoot\Modules\DscResource.Common -ErrorAction Stop
#EndRegion '.\prefix.ps1' 3
#Region '.\Enum\1.Ensure.ps1' 0
enum Ensure
{
    Absent
    Present
}
#EndRegion '.\Enum\1.Ensure.ps1' 6
#Region '.\Enum\nxArchiveAlgorithm.ps1' 0
enum nxArchiveAlgorithm
{
    auto
    bzip2
    xz
    lzma
    gzip
}
#EndRegion '.\Enum\nxArchiveAlgorithm.ps1' 9
#Region '.\Enum\nxFileLineAddMode.ps1' 0
enum nxFileLineAddMode
{
    Append
    AfterLinePatternMatch
    BeforeLinePatternMatch
}
#EndRegion '.\Enum\nxFileLineAddMode.ps1' 7
#Region '.\Enum\nxFileSystemAccessRight.ps1' 0

[Flags()]
enum nxFileSystemAccessRight
{
    Read    = 4
    Write   = 2
    Execute = 1
    None    = 0
}
#EndRegion '.\Enum\nxFileSystemAccessRight.ps1' 10
#Region '.\Enum\nxFileSystemItemType.ps1' 0
enum nxFileSystemItemType
{
    File
    Directory
    Link
    Pipe
    Socket
}
#EndRegion '.\Enum\nxFileSystemItemType.ps1' 9
#Region '.\Enum\nxFileSystemSpecialMode.ps1' 0

[Flags()]
enum nxFileSystemSpecialMode
{
    SetUserId  = 4 # S_ISUID: Set user ID on execution
    SetGroupId = 2 # S_ISVTX: Set group ID on execution
    StickyBit  = 1 # S_ISVTX: Sticky bit
    None       = 0
}
#EndRegion '.\Enum\nxFileSystemSpecialMode.ps1' 10
#Region '.\Enum\nxFileSystemUserClass.ps1' 0
[Flags()]
enum nxFileSystemUserClass
{
    User   = 4 # u
    Group  = 2 # g
    Others = 1 # o
}
#EndRegion '.\Enum\nxFileSystemUserClass.ps1' 8
#Region '.\Enum\nxInitSystem.ps1' 0
enum nxInitSystem
{
    systemd
    initd
    sysvinit
    busybox
    unknown
}
#EndRegion '.\Enum\nxInitSystem.ps1' 9
#Region '.\Enum\nxServiceState.ps1' 0
enum nxServiceState
{
    Running
    Stopped
}
#EndRegion '.\Enum\nxServiceState.ps1' 6
#Region '.\Enum\nxSupportedPackageType.ps1' 0
enum nxSupportedPackageType
{
    dpkg
    yum
    # dnf
    # rpm
    apt
    # zypper
    # snap
}
#EndRegion '.\Enum\nxSupportedPackageType.ps1' 11
#Region '.\Classes\nxEtcShadowEntry.ps1' 0
class nxEtcShadowEntry
{
    hidden static [regex] $EtcShadowLineParser = @(
        '^(?<username>[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$))'
        '(?<password>[^:]*)'
        '(?<lastchanged>[^:]*)'
        '(?<min>[^:]*)'
        '(?<max>[^:]*)'
        '(?<warn>[^:]*)'
        '(?<inactive>[^:]*)'
        '(?<expire>[^:]*)'
        '(?<other>[^:]*)'
    ) -join ':'

    hidden [string] $ShadowEntry
    [string] $Username
    [string] $EncryptedPassword # as in the Shadow file
    [datetime] $PasswordLastChanged
    [int] $MinimumPasswordAgeInDays
    [int] $MaximumPasswordAgeInDays
    [int] $PasswordAgeWarningPeriodInDays
    [int] $PasswordInactivityPeriodInDays
    [System.Nullable[datetime]] $AccountExipreOn
    [string] $ReservedField

    nxEtcShadowEntry()
    {
        # default ctor
    }

    nxEtcShadowEntry([string] $EtcShadowEntry)
    {
        Write-Debug -Message "[nxEtcShadowEntry] Parsing '$_'."
        if ($EtcShadowEntry -notmatch [nxEtcShadowEntry]::EtcShadowLineParser)
        {
            throw "Unrecognised passwd entry: '$EtcShadowEntry'."
        }

        $this.ShadowEntry = $EtcShadowEntry
        $this.Username = $Matches.username
        $this.EncryptedPassword = $Matches.password
        $this.PasswordLastChanged = ([datetime]'1/1/1970').AddDays($Matches.lastchanged)
        $this.MinimumPasswordAgeInDays = $Matches.min
        $this.MaximumPasswordAgeInDays = $Matches.max
        $this.PasswordAgeWarningPeriodInDays = $Matches.warn
        $this.PasswordInactivityPeriodInDays = $Matches.inactive
        if ($Matches.expire)
        {
            $this.AccountExipreOn = ([datetime]'1/1/1970').AddDays($Matches.expire)
        }

        $this.ReservedField = $Matches.other

        $this | Add-Member -MemberType ScriptProperty -Name 'PasswordLocked' -Value {
            $this.IsPasswordLocked()
        }
    }

    [System.String] ToString()
    {
        return ($this.ShadowEntry)
    }

    [bool] IsPasswordLocked()
    {
        if ($this.EncryptedPassword -match '^!')
        {
            return $true
        }
        else
        {
            return $false
        }
    }
}
#EndRegion '.\Classes\nxEtcShadowEntry.ps1' 76
#Region '.\Classes\nxFileSystemInfo.ps1' 0

class nxFileSystemInfo : System.IO.FileSystemInfo
{
    [nxFileSystemMode] $Mode
    [nxFileSystemItemType] $nxFileSystemItemType
    [int] $nxLinkCount
    [System.String] $nxOwner
    [System.String] $nxGroup
    [long] $Length

    [string] $Name
    [datetime] $LastWriteTime

    nxFileSystemInfo ([System.Collections.IDictionary]$properties)
    {
        Write-Verbose -Message "Creating [nxFileSystemInfo] with path '$($properties.FullPath)'."
        $this.OriginalPath = $properties.FullPath
        $this.FullPath = $properties.FullPath
        $this.SetPropertiesFromIDictionary($properties)
        $this.Name = [System.Io.Path]::GetFileName($this.FullPath)
    }

    hidden [void] SetPropertiesFromIDictionary ([System.Collections.IDictionary]$properties)
    {
        Write-Verbose -Message "Setting Propeties from Dictionary."

        $properties.keys.Foreach{
            if ($this.psobject.Properties.name -contains $_)
            {
                try
                {
                    Write-Debug -Message "`tAdding '$_' with value '$($properties[$_])'."
                    $this.($_) = $properties[$_]
                }
                catch
                {
                    Write-Warning -Message $_.Exception.Message
                }
            }
            else
            {
                Write-Verbose -Message "The key '$_' is not a property."
            }
        }
    }

    nxFileSystemInfo([string]$Path)
    {
        # ctor
        $this.OriginalPath = $Path
        $this.FullPath = [System.IO.Path]::GetFullPath($Path)
        $this.Name = [System.Io.Path]::GetFileName($this.FullPath)
    }

    [void] Delete()
    {
        Remove-Item -Path $this.FullName -ErrorAction Stop
        $this.Dispose()
    }

    hidden [string] GetModeWithItemType()
    {
        $modeSymbol = $this.Mode.ToString()
        $typeSymbol = switch ($this.nxFileSystemItemType)
        {
            ([nxFileSystemItemType]::File) { '-' }
            ([nxFileSystemItemType]::Directory) { 'd' }
            ([nxFileSystemItemType]::Link) { 'l' }
            ([nxFileSystemItemType]::Socket) { 's' }
            ([nxFileSystemItemType]::Pipe) { 'p' }
        }

        return ('{0}{1}' -f $typeSymbol,$modeSymbol)
    }
}
#EndRegion '.\Classes\nxFileSystemInfo.ps1' 76
#Region '.\Classes\nxFileSystemMode.ps1' 0
class nxFileSystemMode
{
    hidden static [string] $SymbolicTriadParser = '^[-dlsp]?(?<User>[-wrxsStT]{3})(?<Group>[-wrxsStT]{3})(?<Others>[-wrxsStT]{3})\.?$'
    hidden static [string] $SymbolicOperationParser = '^(?<userClass>[ugoa]{1,3})(?<operator>[\-\+\=]{1})(?<permissions>[wrxTtSs-]{1,3})$'
    [nxFileSystemSpecialMode]  $SpecialModeFlags
    [nxFileSystemAccessRight]  $OwnerMode
    [nxFileSystemAccessRight]  $GroupMode
    [nxFileSystemAccessRight]  $OthersMode

    nxFileSystemMode()
    {
        # default ctor, can be used like this:
        <#
            [nxFileSystemMode]@{
                SpecialModeFlags = 'None'
                OwnerMode  = 'Read, Write, Execute'
                GroupMode  = 'Read, Execute'
                OthersMode = 7
            }
        #>
    }

    nxFileSystemMode([String]$Modes)
    {
        if ($Modes -match '^\d{3,4}$')
        {
            # Convert from Int to nxFileSystemAccessRight
            $this.setNxFileSystemModeFromInt([int]::Parse($Modes))
        }
        elseif ($Modes -cmatch [nxFileSystemMode]::SymbolicTriadParser)
        {
            $this.setNxFileSystemModeFromSymbolicTriadNotation($Modes)
        }
        elseif (-not ($Modes -split '\s+').Where{$_ -cnotmatch [nxFileSystemMode]::SymbolicOperationParser})
        {
            # All items of the space delimited Symbolic operations have been checked.
            $this.DoSymbolicChmodOperation($Modes)
        }
        else
        {
            throw "The symbolic string '$Modes' is invalid."
        }
    }

    nxFileSystemMode([int]$Modes)
    {
        $this.setNxFileSystemModeFromInt($Modes)
    }

    hidden [void] setNxFileSystemModeFromSymbolicTriadNotation([string]$SymbolicTriad)
    {
        $null = $SymbolicTriad -cmatch [nxFileSystemMode]::SymbolicTriadParser

        $this.DoSymbolicChmodOperation(@(
            ('u=' + $Matches['User'])
            ('g=' + $Matches['Group'])
            ('o=' + $Matches['Others'])
        ) -join ' ')
    }

    hidden [void] setNxFileSystemModeFromInt([Int]$Modes)
    {
        # Adding leading 0s to ensure we have a 0 for the special flags i.e. 777 -> 0777
        $StringMode = "{0:0000}" -f $Modes
        Write-Debug -Message "Trying to parse the permission set expressed by '$($Modes)'."

        if ($StringMode.Length -gt 4)
        {
            throw "Mode set should be expressed with 4 or 3 digits (you can omit the one on the left): setuid(4)/setgid(2)/sticky bit(1)|Owner|Group|Others). '$($StringMode)'"
        }

        Write-Debug -Message "Parsing Special Mode Flags: $([int]::Parse($StringMode[0]))"
        $this.SpecialModeFlags = [int]::Parse($StringMode[0])
        $this.OwnerMode  = [int]::Parse($StringMode[1])
        $this.GroupMode  = [int]::Parse($StringMode[2])
        $this.OthersMode = [int]::Parse($StringMode[3])
    }

    [void] DoChmodOperation ([nxFileSystemUserClass]$UserClass, [char]$Operator, [nxFileSystemAccessRight]$AccessRights, [nxFileSystemSpecialMode]$SpecialMode)
    {
        switch ($operator)
        {
            '=' {
                $this.SetMode($userClass, $accessRights, $specialMode)
            }

            '+'
            {
                $this.AddMode($userClass, $accessRights, $specialMode)
            }

            '-'
            {
                $this.RemoveMode($userClass, $accessRights, $specialMode)
            }

            default
            {
                throw "Operator not recognised '$operator'."
            }
        }
    }

    [void] DoSymbolicChmodOperation ([string]$SymbolicChmodString)
    {
        $symbolicChmodList = $SymbolicChmodString -split '\s+'

        foreach ($symbolicChmodStringItem in $symbolicChmodList)
        {
            Write-Debug -Message "Doing Symbolic Operation '$symbolicChmodStringItem'."
            if ($symbolicChmodStringItem -match [nxFileSystemMode]::SymbolicOperationParser)
            {
                $userClassChars = $Matches['userClass']
                $operator       = $Matches['operator']
                $permissions    = $Matches['permissions']
                $userClass      = [nxFileSystemUserClass](Convert-nxSymbolToFileSystemUserClass -Char $userClassChars)
                Write-Debug -Message "Parsing $permissions"
                $specialMode    = [nxFileSystemSpecialMode](Convert-nxSymbolToFileSystemSpecialMode -SpecialModeSymbol $permissions -UserClass $UserClass)
                $accessRights   = [nxFileSystemAccessRight](Convert-nxSymbolToFileSystemAccessRight -AccessRightSymbol $permissions)

                $this.DoChmodOperation($userClass, $operator, $accessRights, $specialMode)
            }
        }
    }

    [void] SetMode ([nxFileSystemUserClass]$UserClass, [nxFileSystemAccessRight]$AccessRights, [nxFileSystemSpecialMode]$SpecialMode)
    {
        Write-Debug -Message "Setting rights '$($AccessRights)' and special flag '$($SpecialMode)' to '$($UserClass)'"
        switch ($UserClass)
        {
            { $_ -band [nxFileSystemUserClass]::User } {
                $this.OwnerMode = $AccessRights
            }

            { $_ -band [nxFileSystemUserClass]::Group } {
                $this.GroupMode = $AccessRights
            }

            { $_ -band [nxFileSystemUserClass]::Others } {
                $this.OthersMode = $AccessRights
            }

            default {
                throw "Error with unrecognized User Class '$UserClass'."
            }
        }

        $this.SpecialModeFlags = $SpecialMode
    }

    [void] AddMode ([nxFileSystemUserClass]$UserClass, [nxFileSystemAccessRight]$AccessRights, [nxFileSystemSpecialMode]$SpecialMode)
    {
        Write-Debug -Message "Adding rights '$($AccessRights)' and special flag '$($SpecialMode)' to '$($UserClass)'"
        switch ($UserClass)
        {
            { $_ -band [nxFileSystemUserClass]::User } {
                $this.OwnerMode = $this.OwnerMode -bor $AccessRights
            }

            { $_ -band [nxFileSystemUserClass]::Group } {
                $this.GroupMode = $this.GroupMode -bor $AccessRights
            }

            { $_ -band [nxFileSystemUserClass]::Others } {
                $this.OthersMode = $this.OthersMode -bor $AccessRights
            }

            default {
                throw "Error with unrecognized User Class '$UserClass'."
            }
        }

        $this.SpecialModeFlags = $this.SpecialModeFlags -bor $SpecialMode
    }

    [void] RemoveMode ([nxFileSystemUserClass]$UserClass, [nxFileSystemAccessRight]$AccessRights, [nxFileSystemSpecialMode]$SpecialMode)
    {
        Write-Debug -Message "Removing rights '$($AccessRights)' and special flag '$($SpecialMode)' to '$($UserClass)'"
        switch ($UserClass)
        {
            { $_ -band [nxFileSystemUserClass]::User } {
                $this.OwnerMode = $this.OwnerMode -band -bnot $AccessRights
            }

            { $_ -band [nxFileSystemUserClass]::Group } {
                $this.GroupMode = $this.GroupMode -band -bnot $AccessRights
            }

            { $_ -band [nxFileSystemUserClass]::Others } {
                $this.OthersMode = $this.OthersMode -band -bnot $AccessRights
            }

            default {
                throw "Error with unrecognized User Class '$UserClass'."
            }
        }

        $this.SpecialModeFlags = $this.SpecialModeFlags -band -bnot $SpecialMode
    }

    [string] ToString()
    {
        Write-Verbose -Message "$($this.OwnerMode)"
        Write-Verbose -Message "$(@($this.OthersMode, $this.SpecialModeFlags) -join '|')"

        $SymbolNotation = [PSCustomObject]@{
            UserClass         = [nxFileSystemUserClass]::User
            AccessRight       = $this.OwnerMode
            UseDashWhenAbsent = $true
        },
        [PSCustomObject]@{
            UserClass         = [nxFileSystemUserClass]::Group
            AccessRight       = $this.GroupMode
            UseDashWhenAbsent = $true
        },
        [PSCustomObject]@{
            UserClass         = [nxFileSystemUserClass]::User
            AccessRight       = $this.OthersMode
            UseDashWhenAbsent = $true
        } | Convert-nxFileSystemAccessRightToSymbol

        Write-Verbose -Message "SymbolNotation: $SymbolNotation"
        return ($SymbolNotation -join '')
    }

    [string] ToOctal()
    {
        return ('{0}{1}{2}{3}' -f (
            ([int]$this.SpecialModeFlags),
            ([int]$this.OwnerMode),
            ([int]$this.GroupMode),
            ([int]$this.OthersMode)
        ))
    }
}
#EndRegion '.\Classes\nxFileSystemMode.ps1' 236
#Region '.\Classes\nxLocalGroup.ps1' 0
class nxLocalGroup
{
    hidden static $GroupEntryParser = '^(?<groupname>[^:]+):(?<pwd>[^:]*):(?<gid>[\d]+):(?<members>.*)$'
    [string]    $GroupName
    [string]    $Password
    [int]       $GroupId
    [string[]]  $GroupMember

    nxLocalGroup()
    {
        # default ctor
    }

    nxLocalGroup([string]$GroupEntry)
    {
        Write-Debug -Message "[nxLocalGroup] Parsing '$_'."
        if ($groupEntry -notmatch [nxLocalGroup]::GroupEntryParser)
        {
            throw "Unrecognized Group entry from /etc/group with '($GroupEntry)'."
        }
        else
        {
            $this.GroupName = $Matches.groupname
            $this.Password  = $Matches.pwd
            $this.GroupId   = [int]::Parse($Matches.gid)
            $this.GroupMember = ($Matches.members -split ',').Where({-not [string]::IsNullOrEmpty($_)})
        }
    }

    [System.String] ToString()
    {
        return $this.GroupName
    }

    static [bool] Exists([string]$GroupName)
    {
        if (Get-nxLocalGroup -GroupName $GroupName -ErrorAction 'SilentlyContinue')
        {
            return $true
        }
        else
        {
            return $false
        }
    }
}
#EndRegion '.\Classes\nxLocalGroup.ps1' 47
#Region '.\Classes\nxLocalUser.ps1' 0
class nxLocalUser
{
    # gcolas:x:1000:1000:,,,:/home/gcolas:/bin/bash
    static [regex] $PasswordLineParser = @(
        '^(?<username>[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$))'
        '(?<password>[^:]+)'
        '(?<userid>[\d]+)'
        '(?<groupid>[\d]+)'
        '(?<userinfo>[^:]*)'
        '(?<homedir>[^:]*)'
        '(?<shellcmd>[^:]*)'
    ) -join ':'

    hidden [bool] $HasChanged = $false

    [string] $UserName
    [string] $Password
    [int]    $UserId
    [int]    $GroupId

    hidden [string] $UserInfo # GECOS field
    [string] $FullName
    [string] $Office
    [string] $OfficePhone
    [string] $HomePhone
    [string] $Description

    [string] $HomeDirectory
    [string] $ShellCommand

    nxLocalUser()
    {
        # default ctor
    }

    nxLocalUser([System.String]$passwdEntry)
    {
        Write-Debug -Message "[nxLocalUser] Parsing '$_'."
        if ($passwdEntry -notmatch [nxLocalUser]::PasswordLineParser)
        {
            throw "Unrecognised passwd entry: '$passwdEntry'."
        }

        $this.UserName = $Matches.username
        $this.Password = $Matches.password
        $this.UserId = [int]::Parse($Matches.userid)
        $this.GroupId = [int]::Parse($Matches.groupid)
        $this.UserInfo = $Matches.userinfo

        if (-not [string]::IsNullOrEmpty($this.UserInfo))
        {
            $this.LoadGecosFields()
        }

        $this.HomeDirectory = $Matches.homedir
        $this.ShellCommand = $Matches.shellcmd

        # the below script properties should probably go in the type format
        $this |
            Add-Member -PassThru -MemberType ScriptProperty -Name 'MemberOf' -Value {
                # only calling the method when needed to avoid unecessary calls
                $this.GetMemberOf()
            }|
            Add-Member -PassThru -MemberType ScriptProperty -Name 'EtcShadow' -Value {
                $this.GetEtcShadow()
            }
    }

    [void] LoadGecosFields()
    {
        $gecosFields = [nxLocalUser]::GetGecosFieldsFromUserInfo($this.UserInfo)
        $this.FullName      = $gecosFields['FullName']
        $this.Office        = $gecosFields['Office']
        $this.OfficePhone   = $gecosFields['OfficePhone']
        $this.HomePhone     = $gecosFields['HomePhone']
        $this.Description   = $gecosFields['Description']
    }

    static [hashtable] GetGecosFieldsFromUserInfo([String] $UserInfoString)
    {
        $gecosFields = $UserInfoString -split ',',5

        return @{
            FullName    = $gecosFields[0]
            Office      = $gecosFields[1]
            OfficePhone = $gecosFields[2]
            HomePhone   = $gecosFields[3]
            Description = $gecosFields[4]
        }
    }

    static [bool] Exists([string]$UserName)
    {
        try
        {
            $result = Invoke-NativeCommand -Executable 'id' -Parameters @('-u', $UserName) -ErrorAction 'Stop'
        }
        catch
        {
            Write-Debug -Message "The command 'id' returned '$_'."
            $result = $false
        }

        [int]$ParsedUserID = -1

        if ([int]::TryParse($result, [ref]$ParsedUserID))
        {
            Write-Debug -Message "User id for '$UserName' is '$result'."
            return $true
        }
        else
        {
            return $false
        }
    }

    [string] ToString()
    {
        return $this.UserName
    }

    [string] ToPasswdString()
    {
        return ('{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}' -f
            $this.UserName,
            $this.Password,
            $this.UserId,
            $this.GroupId,
            $this.UserInfo,
            $this.HomeDirectory,
            $this.ShellCommand
        )
    }

    [void] Save()
    {
        if ([nxLocalUser]::Exists($this.Username))
        {
            $this.Update()
        }
        else
        {
            $this.SaveAsNewNxLocalAccount()
        }
    }

    [void] Update()
    {
        $this | Set-nxLocalUser
    }

    [void] SaveAsNewNxLocalAccount()
    {
        $null = $this | Add-nxLocalUser -ErrorAction 'Stop'
    }

    [nxLocalGroup[]] GetMemberOf()
    {
        return (Get-nxLocalUserMemberOf -User $this.UserName).MemberOf
    }

    [nxEtcShadowEntry] GetEtcShadow()
    {
        return (Get-nxEtcShadow -UserName $this.UserName)
    }

    [bool] IsDisabled()
    {
        $shadowEntry = $this.GetEtcShadow()
        return ($shadowEntry.IsPasswordLocked() -and $shadowEntry.AccountExipreOn -le [dateTime]::Now)
    }
}
#EndRegion '.\Classes\nxLocalUser.ps1' 173
#Region '.\Classes\ValidShell.ps1' 0
class ValidShell : System.Management.Automation.IValidateSetValuesGenerator
{
    [String[]] GetValidValues()
    {
        return (Get-Content -Path '/etc/shells' -ErrorAction 'Stop' | Where-Object -FilterScript {$_ -notmatch '^#'})
    }
}
#EndRegion '.\Classes\ValidShell.ps1' 8
#Region '.\Classes\1.DscResources\01.nxFile.ps1' 0
$script:localizedDataNxFile = ConvertFrom-StringData @'
    nxFileShouldBeAbsent = The item '{0}' was found but should be 'Absent'.
    TypeMismatch = The Type for item '{0}' was expected to be '{1} but was '{2}' instead.
    ContentsMismatch = The Content of '{0}' was not as expected. {2}
    ChecksumMismatch = The DestinationPath '{0}' with checksum, '{2}' did not match the expected checksum of '{1}'.
    ModeMismatch = The mode of '{0}' did not match the expected value '{1}'. The Mode is '{2}'.
    OwnerMismatch = The expected Owner for '{0}' is '{1}' but was '{2}' instead.
    GroupMismatch = The expected Group for '{0}' is '{1}' but was '{2}' instead.
    nxItemNotFound = The Item '{0}' was not found.
    nxFileInDesiredState = The item '{0}' is in the Desired State.
    SourcePathNotFound = Source item not found at '{0}'.
    CompareChecksum = Comparing file checksum '{0}' with desired checksum '{1}'.
    CreateFile = Creating the item '{0}' as per the desired state.
    SetFile = Setting the item '{0}' as per the desired state.
    SetTypeError = The item '{0}' of type '{2}' while we desire type '{1}'. We have no way of correcting this at the moment.
    SetFileContent = Setting file content for '{0}'.
    CopySourceToDestination = Copying Source file '{0}' to Destination '{1}'.
    GetFileContent = Getting the raw content of '{0}'.
    CompareCtime = Comparing current item '{0}' ctime of '{1}' against the source '{2}'.
    CompareMtime = Comparing current item '{0}' mtime of '{1}' against the source '{2}'.
'@

[DscResource()]
class nxFile
{
    [DscProperty()]
    [Ensure] $Ensure

    [DscProperty(key)]
    [System.String] $DestinationPath

    [DscProperty()]
    [System.String] $SourcePath # Write Only

    [DscProperty()]
    [System.String] $Type = 'File' # directory | file | link

    [DscProperty()]
    [System.String] $Contents

    [DscProperty()]
    [System.String] $Checksum #  ctime | mtime | md5 | Value

    [DscProperty()]
    [System.string] $Mode

    [DscProperty()]
    [bool] $Force   # Write Only

    [DscProperty()]
    [bool] $Recurse # Write Only

    [DscProperty()]
    [System.String] $Owner

    [DscProperty()]
    [System.String] $Group

    #Links (follow | manage | ignore)

    [DscProperty()]
    [Reason[]] $Reasons

    [nxFile] Get()
    {
        Write-Verbose -Message (
            $script:localizedDataNxFile.RetrieveFile -f $this.DestinationPath
        )

        $nxFileSystemInfo = Get-nxItem -Path $this.DestinationPath -ErrorAction SilentlyContinue
        $currentState = [nxFile]::new()
        $currentState.DestinationPath = $this.DestinationPath

        if ($nxFileSystemInfo) # The file/folder/link exists
        {
            $currentState.Ensure = [Ensure]::Present
            $currentState.Owner = $nxFileSystemInfo.nxOwner
            $currentState.Group = $nxFileSystemInfo.nxGroup
            $currentState.Type  = $nxFileSystemInfo.nxFileSystemItemType

            if ($this.Mode -match '^\d+$') # using octal notation (i.e. 0777)
            {
                $currentState.Mode = $nxFileSystemInfo.Mode.ToOctal()

                if ($this.Mode.Length -eq 3)
                {
                    # if the desired value omits special flags digit (assuming 0), re-add for comparison
                    $this.Mode = '0' + $this.Mode
                }
            }
            else    # Using Symbolic notation (i.e. rwxrwxrwx)
            {
                $currentState.Mode  = $nxFileSystemInfo.Mode.ToString()
            }

            $isSameFile = $false
            if ($this.Checksum -and $this.Type -eq 'File') # checksum checks has precedence over contents check
            {
                switch ($this.Checksum)
                {
                    'MD5'
                    {
                        # Compare Destination with source using MD5
                        if ($this.SourcePath -and (Test-Path -Path $this.SourcePath))
                        {
                            $sourceHash = (Get-FileHash -Path $this.SourcePath -Algorithm 'MD5').Hash
                            $destinationHash = (Get-FileHash -Path $currentState.DestinationPath -Algorithm 'MD5').Hash
                            $isSameFile = $sourceHash -eq $destinationHash

                            if ($this.Contents)
                            {
                                # Do not compare contents if the comparison is done by checksum
                                $currentState.Contents = $this.Contents
                            }
                        }
                        elseif (-not (Test-Path -Path $this.SourcePath))
                        {
                            throw ($script:localizedDataNxFile.SourcePathNotFound -f $this.SourcePath)
                        }
                    }

                    'ctime' # change time (metadata)
                    {
                        # Compare Destination with source using ctime
                        if ($this.SourcePath -and (Test-Path -Path $this.SourcePath))
                        {
                            $sourceCtime = (Get-nxItem -Path $this.SourcePath).CreationTimeUtc
                            $destinationCtime = $nxFileSystemInfo.CreationTimeUtc
                            $isSameFile = $sourceCtime -eq $destinationCtime
                            Write-Verbose -Message (
                                $script:localizedDataNxFile.CompareCtime -f $this.DestinationPath, $destinationCtime, $sourceCtime
                            )

                            if ($this.Contents)
                            {
                                # Do not compare contents if the comparison is done by checksum
                                $currentState.Contents = $this.Contents
                            }
                        }
                        elseif (-not (Test-Path -Path $this.SourcePath))
                        {
                            throw ($script:localizedDataNxFile.SourcePathNotFound -f $this.SourcePath)
                        }
                    }

                    'mtime' # Modify time (data)
                    {
                        # Compare Destination with Source using mtime
                        if ($this.SourcePath -and (Test-Path -Path $this.SourcePath))
                        {
                            $sourceMtime = (Get-nxItem -Path $this.SourcePath).LastWriteTimeUtc
                            $destinationMtime = $nxFileSystemInfo.LastWriteTimeUtc
                            $isSameFile = $sourceMtime -eq $destinationMtime

                            Write-Verbose -Message (
                                $script:localizedDataNxFile.CompareCtime -f $this.DestinationPath, $destinationMtime, $sourceMtime
                            )

                            if ($this.Contents)
                            {
                                # Do not compare contents if the comparison is done by checksum
                                $currentState.Contents = $this.Contents
                            }
                        }
                        elseif (-not (Test-Path -Path $this.SourcePath))
                        {
                            throw ($script:localizedDataNxFile.SourcePathNotFound -f $this.SourcePath)
                        }
                    }

                    default
                    {
                        # Compare Destination with the provided checksum (ignore source file for comparison)
                        $checksumHashAlgorithm = Get-FileHashAlgorithmFromHash -FileHash $this.Checksum -ErrorAction Stop
                        $currentDestinationFileChecksum = (Get-FileHash -Algorithm $checksumHashAlgorithm -Path $currentState.DestinationPath).Hash
                        Write-Verbose -Message (
                            $script:localizedDataNxFile.CompareChecksum -f $this.Checksum, $currentDestinationFileChecksum
                        )

                        $currentState.Checksum = $currentDestinationFileChecksum
                        $isSameFile = $currentDestinationFileChecksum -eq $this.Checksum

                        if ($this.Contents)
                        {
                            # Do not compare contents if the comparison is done by checksum
                            $currentState.Contents = $this.Contents
                        }
                    }
                }
            }
            elseif ($this.Contents) # no checksum but contents is set. use for comparison
            {

                if ($this.Type -eq 'File')
                {
                    Write-Verbose -Message (
                        $script:localizedDataNxFile.GetFileContent -f $currentState.DestinationPath
                    )

                    $currentState.Contents = Get-Content -Raw -Path $currentState.DestinationPath
                }
                else
                {
                    $currentState.Contents = $this.Contents # to make sure it does not flag in the comparison
                }

            }
            else
            {
                # if we don't check against the source, against a provided checksum, or against the provided content
                # assume it's the same file because the file already exists ([ensure]::Present)
                $isSameFile = $true
            }

            if ($isSameFile)
            {
                $currentState.Checksum = $this.Checksum
            }

            $valuesToCheck = @(
                # DestinationPath can be skipped because it's determined with Ensure absent/present
                # SourcePath is write-only property
                'Ensure'
                'Type'
                'Contents'
                'Checksum'
                'Mode'
                # Force is write-only property
                # Recurse is write-only property
                'Owner'
                'Group'

            ).Where({ $null -ne $this.$_ }) #remove properties not set from comparison

            $compareStateParams = @{
                CurrentValues = ($currentState | Convert-ObjectToHashtable)
                DesiredValues = ($this | Convert-ObjectToHashtable)
                ValuesToCheck = $valuesToCheck
                IncludeValue  = $true
            }

            $comparedState = Compare-DscParameterState @compareStateParams

            $currentState.reasons = switch ($comparedState.Property)
            {
                'Ensure'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Ensure' -f $this.GetType()
                        Phrase = $script:localizedDataNxFile.nxFileShouldBeAbsent -f $this.DestinationPath
                    }
                }

                'Type'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Type' -f $this.GetType()
                        Phrase = $script:localizedDataNxFile.TypeMismatch -f $this.DestinationPath, $this.Type, $currentState.Type
                    }
                    break # If the type is wrong, we can't recover from this.
                }

                'Contents'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Contents' -f $this.GetType()
                        Phrase = $script:localizedDataNxFile.ContentsMismatch -f $this.DestinationPath, $this.Contents, $currentState.Contents
                    }
                }

                'Checksum'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Checksum' -f $this.GetType()
                        Phrase = $script:localizedDataNxFile.ChecksumMismatch -f $this.DestinationPath, $this.Checksum, $currentState.Checksum
                    }
                }

                'Mode'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Mode' -f $this.GetType()
                        Phrase = $script:localizedDataNxFile.ModeMismatch -f $this.DestinationPath, $this.Mode, $currentState.Mode
                    }
                }

                'Owner'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Owner' -f $this.GetType()
                        Phrase = $script:localizedDataNxFile.OwnerMismatch -f $this.DestinationPath, $this.Owner, $currentState.Owner
                    }
                }

                'Group'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Group' -f $this.GetType()
                        Phrase = $script:localizedDataNxFile.GroupMismatch -f $this.DestinationPath, $this.Group, $currentState.Group
                    }
                }
            }
        }
        else
        {
            # No item found for this Destination path
            $currentState.Ensure = [Ensure]::Absent

            if ($this.Ensure -ne $currentState.Ensure)
            {
                # We expected the file to be Present
                $currentState.Reasons = [Reason]@{
                    Code = '{0}:{0}:Ensure' -f $this.GetType()
                    Phrase = $script:localizedDataNxFile.nxItemNotFound -f $this.DestinationPath
                }
            }
            else
            {
                Write-Verbose -Message ($script:localizedDataNxFile.nxFileInDesiredState -f  $this.DestinationPath)
            }
        }

        return $currentState
    }

    [bool] Test()
    {
        $currentState = $this.Get()
        $testTargetResourceResult = $currentState.Reasons -eq 0

        return $testTargetResourceResult
    }

    [void] Set()
    {
        $currentState = $this.Get()

        if ($this.Ensure -eq [Ensure]::Present) # Desired State: Ensure present
        {
            if ($currentState.Ensure -ne $this.Ensure) # but is absent
            {
                Write-Verbose -Message (
                    $script:localizedDataNxFile.CreateFile -f $this.DestinationPath
                )

                # Copy from source or
                # Create new file [with content]
                New-Item -ItemType $this.Type -Path $this.DestinationPath -Value $this.Contents -Force:($this.Force)
                Set-nxMode -Path $this.DestinationPath -Mode $this.Mode
                Set-nxGroupOwnership -Path $this.DestinationPath -Group $this.Group
                Set-nxOwner -Path $this.DestinationPath -Owner $this.Owner

            }
            elseif ($currentState.Reasons.Count -gt 0)
            {
                # The file exists but is not properly configured
                Write-Verbose -Message (
                    $script:localizedDataNxFile.SetFile -f $this.DestinationPath
                )

                switch -Regex ($currentState.Reasons.Code)
                {
                    # DestinationPath can be skipped because it's determined with Ensure absent/present
                    # SourcePath is write-only property
                    # 'Ensure' is managed by the file being present or not (already covered)
                    'Type' # if an item of different type, throw... (we can't delete the item to create a new one)
                    {
                        throw ($script:localizedDataNxFile.SetTypeError -f $this.DestinationPath, $this.Type, $currentState.Type)
                    }

                    'Contents'
                    {
                        Write-Verbose -Message (
                            $script:localizedDataNxFile.SetFileContent -f $this.DestinationPath
                        )

                        [System.IO.File]::WriteAllText($currentState.DestinationPath, $this.Contents) # Set content adds a new line
                    }

                    'Checksum'
                    {
                        # either copy from source
                        if ($this.SourcePath -and (Test-Path -Path $this.SourcePath))
                        {
                            Write-Verbose -Message (
                                $script:localizedDataNxFile.CopySourceToDestination -f $this.SourcePath, $this.DestinationPath
                            )

                            Copy-Item -Confirm:$false -Path $this.SourcePath -Destination $this.DestinationPath -Force -Recurse:($this.Recurse)
                        }
                        elseif ($this.Contents -and $this.Type -eq 'File')
                        {
                            Write-Verbose -Message (
                                $script:localizedDataNxFile.SetFileContent -f $this.SourcePath
                            )

                            # or set content from $this.Contents
                            Set-Content -Path $this.DestinationPath -Value $this.Contents -Confirm:$false -Force
                        }
                    }

                    'Mode'
                    {
                        Set-nxMode -Path $this.DestinationPath -Mode $this.Mode -Recurse:($this.Force) -Confirm:$false -Force:($this.Force)
                    }

                    # Force is write-only property
                    # Recurse is write-only property
                    'Owner'
                    {
                        Set-nxOwner -Path $this.DestinationPath -Owner $this.Owner -Recurse:($this.Recurse) -Force:($this.Force) -Confirm:$false
                    }

                    'Group'
                    {
                        Set-nxGroupOwnership -Path $this.DestinationPath -Group $this.Group -Recurse:($this.Recurse) -Force:($this.Force) -Confirm:$false
                    }
                }
            }
            else
            {
                # Set has been invoked but the file is compliant with the desired state (no reasons found).
            }
        }
        else # Desired to be Absent
        {
            $nxFileSystemInfo = Get-nxItem -Path $this.DestinationPath -ErrorAction Stop | Where-Object -FilterScript { $this.Type -eq $_.nxFileSystemItemType}
            if ($nxFileSystemInfo -and $currentState.Ensure -eq [Ensure]::Present)
            {
                Remove-Item -Path $nxFileSystemInfo.DestinationPath -Force:($this.Force) -Recurse:($this.Recurse) -Confirm:$false
            }
        }
    }
}
#EndRegion '.\Classes\1.DscResources\01.nxFile.ps1' 435
#Region '.\Classes\1.DscResources\02.nxGroup.ps1' 0
$script:localizedDataNxGroup = ConvertFrom-StringData @'
    RetrieveGroup = Retrieving nxLocalGroup with GroupName '{0}'.
    nxGroupFound = Found nxLocalGroup with GroupName '{0}'.
    nxLocalGroupShouldBeAbsent = The nxLocalGroup with GroupName '{0}' is expected to be absent but is present on the system.
    MembersMismatch = The members for Group '{0}' do not match. It's missing '{1}' and has the extra '{2}'.
    MembersToIncludeMismatch = The group '{0}' is missing the following members: {1}.
    MembersToExcludeMismatch = The following members should be excluded from group '{0}': {1}.
    PreferredGroupIDMismatch = The GroupID preferred for group '{0}' is '{1}' but got '{2}.
    nxLocalGroupNotFound = The nxLocalGroup with name '{0}' was not found but was expected to be present on this system.
    CreateGroup = Creating nxLocalGroup with GroupName '{0}'.
    SettingProperties = Setting the properties for GroupName '{0}'.
    EvaluateProperties = Evaluating Property '{0}'.
    RemoveNxLocalGroup = Removing nxLocalGroup with GroupName '{0}'.
'@

[DscResource()]
class nxGroup
{
    [DscProperty()]
    [Ensure] $Ensure = [Ensure]::Present

    [DscProperty(Key)]
    [System.String] $GroupName

    [DscProperty()]
    [System.String[]] $Members

    [DscProperty()]
    [System.String[]] $MembersToInclude

    [DscProperty()]
    [System.String[]] $MembersToExclude

    [DscProperty()]
    [System.String] $PreferredGroupID

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [nxGroup] Get()
    {
        Write-Verbose -Message (
            $script:localizedDataNxGroup.RetrieveGroup -f $this.GroupName
        )

        $nxLocalGroup = Get-nxLocalGroup -GroupName $this.GroupName
        $currentState = [nxGroup]::new()
        $currentState.GroupName = $this.GroupName

        if ($nxLocalGroup) # The group with this name exists
        {
            Write-Verbose -Message ($script:localizedDataNxGroup.nxGroupFound -f $this.GroupName)
            $currentState.Ensure = [Ensure]::Present
            $currentState.GroupName = $nxLocalGroup.GroupName # Make sure we get exactly what's in /etc/passwd
            $currentState.Members = $nxLocalGroup.GroupMember # Only compare during Exact match

            if ($this.MembersToInclude -and -not $this.Members) # Contains
            {
                $currentState.MembersToInclude = $nxLocalGroup.GroupMember.Where({$_ -in $this.MembersToInclude})
            }

            if ($this.MembersToExclude -and -not ($this.Members)) # Not Contains
            {
                # If it should be excluded but is present, remove it so the compare picks the difference on the right group.
                $currentState.MembersToExclude = $this.MembersToExclude.Where({$_ -notin $nxLocalGroup.GroupMember})
            }

            $currentState.PreferredGroupID = $nxLocalGroup.GroupID

            $valuesToCheck = @(
                # GroupName can be skipped because it's determined with Ensure absent/present
                'Ensure'
                'Members'
                'MembersToInclude'
                'MembersToExclude'
                'PreferredGroupID'
            ).Where({ $null -ne $this.$_ }) #remove properties not set from comparison

            $compareStateParams = @{
                CurrentValues   = ($currentState | Convert-ObjectToHashtable)
                DesiredValues   = ($this | Convert-ObjectToHashtable)
                ValuesToCheck   = $valuesToCheck
                IncludeValue    = $true
                SortArrayValues = $true
            }

            $comparedState = Compare-DscParameterState @compareStateParams

            $currentState.reasons = switch ($comparedState.Property)
            {
                'Ensure'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Ensure' -f $this.GetType()
                        Phrase = $script:localizedDataNxGroup.nxLocalGroupShouldBeAbsent -f $this.GroupName
                    }
                }

                'Members'
                {
                    $Property = $comparedState.Where({$_.Property -eq 'Members'})
                    $missingMembers = $Property.ExpectedValue.Where({$_ -notin $Property.ActualValue})
                    $ExtraMembers = $Property.ActualValue.Where({$_ -notin $Property.ExpectedValue})

                    [Reason]@{
                        Code = '{0}:{0}:Members' -f $this.GetType()
                        Phrase = $script:localizedDataNxGroup.MembersMismatch -f $this.GroupName, ($missingMembers -join ', '), ($ExtraMembers -join ', ')
                    }
                }

                'MembersToInclude'
                {
                    $Property = $comparedState.Where({$_.Property -eq 'MembersToInclude'})
                    $missingMembers = $Property.ExpectedValue.Where({$_ -notin $Property.ActualValue})

                    [Reason]@{
                        Code = '{0}:{0}:MembersToInclude' -f $this.GetType()
                        Phrase = $script:localizedDataNxGroup.MembersToIncludeMismatch -f $this.GroupName, ($missingMembers -join ', '), ($missingMembers -join ',')
                    }
                }

                'MembersToExclude'
                {
                    $Property = $comparedState.Where({$_.Property -eq 'MembersToExclude'})
                    $UndesiredMembers = $this.MembersToExclude.Where({$_ -notin $Property.ActualValue})

                    [Reason]@{
                        Code = '{0}:{0}:MembersToExclude' -f $this.GetType()
                        Phrase = $script:localizedDataNxGroup.MembersToExcludeMismatch -f $this.GroupName,  ($UndesiredMembers -join ', ')
                    }
                }

                'PreferredGroupID'
                {
                    [Reason]@{
                        Code = '{0}:{0}:PreferredGroupID' -f $this.GetType()
                        Phrase = $script:localizedDataNxGroup.PreferredGroupIDMismatch -f $this.GroupName,  $this.PreferredGroupID, $currentState.PreferredGroupID
                    }
                }
            }
        }
        else # no matching group for 'Name'
        {
            $currentState.Ensure = [Ensure]::Absent
            $currentState.GroupName = $this.GroupName
            Write-Verbose -Message ($script:localizedDataNxGroup.nxLocalGroupNotFound -f $this.GroupName)
            if ($this.Ensure -ne $currentState.Ensure)
            {
                $currentState.reasons = [Reason]@{
                    Code = '{0}:{0}:Ensure' -f $this.GetType()
                    Phrase = $script:localizedDataNxGroup.nxLocalGroupNotFound -f $this.GroupName
                }
            }
            else
            {
                Write-Verbose -Message ('The group ''{0}'' is in the desired state' -f $this.GroupName)
            }
        }

        return $currentState
    }

    [bool] Test()
    {
        $currentState = $this.Get()
        $testTargetResourceResult = $currentState.Reasons.Where({$_.Code -notmatch ':PreferredGroupID$'}).count -eq 0

        return $testTargetResourceResult
    }

    [void] Set()
    {
        # Not implemented yet
        # throw 'Set not implemented yet'

        $currentState = $this.Get()

        if ($this.Ensure -eq [Ensure]::Present) # Desired State: Ensure present
        {
            if ($currentState.Ensure -eq [Ensure]::Absent) # but is absent
            {
                Write-Verbose -Message (
                    $script:localizedDataNxUser.CreateGroup -f $this.GroupName
                )

                $newNxLocalGroupParams = @{
                    GroupName = $this.GroupName
                    PassThru = $true
                    Confirm = $false
                }

                if ($this.PreferredGroupID)
                {
                    $newNxLocalGroupParams['GroupID'] = $this.PreferredGroupID
                }

                $nxLocalGroup = New-nxLocalGroup @newNxLocalGroupParams

                if ($this.Members)
                {
                    Set-nxLocalGroup -GroupName $this.GroupName -Member $this.Members
                }
                else
                {
                    if ($this.MembersToExclude)
                    {
                        $this.MembersToExclude.Where({
                            $_ -in $nxLocalGroup.GroupMember
                        }) | Remove-nxLocalGroupMember -UserName $_ -GroupName $this.GroupName -Confirm:$false
                    }

                    if ($this.MembersToInclude)
                    {
                        $this.MembersToInclude.Where({
                            $_ -notin $nxLocalGroup.GroupMember
                        }) | Add-nxLocalGroupMember -GroupName $this.GroupName -Confirm:$false
                    }
                }
            }
            elseif ($currentState.Reasons.Count -gt 0)
            {
                $nxLocalGroup = Get-nxLocalGroup -GroupName $this.GroupName
                # The Group exists but is not set properly
                switch -Regex ($currentState.Reasons.Code)
                {
                    ':PreferredGroupID$'
                    {
                        Write-Verbose -Message "Attempting to set the GroupID to '$($this.PreferredGroupID)'."
                        Set-nxLocalGroupGID -GroupName $nxLocalGroup.GroupName -GroupID $this.PreferredGroupID -Confirm:$false
                    }

                    ':Members$'
                    {
                        Write-Verbose -Message "Attempting to set the Members for group '$($nxLocalGroup.GroupName)' to '$($this.Members -join "', '")'."
                        Set-nxLocalGroup -GroupName $nxLocalGroup.GroupName -Member $this.Members -Confirm:$false
                    }

                    ':MembersToInclude$'
                    {
                        if (-not $this.Members)
                        {
                            Write-Verbose -Message "Attempting to add missing Members to Include for group '$($nxLocalGroup.GroupName)' to '$($this.MembersToInclude -join "', '")'."
                            $this.MembersToInclude.Where({
                                $_ -notin $nxLocalGroup.GroupMember
                            }) | Add-nxLocalGroupMember -GroupName $this.GroupName -Confirm:$false
                        }
                    }

                    ':MembersToExclude$'
                    {
                        if (-not $this.Members)
                        {
                            $usersToRemoveFromGroup = $this.MembersToExclude.Where({
                                $_ -in $nxLocalGroup.GroupMember
                            })

                            Write-Verbose -Message "Attempting to remove extra Members Excluded from group '$($nxLocalGroup.GroupName)' ('$($usersToRemoveFromGroup -join "', '")')."
                            $usersToRemoveFromGroup | Remove-nxLocalGroupMember -GroupName $this.GroupName -Confirm:$false
                        }
                    }
                }
            }
            else
            {
                # Set() invoked but no change needed.
            }
        }
        else
        {
            # Desired state: Ensure Absent
            if ($currentState.Ensure -eq [Ensure]::Present)
            {
                Remove-nxLocalGroup -GroupName $this.GroupName -Force -Confirm:$false
            }
        }
    }
}
#EndRegion '.\Classes\1.DscResources\02.nxGroup.ps1' 278
#Region '.\Classes\1.DscResources\03.nxUser.ps1' 0

$script:localizedDataNxUser = ConvertFrom-StringData @'
    RetrieveUser = Retrieving nxLocalUser with UserName '{0}'.
    nxUserFound = The nxLocalUser with UserName '{0}' was found.
    nxLocalUserShouldBeAbsent = The nxLocalUser with UserName '{0}' is present but is expected to be absent from the System.
    FullNameMismatch = The nxLocalUser with UserName '{0}' has a Full name of '{1}' while we expected '{2}'.
    DescriptionMismatch = The nxLocalUser with UserName '{0}' has an unexpected Description: '{1}'.
    PasswordMismatch = The nxLocalUser with UserName '{0}' has an unexpected Password.
    DisabledMismatch = The nxLocalUser with UserName '{0}' has the Disabled flag set to '{1}'.
    PasswordChangeRequiredMismatch = The nxLocalUser with UserName '{0}' has the PasswordChangeRequired flag set to '{1}' instead of '{2}'.
    HomeDirectoryMismatch = The nxLocalUser with UserName '{0}' has the HomeDirectory set to '{1}' instead of '{2}'.
    GroupIDMismatch = The nxLocalUser with UserName '{0}' has a GroupID set to '{1}' instead of '{2}'.
    nxLocalUserNotFound = The nxLocalUser with UserName '{0}' was not found but is expected to be present.
    CreateUser = Creating the nxLocalUser with UserName '{0}'.
    SettingProperties = Setting the properties for the nxLocalUser with UserName '{0}'.
    EvaluateProperties = Evaluating property '{0}' for nxLocalUser with UserName {1}'.
    RemoveNxLocalUser = Removing the nxLocalUser with UserName '{0}'.
'@

[DscResource()]
class nxUser
{
    [DscProperty()]
    [Ensure] $Ensure = [Ensure]::Present

    [DscProperty(Key)]
    [string] $UserName

    [DscProperty()]
    [string] $FullName

    [DscProperty()]
    [string] $Description

    [DscProperty()]
    [string] $Password

    [DscProperty()]
    [System.Nullable[bool]] $Disabled

    [DscProperty()]
    [string] $PasswordChangeRequired

    [DscProperty()]
    [string] $HomeDirectory

    [DscProperty()]
    [string] $GroupID

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [nxUser] Get()
    {
        Write-Verbose -Message (
            $script:localizedDataNxUser.RetrieveUser -f $this.UserName
        )

        $nxLocalUser = Get-nxLocalUser -UserName $this.UserName
        $currentState = [nxUser]::new()

        if ($nxLocalUser)
        {
            Write-Verbose -Message ($script:localizedDataNxUser.nxUserFound -f $this.UserName)

            $currentState.Ensure        = [Ensure]::Present
            $currentState.UserName      = $nxLocalUser.UserName
            $currentState.FullName      = $nxLocalUser.FullName
            $currentState.Description   = $nxLocalUser.Description
            $currentState.Password      = $nxLocalUser.EtcShadow.EncryptedPassword
            $currentState.Disabled      = $nxLocalUser.isDisabled()
            # $currentState.PasswordChangeRequired --> this is a WriteNoRead
            $currentState.HomeDirectory = $nxLocalUser.HomeDirectory

            # get the current primary group as an ID or a string based on what is Desired
            if ($this.GroupID -as [int])
            {
                $currentState.GroupId = $nxLocalUser.GroupID
            }
            else
            {
                # Expected GroupID is a string, resolve the Current GroupId's name.
                $currentState.GroupId = (Get-nxLocalGroup).Where({ $_.GroupID -eq $nxLocalUser.GroupID }).GroupName | Select-Object -First 1
            }

            $valuesToCheck = @(
                # UserName can be skipped because it's determined with Ensure absent/present
                'Ensure'
                'FullName'
                'Description'
                'Password'
                'Disabled'
                'HomeDirectory'
                'GroupID'
            ).Where({ $null -ne $this.$_ }) #remove properties not set from comparison

            $compareStateParams = @{
                CurrentValues = ($currentState | Convert-ObjectToHashtable)
                DesiredValues = ($this | Convert-ObjectToHashtable)
                ValuesToCheck = $valuesToCheck
            }

            $compareState = Compare-DscParameterState @compareStateParams

            $currentState.reasons = switch ($compareState.Property)
            {
                'Ensure'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Ensure' -f $this.GetType()
                        Phrase = $script:localizedDataNxUser.nxLocalUserShouldBeAbsent -f $this.UserName
                    }
                }

                'FullName'
                {
                    [Reason]@{
                        Code = '{0}:{0}:FullName' -f $this.GetType()
                        Phrase = $script:localizedDataNxUser.FullNameMismatch -f $this.FullName, $currentState.FullName
                    }
                }

                'Description'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Description' -f $this.GetType()
                        Phrase = $script:localizedDataNxUser.DescriptionMismatch -f $this.Description, $currentState.Description
                    }
                }

                'Password'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Password' -f $this.GetType()
                        Phrase = $script:localizedDataNxUser.PasswordMismatch -f $this.Password, $currentState.Password
                    }
                }

                'Disabled'
                {
                    [Reason]@{
                        Code = '{0}:{0}:Disabled' -f $this.GetType()
                        Phrase = $script:localizedDataNxUser.DisabledMismatch -f $this.Disabled, $currentState.Disabled
                    }
                }

                'PasswordChangeRequired'
                {
                    [Reason]@{
                        Code = '{0}:{0}:PasswordChangeRequired' -f $this.GetType()
                        Phrase = $script:localizedDataNxUser.PasswordChangeRequiredMismatch -f $this.PasswordChangeRequired, $currentState.PasswordChangeRequired
                    }
                }

                'HomeDirectory'
                {
                    [Reason]@{
                        Code = '{0}:{0}:HomeDirectory' -f $this.GetType()
                        Phrase = $script:localizedDataNxUser.HomeDirectoryMismatch -f $this.HomeDirectory, $currentState.HomeDirectory
                    }
                }

                'GroupID'
                {
                    [Reason]@{
                        Code = '{0}:{0}:GroupID' -f $this.GetType()
                        Phrase = $script:localizedDataNxUser.GroupIDMismatch -f $this.GroupID, $currentState.GroupID
                    }
                }
            }
        }
        else
        {
            $currentState.Ensure = [Ensure]::Absent
            $currentState.UserName = $this.UserName
            Write-Verbose -Message ($script:localizedDataNxUser.nxLocalUserNotFound -f $this.UserName)
            if ($this.Ensure -ne $currentState.Ensure)
            {
                $currentState.reasons = [Reason]@{
                    Code = '{0}:{0}:Ensure' -f $this.GetType()
                    Phrase = $script:localizedDataNxUser.nxLocalUserNotFound -f $this.UserName
                }
            }
            else
            {
                Write-Verbose -Message ('The user ''{0}'' is in the desired state' -f $this.UserName)
            }
        }

        return $currentState
    }

    [void] Set()
    {
        $currentState = $this.Get()

        if ($this.Ensure -eq [Ensure]::Present) # must be present
        {
            if ($currentState.Ensure -eq [Ensure]::Absent) # but is absent
            {
                Write-Verbose -Message (
                    $script:localizedDataNxUser.CreateUser -f $this.UserName
                )

                $newNxLocalUserParam = @{
                    Username    = $this.UserName
                    Passthru    = $true
                    ErrorAction = 'Stop'
                    Confirm     = $false
                }

                if ($this.GroupID)
                {
                    $newNxLocalUserParam.Add(
                        'PrimaryGroup', $this.GroupID
                    )
                }

                if ($this.Password)
                {
                    $newNxLocalUserParam.Add(
                        'EncryptedPassword', $this.Password
                    )
                }

                if ($this.HomeDirectory)
                {
                    $newNxLocalUserParam.Add(
                        'HomeDirectory', $this.HomeDirectory
                    )
                }

                if ($this.FullName -or $this.Description)
                {
                    $newNxLocalUserParam.Add(
                        'UserInfo',
                        ('{0},,,,{1},' -f $this.FullName, $this.Description)
                    )
                }

                if ($this.PasswordChangeRequired)
                {
                    # Make it expired yesterday
                    $newNxLocalUserParam.Add(
                        'ExpireOn',
                        (Get-Date).AddDays(-1)
                    )
                }

                $localUser = New-nxLocalUser @newNxLocalUserParam
            }
            else
            {
                # The user exists but has some non-compliant settings (found in the reasons)

                # Get user so we can set other properties
                $localUser = Get-nxLocalUser -UserName $this.UserName -ErrorAction Stop
                $setUserParams = @{}

                switch -Regex ($currentState.Reasons.Code)
                {
                    ':FullName$'
                    {
                        $setUserParams['FullName'] = $this.FullName
                    }

                    ':Description$'
                    {
                        $setUserParams['Description'] = $this.Description
                    }

                    ':Password$'
                    {
                        $setUserParams['EncryptedPassword'] = $this.Password
                    }

                    ':HomeDirectory$'
                    {
                        $setUserParams['HomeDirectory'] = $this.HomeDirectory
                    }

                    ':GroupID$'
                    {
                        Write-Verbose -Message ('Forcing the PrimaryGroup to be ID {0}' -f  $this.GroupID)
                        $setUserParams['GroupID'] = $this.GroupID
                    }
                }

                if ($setUserParams.Keys.Count -gt 0)
                {
                    Set-nxLocalUser @setUserParams
                }

                if ('nxUser:nxUser:Disabled' -in $currentState.Reasons.Code)
                {
                    if ($true -eq $this.Disabled)
                    {
                        Disable-nxLocalUser -UserName $this.UserName
                    }
                    elseif ($false -eq $this.Disabled)
                    {
                        Enable-nxLocalUser -UserName $this.UserName
                    }
                }
            }

            # Set other properties if needed
            if ($this.Disabled -and -not $localUser.IsDisabled())
            {
                Write-Verbose -Message "Disabling user account '$($this.UserName)'."
                Disable-nxLocalUser -UserName $localUser.UserName
            }
            elseif ($false -eq $this.Disabled -and $localUser.IsDisabled())
            {
                Write-Verbose -Message "Enabling user account '$($this.UserName)'."
                Enable-nxLocalUser -UserName $localUser.UserName
            }

            Write-Verbose -Message (
                $script:localizedDataNxUser.SettingProperties -f $this.UserName
            )
        }
        else
        {
            # The user must not exist
            if ($currentState.Ensure -eq 'Present')
            {
                # But it does, remove it
                Write-Verbose -Message (
                    $script:localizedDataNxUser.RemoveNxLocalUser -f $this.Path
                )

                Remove-nxLocalUser -UserName $this.Username -Confirm:$false
            }
        }
    }

    [bool] Test()
    {
        $currentState = $this.Get()
        $testTargetResourceResult = $currentState.Reasons.count -eq 0

        return $testTargetResourceResult
    }
}
#EndRegion '.\Classes\1.DscResources\03.nxUser.ps1' 346
#Region '.\Classes\1.DscResources\04.nxPackage.ps1' 0

[DscResource()]
class nxPackage
{
    [DscProperty()]
    [Ensure] $Ensure = [Ensure]::Present

    [DscProperty(Key)]
    [String] $Name

    [DscProperty()]
    [String] $Version

    [DscProperty()]
    [String] $PackageType

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [nxPackage] Get()
    {
        $currentState = [nxPackage]::new()
        $getNxPackageParams = @{
            Name = $this.Name
        }

        $packageFound = Get-nxPackage @getNxPackageParams

        if ($packageFound.count -eq 0)
        {
            $currentState.Ensure = [Ensure]::Absent
        }
        elseif ($packageFound.count -gt 1 -and $packageFound.Where{$_.Version -eq $this.Version})
        {
            $packageFound = ($packageFound.Where{$_.Version -eq $this.Version})[0]
        }
        else
        {
            $packageFound = $packageFound[0]
        }

        $currentState.Name = $this.Name
        $currentState.PackageType = $packageFound.PackageType
        $currentState.Version = $packageFound.Version

        $valuesToCheck = @(
                # UserName can be skipped because it's determined with Ensure absent/present
                'Ensure'
                'Version'
            ).Where({ $null -ne $this.$_ }) #remove properties not set from comparison


        $compareStateParams = @{
            CurrentValues = ($currentState | Convert-ObjectToHashtable)
            DesiredValues = ($this | Convert-ObjectToHashtable)
            ValuesToCheck = $valuesToCheck
        }

        $compareState = Compare-DscParameterState @compareStateParams

        $currentState.reasons = switch ($compareState.Property)
        {
            'Ensure'
            {
                [Reason]@{
                    Code = '{0}:{0}:Ensure' -f 'nxPackage'
                    Phrase ='The {0} is not in desired state because the package was expected {1} but was {2}.' -f $this.GetType(), $this.Ensure, $currentState.Ensure
                }
            }

            'PackageVersion'
            {
                if ($this.Ensure -eq [Ensure]::Present -and $currentState.Ensure -eq [Ensure]::Present)
                {
                    [Reason]@{
                        Code = '{0}:{0}:PackageVersion' -f 'nxPackage'
                        Phrase = 'The Package {0} is present but we''re expecting version {1} and got {2}' -f $this.Name, $this.Version, $currentState.Version
                    }
                }
            }
        }

        return $currentState
    }

    [bool] Test()
    {
        $currentState = $this.Get()
        $testTargetResourceResult = $currentState.Reasons.count -eq 0

        return $testTargetResourceResult
    }

    [void] Set()
    {
        $currentState = $this.Get()

        if ($this.Ensure -eq [Ensure]::Present) # must be present
        {
            if ($currentState.Ensure -eq [Ensure]::Absent) # but is absent
            {
                Write-Verbose -Message (
                    'Installing Package {0}' -f $this.Name
                )
            }
            elseif ($currentState.Reasons.Count -gt 0)
            {
                # Package is present, and there's a reason for non compliance
                # Try installing the correct version
                Write-Verbose -Message (
                    'Installing version {0} of package {1}' -f $this.Version,$this.Name
                )
            }

            # Anyway, whether absent or present at wrong version, we can only try to install at specific version
            $installnxPackageParams = @{
                Name = $this.Name
            }

            if (-not [string]::IsNullOrEmpty)
            {
                $installnxPackageParams['Version'] = $this.Version
            }

            Install-nxPackage @installnxPackageParams
        }
        else # Expected Absent
        {
            if ($currentState.Ensure -eq [Ensure]::Present) # But is Absent
            {
                $removenxPackageParams = @{
                    Name = $this.Name
                }

                if (-not [string]::IsNullOrEmpty($this.Version))
                {
                    $removenxPackageParams['Version'] = $this.Version
                }

                Remove-nxPackage @removenxPackageParams
            }

            # Is absent, all good.
        }
    }
}
#EndRegion '.\Classes\1.DscResources\04.nxPackage.ps1' 147
#Region '.\Classes\1.DscResources\05.nxFileLine.ps1' 0
[DscResource()]
class nxFileLine
{
    [DscProperty(Key)]
    # The full path to the file to manage lines in on the target node.
    [string] $FilePath

    [DscProperty(Key)]
    # A line to ensure exists in the file.
    # By default, this line will be appended to the file if it does not exist in the file.
    # ContainsLine is mandatory, but can be set to an empty string (ContainsLine = "") if it is not needed.
    [string] $ContainsLine

    [DscProperty()] #WriteOnly
    # A regular expression pattern for lines that should not exist in the file.
    # For any lines that exist in the file that match this regular expression, the line will be removed from the file.
    [string] $DoesNotContainPattern

    [DscProperty()] #WriteOnly
    [bool] $CaseSensitive = $false

    # Append, AfterLinePatternMatch, BeforeLinePatternMatch
    [nxFileLineAddMode] $AddLineMode = [nxFileLineAddMode]::Append

    [string] $LinePattern

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [nxFileLine] Get()
    {
        #
        $currentState = [nxFileLine]::new()
        $currentState.ContainsLine = $this.ContainsLine
        $currentState.DoesNotContainPattern = $this.DoesNotContainPattern
        $currentState.FilePath = $this.FilePath
        $currentState.LinePattern = $this.LinePattern
        $currentState.CaseSensitive = $this.CaseSensitive
        $currentState.AddLineMode = $this.AddLineMode

        if (-not (Test-Path -Path $this.FilePath -ErrorAction Ignore))
        {
            $currentState.Reasons = [Reason]@{
                Code    = '{0}:{0}:FileNotFound' -f $this.GetType()
                Phrase  = "The file '$this.filePath' was not found."
            }

            return $currentState
        }
        elseif ((Get-Item -Path $this.FilePath).count -gt 1)
        {
            $allFiles = Get-Item -Path $this.FilePath
            $currentState.Reasons = [Reason]@{
                Code   = '{0}:{0}:ResolvedToMultipleFiles' -f $this.GetType()
                Phrase = "The Path '$($this.FilePath)' resolved to multiple paths: ['$($allFiles -join "','")']."
            }

            return $currentState
        }

        if (-not [string]::IsNullOrEmpty($this.ContainsLine))
        {
            $foundLines = Select-String -Path $this.FilePath -Pattern $this.ContainsLine -SimpleMatch -AllMatches -CaseSensitive:$this.CaseSensitive
            if ($foundLines.Count -gt 0)
            {
                Write-Verbose -Message "The line '$($this.ContainsLine)' was found $($foundLines.count) times."
                $currentState.Reasons = $foundLines.Foreach{
                    [Reason]@{
                        Code   = '{0}:{0}:LineFound' -f $this.GetType()
                        Phrase = "[Compliant]The expected line '$($_.Pattern)' was found at line number '$($_.LineNumber)'."
                    }
                }
            }
            else
            {
                Write-Verbose -Message "The line '$($this.ContainsLine)' was not found."
                $currentState.Reasons = [Reason]@{
                    Code   = '{0}:{0}:LineNotFound' -f $this.GetType()
                    Phrase = "Can't find the expected line '$($this.ContainsLine)'."
                }
            }
        }

        if (-not [string]::IsNullOrEmpty($this.DoesNotContainPattern))
        {
            $shouldNotFindPattern = Select-String -Path $this.FilePath -Pattern $this.DoesNotContainPattern -AllMatches -CaseSensitive:$this.CaseSensitive
            $currentState.Reasons += $shouldNotFindPattern.Foreach{
                [Reason]@{
                    Code   = '{0}:{0}:LineUnexpected' -f $this.GetType()
                    Phrase = "The pattern '$($_.Pattern)' was found at line '$($_.LineNumber)' but is expeced to be absent."
                }
            }
        }

        return $currentState
    }

    [bool] Test()
    {
        $currentState = $this.Get()
        $testTargetResourceResult = ($currentState.Reasons.Where({
            $_.Code -notmatch 'LineFound'
        })).count -eq 0

        return $testTargetResourceResult
    }

    [void] Set()
    {
        $file = Get-nxChildItem -Path $this.FilePath -File

        if (-not $file)
        {
            Write-Warning -Message "The file '$($this.FilePath)' was not found. Please create the file with [nxFile] to manage its content with [nxFileLine]."
        }

        if (-not ([string]::IsNullOrEmpty($this.ContainsLine)))
        {
            $foundLines = Select-String -Path $this.FilePath -Pattern $this.ContainsLine -SimpleMatch -AllMatches -CaseSensitive:$this.CaseSensitive

            if ($foundLines.Count -eq 0)
            {
                Add-nxFileLine -Path $this.FilePath -Line $this.ContainsLine -AddLineMode $this.AddLineMode -LinePattern $this.LinePattern
            }
        }

        if (-not [string]::IsNullOrEmpty($this.DoesNotContainPattern))
        {
            $shouldNotFindPattern = Select-String -Path $this.FilePath -Pattern $this.DoesNotContainPattern -AllMatches -CaseSensitive:$this.CaseSensitive

            if ($shouldNotFindPattern.count -gt 0)
            {
                Remove-nxFileLine -Path $this.FilePath -LineNumber $shouldNotFindPattern.LineNumber
            }
        }
    }
}
#EndRegion '.\Classes\1.DscResources\05.nxFileLine.ps1' 138
#Region '.\Classes\1.DscResources\06.nxFileContentReplace.ps1' 0
[DscResource()]
class nxFileContentReplace
{
    [DscProperty()]
    [Ensure] $Ensure

    [DscProperty(Key)]
    [string] $FilePath

    [DscProperty(Key)]
    [string] $EnsureExpectedPattern

    [DscProperty()] # WriteOnly
    [bool] $Multiline = $false  # Will read the whole file and -match/-replace the whole content

    [DscProperty()] # WriteOnly
    [string] $SearchPattern

    [DscProperty()] # WriteOnly
    [bool] $SimpleMatch

    [DscProperty()] # WriteOnly
    [string] $ReplacementString

    [DscProperty()] # WriteOnly
    [bool] $CaseSensitive = $false

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [nxFileContentReplace] Get()
    {
        # Copy all properties except Ensure
        $currentState = [nxFileContentReplace]::new()
        $currentState.FilePath = $this.FilePath
        $currentState.EnsureExpectedPattern = $this.EnsureExpectedPattern
        $currentState.SearchPattern = $this.SearchPattern
        $currentState.SimpleMatch = $this.SimpleMatch
        $currentState.ReplacementString = $this.ReplacementString
        $currentState.CaseSensitive = $this.CaseSensitive
        $currentState.Multiline = $this.Multiline

        if (-not (Test-Path -Path $this.FilePath -ErrorAction Ignore))
        {
            $currentState.Reasons = [Reason]@{
                Code    = '{0}:{0}:FileNotFound' -f $this.GetType()
                Phrase  = "The file '$this.filePath' was not found."
            }

            return $currentState
        }
        elseif ((Get-Item -Path $this.FilePath).count -gt 1)
        {
            $allFiles = Get-Item -Path $this.FilePath
            $currentState.Reasons = [Reason]@{
                Code   = '{0}:{0}:ResolvedToMultipledFiles' -f $this.GetType()
                Phrase = "The Path '$($this.filePath)' resolved to multiple paths: ['$($allFiles -join "','")']."
            }

            return $currentState
        }

        if ($this.SimpleMatch)
        {
            $ExpectedPattern = [regex]::Escape($this.EnsureExpectedPattern)
        }
        else
        {
            $ExpectedPattern = $this.EnsureExpectedPattern
        }

        if ($this.Multiline)
        {
            $selectStringParams = @{
                Pattern = $ExpectedPattern
                AllMatches = $true
                CaseSensitive = $this.CaseSensitive
            }

            $foundMatches = Get-Content -Raw -Path $this.FilePath | Select-String @selectStringParams
        }
        else
        {
            $selectStringParams = @{
                Path = $this.FilePath
                Pattern = $ExpectedPattern
                AllMatches = $true
                CaseSensitive = $this.CaseSensitive
            }

            $foundMatches = Select-String @selectStringParams
        }

        if ($foundMatches.count -gt 0)
        {
            $currentState.Ensure = [Ensure]::Present
        }
        else
        {
            $currentState.Ensure = [Ensure]::Absent
        }

        if ($this.Ensure -ne $currentState.Ensure) # non compliant
        {
            if ($this.Ensure -eq [Ensure]::Present) # We expected it to be Present but it's not
            {
                Write-Debug -Message "We expected the pattern '$($this.EnsureExpectedPattern)' to be Present but it was not found in '$($this.FilePath)'."
                $CurrentState.Reasons += [Reason]@{
                    Code    = '{0}:{0}:ExpectedPatternNotFound' -f $this.GetType()
                    Phrase  = "We expected the pattern '$($this.EnsureExpectedPattern)' to be Present but it was not found in '$($this.FilePath)'."
                }
            }
            elseif ($this.Ensure -eq [Ensure]::Absent) # We expected it to be Absent but it's not
            {
                Write-Debug -Message "The undesired pattern '$($this.EnsureExpectedPattern)' was found to be Present in '$($this.FilePath)'."
                $CurrentState.Reasons += [Reason]@{
                    Code    = '{0}:{0}:UndesiredPatternFound' -f $this.GetType()
                    Phrase  = "The undesired pattern '$($this.EnsureExpectedPattern)' was found to be Present $($foundMatches.Count) times in '$($this.FilePath)'."
                }
            }

            if (-not $this.Multiline)
            {
                # List all of the transforms that we want to happen.
                # Re-use the sls params but now use the SearchPattern for pattern.
                $selectStringParams['Pattern'] = $this.SearchPattern
                $foundReplace = Select-String @selectStringParams
                $foundReplace.Foreach{
                    $currentState.Reasons += [Reason]@{
                        Code   = '{0}:{0}:SubstitubtionRequired' -f $this.GetType()
                        Phrase = 'Pattern ''{0}'' found at line {1} to be replaced with ''{2}'' of file ''{3}'' resulting in: ''.' -f $_.Pattern, $_.LineNumber, $this.ReplacementString, $CurrentState.FilePath
                    }
                }
            }
            else
            {
                # List all of the transforms that we want to happen on the whole file.
                # Re-use the sls params but now use the SearchPattern for pattern.
                $selectStringParams['Pattern'] = $this.SearchPattern
                $foundReplace = Get-Content -Raw -Path $this.FilePath | Select-String @selectStringParams
                $foundReplace.Matches.Foreach{
                    $currentState.Reasons += [Reason]@{
                        Code   = '{0}:{0}:MultilineSubstitubtionRequired' -f $this.GetType()
                        Phrase = 'Pattern ''{0}'' found at index {1} of length ''{2}'' to be replaced with ''{3}'' of file ''{4}'' resulting in: ''.' -f $foundReplace.Pattern, $_.Index, $_.Length, $this.ReplacementString, $CurrentState.FilePath
                    }
                }
            }
        }
        else # Compliant, nothing to do.
        {
            Write-Verbose -Message "The resource is compliant with the expectation."
        }

        return $currentState
    }

    [bool] Test()
    {
        $currentState = $this.Get()

        return ($currentState.Reasons.Count -eq 0)
    }

    [void] Set()
    {
        $currentState = $this.Get()

        if ($this.Ensure -ne $currentState.Ensure)
        {
            # Do the substitutions
            Invoke-nxFileContentReplace -Path $this.FilePath -SearchPattern $this.SearchPattern -ReplaceWith $this.ReplacementString -Multiline:$this.Multiline
        }
    }
}
#EndRegion '.\Classes\1.DscResources\06.nxFileContentReplace.ps1' 175
#Region '.\Classes\1.DscResources\07.nxService.ps1' 0
#using namespace System.Collections

[DscResource()]
class nxService
{
    [DscProperty(Key)]
    [string] $Name

    [DscProperty()]
    [System.Nullable[bool]] $Enabled # enabled, disabled, masked

    [DscProperty()]
    [string] $State

    [DscProperty()] # Write Only
    [nxInitSystem] $Controller = (Get-nxInitSystem)

    hidden [void] SetNxServiceProperties([IDictionary] $Definition)
    {
        if ($Definition.keys -notcontains 'Name')
        {
            throw 'You must provide the  name of the service you want to manage.'
        }

        foreach ($property in $Definition.Keys.Where{$_ -in $this.PSObject.Properties.Where{$_.IsSettable}.Name})
        {
            $this.($property) = $Definition[$property]
        }
    }

    [nxService] Get()
    {
        $currentState = Get-nxService -Name $this.Name

        if (-not $currentState)
        {
            # Silently return if the service does not exist
            Write-Warning -Message ('Service ''{0}'' could not be found.' -f $this.Name)
            return [nxService]::new()
        }

        $valuesToCheck = @(
            'Enabled'
            'State'
        ).Where({ $null -ne $this.$_ }) #remove properties not set from comparison

        $compareStateParams = @{
            CurrentValues       = ($currentState | Convert-ObjectToHashtable)
            DesiredValues       = ($this | Convert-ObjectToHashtable)
            ValuesToCheck       = $valuesToCheck
            TurnOffTypeChecking = $true
            ErrorAction         = 'Ignore'
        }

        $compareState = Compare-DscParameterState @compareStateParams

        Write-Debug -Message 'Adding reasons to the current state to explain discrepancies...'

        $currentState.reasons = switch ($compareState.Property)
        {
            'Enabled'
            {
                if ($null -ne $this.enabled -and $currentState -and $this.Enabled -ne $currentState.Enabled)
                {
                    $enabledReference = @{
                        $true = 'enabled'
                        $false = 'disabled'
                    }

                    [Reason]@{
                        Code = '{0}:{0}:Enabled' -f 'nxService'
                        Phrase = 'The service ''{0}'' is present but we''re expecting it to be {1} instead of {2}.' -f $this.Name, $enabledReference[$this.Enabled], $enabledReference[$currentState.Enabled]
                    }
                }
            }

            'State'
            {
                if ($null -ne $this.State -and $currentState -and $this.State -ne $currentState.State)
                {
                    [Reason]@{
                        Code = '{0}:{0}:State' -f 'nxService'
                        Phrase = 'The service ''{0}'' is present but we''re expecting it to be ''{1}'' instead of ''{2}''' -f $this.Name, $this.State, $currentState.State
                    }
                }
            }
        }

        return $currentState
    }

    [bool] Test()
    {
        $currentState = $this.Get()

        if ($currentState.Reasons.Count -gt 0)
        {
            return $false
        }
        else
        {
            return $true
        }
    }

    [void] Set()
    {
        $currentState = $this.Get()

        switch -Regex ($currentState.Reasons.Code)
        {
            'State$'
            {
                if ($currentState.State -eq 'running')
                {
                    $this.Stop()
                }
                else
                {
                    $this.Start()
                }
            }

            'Enabled$'
            {
                if ($currentState.Enabled)
                {
                    $this.Disable()
                }
                else
                {
                    $this.Enable()
                }
            }
        }
    }

    [void] Disable()
    {
        # Disable the service
        Write-Debug -Message ('Disabling service ''{0}''.' -f $this.Name)
        Disable-nxService -Name $this.Name -Controller $this.Controller
    }

    [void] Enable()
    {
        # Enable the service now or at next machine start
        Write-Debug -Message ('Enabling service ''{0}''.' -f $this.Name)
        Enable-nxService -Name $this.Name -Controller $this.Controller
    }

    [void] Start()
    {
        # Start the service
        Write-Debug -Message ('Starting service ''{0}''.' -f $this.Name)
        Start-nxService -Name $this.Name -Controller $this.Controller
    }

    [void] Stop()
    {
        # Stop the service
        Write-Debug -Message ('Stopping service ''{0}''.' -f $this.Name)
        Stop-nxService -Name $this.Name -Controller $this.Controller
    }

    [void] Restart()
    {
        # Restart the service
        Write-Debug -Message ('Restarting service ''{0}''.' -f $this.Name)
        Restart-nxService -Name $this.Name -Controller $this.Controller
    }

    [bool] IsEnabled()
    {
        # Message when the method is not overridden by the controller-specific class
        throw 'The [nxService] method IsEnabled() is not yet supported for this Controller.'
    }

    [bool] IsRunning()
    {
        # Message when the method is not overridden by the controller-specific class
        throw 'The [nxService] method IsRunning() is not yet supported for this Controller.'
    }
}
#EndRegion '.\Classes\1.DscResources\07.nxService.ps1' 185
#Region '.\Classes\1.DscResources\Reason.ps1' 0

class Reason
{
    [DscProperty()]
    [string] $Code

    [DscProperty()]
    [string] $Phrase
}
#EndRegion '.\Classes\1.DscResources\Reason.ps1' 10
#Region '.\Classes\2.GCResources\01.GC_LinuxGroup.ps1' 0
[DscResource()]
class GC_LinuxGroup : nxGroup
{
    [DscProperty()]
    [System.String] $MembersAsString

    [DscProperty()]
    [System.String] $MembersToIncludeAsString

    [DscProperty()]
    [System.String] $MembersToExcludeAsString

    GC_LinuxGroup()
    {
        # default ctor

        $this.ConvertAsStringToBaseClass()
    }

    GC_LinuxGroup ([nxGroup] $nxGroup)
    {
        $this.GroupName = $nxGroup.GroupName
        $this.Members = $nxGroup.Members
        $this.MembersToInclude = $nxGroup.MembersToInclude
        $this.MembersToExclude = $nxGroup.MembersToExclude
        $this.Reasons = $nxGroup.Reasons
        $this.Ensure = $nxGroup.Ensure
        $this.PreferredGroupID = $nxGroup.PreferredGroupID

        $this.MembersAsString = $nxGroup.Members -join ';'
        $this.MembersToExcludeAsString = $nxGroup.MembersToExclude -join ';'
        $this.MembersToIncludeAsString = $nxGroup.MembersToInclude -join ';'
    }

    [void] ConvertAsStringToBaseClass()
    {
        if ($null -ne $this.MembersToIncludeAsString)
        {
            $this.MembersToInclude = $this.MembersToIncludeAsString -split ';'
        }

        if ($null -ne $this.MembersToExcludeAsString)
        {
            $this.MembersToExclude = $this.MembersToExcludeAsString -split ';'
        }

        if ($null -ne $this.MembersAsString)
        {
            $this.Members = $this.MembersAsString -split ';'
        }
    }

    [GC_LinuxGroup] Get()
    {
        $this.ConvertAsStringToBaseClass()

        return ([GC_LinuxGroup]([nxGroup]$this).Get())
    }

    [bool] Test()
    {
        $currentState = $this.Get()
        $testTargetResourceResult = $currentState.Reasons.Where({$_.Code -notmatch ':PreferredGroupID$'}).count -eq 0

        return $testTargetResourceResult
    }

    [void] Set()
    {
        $this.ConvertAsStringToBaseClass()
        ([nxGroup]$this).Set()
    }
}
#EndRegion '.\Classes\2.GCResources\01.GC_LinuxGroup.ps1' 74
#Region '.\Classes\2.GCResources\02.GC_msid110.ps1' 0

# author: Michael Greene

# control 'msid110' do
#   impact 1.0
#   title 'Remote connections from accounts with empty passwords should be disabled.'
#   desc 'An attacker could gain access through password guessing'

#   describe file('/etc/ssh/sshd_config') do
#     its('content') { should match "^[\s\t]*PermitEmptyPasswords\s+no" }
#   end
# end

# instance of MSFT_ChefInSpecResource as $MSFT_ChefInSpecResource2ref
# {
#     ResourceID = "[ChefInSpec]MSID110";
#     SourceInfo = "::11::5::ChefInSpec";
#     Name = "PasswordPolicy_msid110";
#     ModuleName = "ChefInSpec";
#     ModuleVersion = "1.0";
#     GithubPath = "PasswordPolicy_msid110/Modules/PasswordPolicy_msid110_inspec_controls/";
#     ConfigurationName = "chefInSpec";
# };



[DscResource()]
class GC_msid110
{
    [DscProperty(Key)]
    [String] $Name

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [GC_msid110] Get()
    {
        $sshdContentMatch = Get-Content -Path '/etc/ssh/sshd_config' -ErrorAction SilentlyContinue | Where-Object -FilterScript {
            $_ -match '^[\s\t]*PermitEmptyPasswords\s+no'
        }

        $result = [GC_msid110]::new()
        $result.Name = $this.Name

        if (-not $sshdContentMatch)
        {
            $result.Reasons += [Reason]@{
                Code = '{0}:{0}:sshdPermitEmptyPasswords' -f $this.GetType()
                Phrase = 'Remote connections from accounts with empty passwords is not disabled.'
            }
        }

        return $result
    }

    [bool] Test()
    {
        $getResult = $this.Get()
        if ($getResult.Reasons -is [Reason[]] -and $getResult.Count -ge 1)
        {
            return $false
        }
        else
        {
            return $true
        }
    }

    [void] Set()
    {
        throw 'The Set method is not implemented for this Audit resource.'
    }
}
#EndRegion '.\Classes\2.GCResources\02.GC_msid110.ps1' 74
#Region '.\Classes\2.GCResources\03.GC_msid121.ps1' 0
# author: Michael Greene

# control 'msid12.1' do
#   impact 1.0
#   title '/etc/passwd file permissions should be 0644'
#   desc 'An attacker could modify userIDs and login shells'

#   describe file('/etc/passwd') do
#     its('mode') { should cmp '0644' }
#   end
# end

# instance of MSFT_ChefInSpecResource as $MSFT_ChefInSpecResource2ref
# {
#     ResourceID = "[ChefInSpec]MSID121";
#     SourceInfo = "::11::5::ChefInSpec";
#     Name = "PasswordPolicy_msid121";
#     ModuleName = "ChefInSpec";
#     ModuleVersion = "1.0";
#     GithubPath = "PasswordPolicy_msid121/Modules/PasswordPolicy_msid121_inspec_controls/";
#     ConfigurationName = "chefInSpec";
# };


[DscResource()]
class GC_msid121
{
    [DscProperty(Key)]
    [String] $Name

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [GC_msid121] Get()
    {
        $etcPasswdFile = Get-nxItem -Path '/etc/passwd'
        $modeDifference = Compare-nxMode -ReferenceMode 0644 -DifferenceMode $etcPasswdFile.Mode

        $result = [GC_msid121]::new()
        $result.Name = $this.Name

        if ($null -ne $modeDifference)
        {
            $result.Reasons += [Reason]@{
                Code = '{0}:{0}:passwd' -f $this.GetType()
                Phrase = 'The file ''/etc/passwd'' has a mode of ''{0}''.' -f $etcPasswdFile.Mode.ToOctal()
            }
        }

        return $result
    }

    [bool] Test()
    {
        $getResult = $this.Get()
        if ($getResult.Reasons -is [Reason[]] -and $getResult.Count -ge 1)
        {
            return $false
        }
        else
        {
            return $true
        }
    }

    [void] Set()
    {
        throw 'The Set method is not implemented for this Audit resource.'
    }
}
#EndRegion '.\Classes\2.GCResources\03.GC_msid121.ps1' 71
#Region '.\Classes\2.GCResources\04.GC_msid232.ps1' 0

# author: Michael Greene

# control 'msid23.2' do
#   impact 1.0
#   title 'There are no accounts without passwords'
#   desc 'An attacker could modify userIDs and login shells'

#   describe file('/etc/shadow') do
#     its('content') { should_not match "^[^:]+::" }
#   end
# end

# instance of MSFT_ChefInSpecResource as $MSFT_ChefInSpecResource2ref
# {
#     ResourceID = "[ChefInSpec]MSID232";
#     SourceInfo = "::11::5::ChefInSpec";
#     Name = "PasswordPolicy_msid232";
#     ModuleName = "ChefInSpec";
#     ModuleVersion = "1.0";
#     GithubPath = "PasswordPolicy_msid232/Modules/PasswordPolicy_msid232_inspec_controls/";
#     ConfigurationName = "chefInSpec";
# };

[DscResource()]
class GC_msid232
{
    [DscProperty(Key)]
    [String] $Name

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [GC_msid232] Get()
    {
        $userAccountWithoutPassword = Get-nxLocalUser | Where-Object -FilterScript {
            [string]::IsNullOrEmpty($_.etcShadow.Encryptedpassword)
        } #| select username,password,@{N='pass';E={$_.etcShadow.EncryptedPassword}}

        $result = [GC_msid232]::new()
        $result.Name = $this.Name

        foreach ($item in $userAccountWithoutPassword)
        {
            $result.Reasons += [Reason]@{
                Code = '{0}:{0}:{1}' -f $this.GetType(),$item.UserName
                Phrase = 'Username ''{0}'' has an empty password.' -f $item.UserName
            }
        }

        return $result
    }

    [bool] Test()
    {
        $getResult = $this.Get()
        if ($getResult.Reasons -is [Reason[]] -and $getResult.Count -ge 1)
        {
            return $false
        }
        else
        {
            return $true
        }
    }

    [void] Set()
    {
        throw 'The Set method is not implemented for this Audit resource.'
    }
}
#EndRegion '.\Classes\2.GCResources\04.GC_msid232.ps1' 72
#Region '.\Classes\2.GCResources\05.GC_InstalledApplicationLinux.ps1' 0
# val_packages = attribute('packages', description: 'The names of the packages that should be installed.')

# control 'Installed Application Packages' do
#   impact 1.0
#   title 'Verify installed applications'
#   desc 'Validates that application packages are installed'

#   val_packages.each do |val_package|
#     describe package(val_package) do
#         it { should be_installed }
#     end
#   end
# end

# instance of MSFT_ChefInSpecResource as $MSFT_ChefInSpecResource1ref
# {
#     ResourceID = "[ChefInSpec]InstalledApplicationLinuxResource1";
#     SourceInfo = "::11::5::ChefInSpec";
#     Name = "installed_application_linux";
#     ModuleName = "ChefInSpec";
#     ModuleVersion = "1.0";
#     ConfigurationName = "InstalledApplicationLinux";
#     GithubPath = "installed_application_linux/Modules/installed_application_linux_inspec_controls/";
#     AttributesYmlContent = "packages: [Unknown Application]";
# };

[DscResource()]
class GC_InstalledApplicationLinux
{
    [DscProperty(Key)]
    [String] $Name

    [DscProperty()]
    [String] $AttributesYmlContent = "packages: [Unknown Application]"

    [DscProperty(NotConfigurable)]
    [string[]] $PackageShouldBeInstalled = @()

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [GC_InstalledApplicationLinux] Get()
    {
        $this.ConvertAttributesYmlContentToStringArray()

        $getResult = [GC_InstalledApplicationLinux]@{
            Name = $this.Name
        }

        $getResult.PackageShouldBeInstalled = (Get-nxPackageInstalled -Name $this.PackageShouldBeInstalled -ErrorAction Ignore).Name
        $this.PackageShouldBeInstalled.Where({$_ -notin $getResult.PackageShouldBeInstalled}).Foreach({
            $getResult.Reasons += [Reason]@{
                code = '{0}:{0}:Ensure' -f $this.GetType()
                phrase = 'The package ''{0}'' is expected to be installed but could not be found on the local system' -f $_
            }
        })

        $getResult.ConvertStringArrayToAttributeYmlContent()

        return $getResult
    }

    [bool] Test()
    {
        $getResult = $this.Get()
        if ($getResult.Reasons -is [Reason[]] -and $getResult.Count -ge 1)
        {
            return $false
        }
        else
        {
            return $true
        }
    }

    [void] Set()
    {
        throw "Remediation (Set) is not implemented yet."
    }

    [void] ConvertAttributesYmlContentToStringArray()
    {
        # remove 'packages:' from the string
        # split what's in [] with ; separator
        # update $this.PackageShouldBeInstalled
        $stringList = $this.AttributesYmlContent -replace '^packages:\s*\[|^\[|\]$'
        $this.PackageShouldBeInstalled = $stringList -split '\s*;\s*'
    }

    [void] ConvertStringArrayToAttributeYmlContent()
    {
        $this.AttributesYmlContent = $this.PackageShouldBeInstalled -join ';'
    }
}
#EndRegion '.\Classes\2.GCResources\05.GC_InstalledApplicationLinux.ps1' 95
#Region '.\Classes\2.GCResources\06.GC_NotInstalledApplicationLinux.ps1' 0
# val_packages = attribute('packages', description: 'The names of the packages that should not be installed.')

# control 'Not Installed Application Packages' do
#   impact 1.0
#   title 'Verify not installed applications'
#   desc 'Validates that application packages are not installed'

#   val_packages.each do |val_package|
#     describe package(val_package) do
#         it { should_not be_installed }
#     end
#   end
# end


# instance of MSFT_ChefInSpecResource as $MSFT_ChefInSpecResource1ref
# {
#     ResourceID = "[ChefInSpec]NotInstalledApplicationLinuxResource1";
#     SourceInfo = "::11::5::ChefInSpec";
#     Name = "not_installed_application_linux";
#     ModuleName = "ChefInSpec";
#     ModuleVersion = "1.0";
#     ConfigurationName = "NotInstalledApplicationLinux";
#     GithubPath = "not_installed_application_linux/Modules/not_installed_application_linux_inspec_controls/";
#     AttributesYmlContent = "packages: [Unknown Application]";
# };

[DscResource()]
class GC_NotInstalledApplicationLinux
{
    [DscProperty(Key)]
    [String] $Name

    [DscProperty()]
    [String] $AttributesYmlContent = "packages: [Unknown Application]"

    [DscProperty(NotConfigurable)]
    [string[]] $PackageShouldNotBeInstalled = @()

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [GC_NotInstalledApplicationLinux] Get()
    {
        $this.ConvertAttributesYmlContentToStringArray()

        $getResult = [GC_NotInstalledApplicationLinux]@{
            Name = $this.Name
        }

        $getResult.PackageShouldNotBeInstalled = (Get-nxPackageInstalled -Name $this.PackageShouldNotBeInstalled).Name
        $this.PackageShouldNotBeInstalled.Where({$_ -in $getResult.PackageShouldNotBeInstalled}).Foreach({
            $getResult.Reasons += [Reason]@{
                code = '{0}:{0}:Ensure' -f $this.GetType()
                phrase = 'The package ''{0}'' is expected to not be installed but was found on the local system' -f $_
            }
        })

        $getResult.ConvertStringArrayToAttributeYmlContent()
        return $getResult
    }

    [bool] Test()
    {
        $getResult = $this.Get()
        if ($getResult.Reasons -is [Reason[]] -and $getResult.Count -ge 1)
        {
            return $false
        }
        else
        {
            return $true
        }
    }

    [void] Set()
    {
        throw "Remediation (Set) is not implemented yet."
    }

    [void] ConvertAttributesYmlContentToStringArray()
    {
        # remove 'packages:' from the string
        # split what's in [] with ; separator
        # update $this.PackageShouldNotBeInstalled
        $stringList = $this.AttributesYmlContent -replace '^packages:\s*\[|^\[|\]$'
        $this.PackageShouldNotBeInstalled = $stringList -split '\s*;\s*'
    }

    [void] ConvertStringArrayToAttributeYmlContent()
    {
        $this.AttributesYmlContent = $this.PackageShouldNotBeInstalled -join ';'
    }
}
#EndRegion '.\Classes\2.GCResources\06.GC_NotInstalledApplicationLinux.ps1' 95
#Region '.\Classes\2.GCResources\07.GC_LinuxLogAnalyticsAgent.ps1' 0
# instance of GC_OmsAgent as $GC_OmsAgent1ref
# {
#  ModuleVersion = "0.0.1";
#  SourceInfo = "::4::5::GC_OmsAgent";
#  ResourceID = "Audit OmsAgent connection";
#  ModuleName = "nxtools";
#  WorkspaceId = "NotSpecified";
#  ConfigurationName = "OmsAgentConnection";
# };

[DscResource()]
class GC_LinuxLogAnalyticsAgent
{
    [DscProperty(Key)]
    [String] $WorkspaceId = "NotSpecified"

    [DscProperty(NotConfigurable)]
    [String] $AttributesYmlContent = "packages: [omsagent]"

    [DscProperty(NotConfigurable)]
    [string[]] $PackageShouldBeInstalled = @()

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [GC_LinuxLogAnalyticsAgent] Get()
    {
        $getResult = [GC_LinuxLogAnalyticsAgent]@{
            WorkspaceId = $this.WorkspaceId
        }

        $linuxApplicationResource = [GC_InstalledApplicationLinux]@{
            Name = $this.WorkspaceId
            AttributesYmlContent = $this.AttributesYmlContent
        }

        if ($linuxApplicationResource.Test())
        {
            if ($this.WorkspaceId -ieq "NotSpecified")
            {
                $this.Reasons += [Reason]@{
                    code = 'LogAnalyticsAgent:LogAnalyticsAgent:ApplicationInstalled'
                    phrase = 'The Log Analytics agent application is installed.'
                }
            }
            else {
                $this.TestConnectionStatus()
            }
        }
        else
        {
            $this.Reasons += [Reason]@{
                code = 'LogAnalyticsAgent:LogAnalyticsAgent:ApplicationNotInstalled'
                phrase = 'The Log Analytics agent application is not installed.'
            }
        }

        $getResult.Reasons = $this.Reasons
        return $getResult
    }

    [bool] Test()
    {
        $linuxApplicationResource = [GC_InstalledApplicationLinux]@{
            Name = $this.WorkspaceId
            AttributesYmlContent = $this.AttributesYmlContent
        }

        if (-not ($linuxApplicationResource.Test()))
        {
            return $false
        }

        if ($this.WorkspaceId -ieq "NotSpecified")
        {
            return $true
        }

        return $this.TestConnectionStatus()
    }

    [void] Set()
    {
        throw "Remediation (Set) is not implemented."
    }

    [bool] TestConnectionStatus()
    {
        $workspaceDir = Get-ChildItem '/etc/opt/microsoft/omsagent' -ErrorAction SilentlyContinue
        $connectedWorkspaceIds = @()
        $workspaceDir | ForEach-Object { if (($_.Name -match '(?im)^[{(]?[0-9A-F]{8}[-]?(?:[0-9A-F]{4}[-]?){3}[0-9A-F]{12}[)}]?$')) { $connectedWorkspaceIds = $connectedWorkspaceIds + $_.Name } }

        $reasonCodePrefix = 'LogAnalyticsAgent:LogAnalyticsAgent'
        $ComplianceStatus = $false
        if ($connectedWorkspaceIds.Count -eq 0)
        {
            $this.Reasons += [Reason]@{
                code = $reasonCodePrefix + ':WorkspaceNotFound'
                phrase = 'The Log Analytics agent application is not connected to any workspace.'
            }
        }
        else
        {
            $ComplianceStatus = $true
            $notConnectedWorkspaceIds = @()
            if (-not($this.WorkspaceId -ieq "NotSpecified"))
            {
                $workspaceIdList = @($this.WorkspaceId.Split(';').Trim())
                $workspaceIdList = $workspaceIdList.ToLower()
                $connectedWorkspaceIds = $connectedWorkspaceIds.ToLower()
                foreach ($individualWorkspaceId in $workspaceIdList)
                {
                    if (-not($connectedWorkspaceIds -match $individualWorkspaceId))
                    {
                        $ComplianceStatus = $false
                        $notConnectedWorkspaceIds = $notConnectedWorkspaceIds + $individualWorkspaceId
                    }
                }
            }

            if ($ComplianceStatus)
            {
                $this.Reasons += [Reason]@{
                    code = $reasonCodePrefix + ':ConnectedWorkspaces'
                    phrase = "{0}" -f ($connectedWorkspaceIds -join ';')
                }
            }
            else
            {
                $this.Reasons += [Reason]@{
                    code = $reasonCodePrefix + ':WorkspaceNotFound'
                    phrase = 'Could not find a workspace with the specified workspace ID ''{0}'' connected to this machine.' -f ($notConnectedWorkspaceIds -join ';')
                }
            }
        }

        return $ComplianceStatus
    }
}
#EndRegion '.\Classes\2.GCResources\07.GC_LinuxLogAnalyticsAgent.ps1' 140
#Region '.\Classes\3.Packages\00.nxDebPackage.ps1' 0
#using module Package
class nxDebPackage : nxPackage
{
    # https://www.debian.org/doc/debian-policy/ch-controlfields.html

    # This field identifies the source package name.
    $Source

    # The package maintainer’s name and email address.
    # The name must come first, then the email address inside angle brackets <> (in RFC822 format).
    $Maintainer

    # List of the names and email addresses of co-maintainers of the package, if any.
    $Uploaders

    # The name and email address of the person who prepared this version of the package,
    # usually a maintainer. The syntax is the same as for the Maintainer field.
    $ChangedBy

    # This field specifies an application area into which the package has been classified.
    # See Sections.
    $Section

    # This field represents how important it is that the user have the package installed.
    # See Priorities.
    $Priority

    # The name of the binary package.
    # Binary package names must follow the same syntax and restrictions as source package names.
    # See Source for the details.
    # This also populates the Name property of the [Package] parent class
    $Package

    # Depending on context and the control file used, the Architecture field can include the following sets of values:
    #  - A unique single word identifying a Debian machine architecture as described in Architecture specification strings.
    #    (https://www.debian.org/doc/debian-policy/ch-customized-programs.html#s-arch-spec)
    #  - An architecture wildcard identifying a set of Debian machine architectures, see Architecture wildcards.
    #    (https://www.debian.org/doc/debian-policy/ch-customized-programs.html#s-arch-wildcard-spec)
    #    `any` matches all Debian machine architectures and is the most frequently used.
    #  - all, which indicates an architecture-independent package.
    #  - source, which indicates a source package.
    $Architecture

    # This is a boolean field which may occur only in the control file of a binary package or
    # in a per-package fields paragraph of a source package control file.
    # If set to yes then the package management system will refuse to remove the package
    # (upgrading and replacing it is still possible).
    # The other possible value is no, which is the same as not having the field at all.
    $Essential

    #region Package interrelationship fields
    # These fields describe the package’s relationships with other packages.
    # Their syntax and semantics are described in Declaring relationships between packages.
    # (https://www.debian.org/doc/debian-policy/ch-relationships.html)

    $Depends
    $PreDepends
    $Recommends
    $Suggests
    $Breaks
    $Conflicts
    $Provides
    $Replaces
    $Enhances

    #endregion Package interrelationship fields

    $StandardsVersion

    # $Version # defined in Parent Class [Package]
    $Description

    $Distribution
    $Date
    $Format
    $Urgency
    $Changes
    $Binary
    $InstalledSize
    $Files
    $Closes
    $Homepage
    $ChecksumsSha1
    $ChecksumsSha256
    $DMUploadAllowed # obsolete
    $PackageList
    $PackageType
    $Dgit
    $TestSuite
    $RulesRequiresRoot

    # Additional Fields
    $Status
    $OriginalMaintainer
    $MultiArch
    $Conffiles
    $AdditionalFields = @{}

    $Vendor

    nxDebPackage()
    {
        # Default constructor
    }

    nxDebPackage([hashtable]$Properties)
    {
        $this.SetProperties($Properties)
    }

    hidden [void] SetProperties([hashtable]$Properties)
    {
        foreach ($propertyName in $properties.keys)
        {
            $this.($propertyName) = $properties[$propertyName]
        }

        if ($properties.keys -contains 'package' -and $properties.keys -notcontains 'name')
        {
            $this.Name = $properties['package']
        }
    }
}
#EndRegion '.\Classes\3.Packages\00.nxDebPackage.ps1' 124
#Region '.\Classes\3.Packages\01.nxDpkgPackage.ps1' 0
#using module Package
class nxDpkgPackage : nxDebPackage
{
    # Same fields as Deb packages

    nxDpkgPackage()
    {
        #Default ctor
    }

    nxDpkgPackage([hashtable]$Properties)
    {
        $this.SetProperties($Properties)
    }
}
#EndRegion '.\Classes\3.Packages\01.nxDpkgPackage.ps1' 16
#Region '.\Classes\3.Packages\02.nxYumPackage.ps1' 0

class nxYumPackage : nxPackage
{
    $Arch
    $Release
    $Size
    $Repo
    $FromRepo
    $Summary
    $Url
    $License
    $Description

    $AdditionalFields = @{}
}
#EndRegion '.\Classes\3.Packages\02.nxYumPackage.ps1' 16
#Region '.\Classes\3.Packages\03.nxAptPackage.ps1' 0
class nxAptPackage : nxDebPackage
{
    #Extends nxDebPackage
    $FileName
    $Descriptionmd5
    $Size
    $MD5sum
    $Origin
    $License
    $SHA512
    $SHA256
    $SHA1
    $Descriptionen

    nxAptPackage()
    {
        #Default ctor
    }

    nxAptPackage([hashtable]$Properties)
    {
        $this.SetProperties($Properties)
    }
}
#EndRegion '.\Classes\3.Packages\03.nxAptPackage.ps1' 25
#Region '.\Classes\4.Services\nxSystemdService.ps1' 0
#using namespace System.Collections

class nxSystemdService : nxService
{
    # [string] $Name # Defined in Parent class
    [string] $Load
    [string] $Active
    # [nxServiceState] $State # Defined in parent class
    [string] $Status # Specific to Systemctl
    [string] $Description

    [Reason[]] $Reasons

    nxSystemdService()
    {
        # default ctor
    }

    nxSystemdService([IDictionary] $Definition)
    {
        if (-not [string]::IsNullOrEmpty($Definition.name) -and $Definition['name'] -notmatch '\.service')
        {
            # Systemctl version 219 and prior do not support short names.
            $Definition['name'] = '{0}.service' -f $Definition['name']
        }

        $this.SetNxServiceProperties($Definition)
    }

    hidden [void] SetNxServiceProperties([IDictionary] $Definition)
    {
        foreach ($property in $Definition.Keys.Where{$_ -in $this.PSObject.Properties.Where{$_.IsSettable}.Name})
        {
            $this.($property) = $Definition[$property]
        }

        if (-not $Definition.ContainsKey('enabled'))
        {
            $this.Enabled = $this.isEnabled()
        }
    }

    [bool] IsEnabled()
    {
        [bool] $result = $false
        switch -regex (Invoke-NativeCommand -Executable 'systemctl' -Parameters @('is-enabled',$this.Name))
        {
            '^enabled$'
            {
                $result = $true
                $this.Status = $_
            }

            default
            {
                $result = $false
                $this.Status = $_
            }
        }

        $this.Enabled = $result
        return $result
    }

    [bool] IsRunning()
    {
        [bool] $result = $false
        switch -regex (Invoke-NativeCommand -Executable 'systemctl' -Parameters @('is-active', $this.Name))
        {
            '^active$'
            {
                $result = $true
                $this.Active = 'active'
                $this.State = [nxServiceState]::Running
            }

            default
            {
                Write-Verbose -Message ('The service ''{1}'' is ''{0}''.' -f $_, $this.Name)
                $this.Active = $_
                $this.State = [nxServiceState]::Stopped
                $result = $false
            }
        }

        return $result
    }
}
#EndRegion '.\Classes\4.Services\nxSystemdService.ps1' 89
#Region '.\Private\Convert-ObjectToHashtable.ps1' 0

function Convert-ObjectToHashtable
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]
        [Alias('Object')]
        $InputObject
    )

    process
    {

        $hashResult = @{}

        $InputObject.psobject.Properties | Foreach-Object {
            $hashResult[$_.Name] = $_.Value
        }

        return $hashResult
    }
}
#EndRegion '.\Private\Convert-ObjectToHashtable.ps1' 26
#Region '.\Private\Get-nxEscapedPath.ps1' 0
function Get-nxEscapedPath
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(ValueFromPipeline = $true)]
        [System.String]
        $Path
    )

    process
    {
        return ('"{0}"' -f $Path)
    }
}
#EndRegion '.\Private\Get-nxEscapedPath.ps1' 17
#Region '.\Private\Get-nxEscapedString.ps1' 0
function Get-nxEscapedString
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(ValueFromPipeline = $true)]
        [System.String]
        $String
    )

    process
    {
        return ('''{0}''' -f ($String -replace "\'","''"))
    }
}
#EndRegion '.\Private\Get-nxEscapedString.ps1' 17
#Region '.\Private\Get-nxInitSystem.ps1' 0
function Get-nxInitSystem
{
    [OutputType([nxInitSystem])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [switch]
        $Force
    )
    if ($script:nxInitSystem -and -not $Force.IsPresent)
    {
        Write-Debug -Message "Returning nxInitSystem from module variable."
    }
    else
    {
        Write-Debug -Message "Evaluating nxInitSystem."
        $initPath = Get-Item -ErrorAction SilentlyContinue -Path '/sbin/init'

        if ($initPath.LinkType -ne 'SymbolicLink')
        {
            # It's a hard path, so probably using initd
            $script:nxInitSystem = [nxInitSystem]::initd
        }
        elseif ($initPath.LinkTarget -match 'systemd$')
        {
            $script:nxInitSystem =  [nxInitSystem]::systemd
        }
        elseif ($initPath.LinkTarget -match 'sysvinit')
        {
            $script:nxInitSystem =  [nxInitSystem]::sysvinit
        }
        elseif ($initPath.LinkTarget -match 'busybox')
        {
            $script:nxInitSystem =  [nxInitSystem]::busybox
        }
        else
        {
            $script:nxInitSystem =  [nxInitSystem]::unknown
        }
    }

    return $script:nxInitSystem
}
#EndRegion '.\Private\Get-nxInitSystem.ps1' 45
#Region '.\Private\Get-nxSourceFile.ps1' 0
function Get-nxSourceFile
{
    [CmdletBinding()]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]
        [ValidateScript({$null -ne ($_ -as [uri]).Scheme -or (Test-Path -Path $_ -PathType Leaf)})]
        [Alias('Uri')]
        $Path,

        [Parameter()]
        [System.String]
        $DestinationFile,

        [Parameter()]
        [System.Management.Automation.SwitchParameter]
        $Force
    )

    if (-not $PSBoundParameters.ContainsKey('DestinationFile'))
    {
        $fileName = [System.Io.FileInfo](Split-Path -Leaf $Path)
        if ($null -ne ($Path -as [uri]).Scheme -and -not [string]::IsNullOrEmpty($fileName.Extension))
        {
            $DestinationFile = $fileName
        }
    }

    if (Test-Path -Path $DestinationFile)
    {
        if ($Force.IsPresent)
        {
            Remove-Item -Force -Recurse -Path $DestinationFile
        }
        else
        {
            throw ('File ''{0}'' already exists.' -f $DestinationFile)
        }
    }

    if ($Path -as [uri] -and ([uri]$Path).Scheme -match '^http|^ftp')
    {
        $null = Invoke-WebRequest -Uri $Path -OutFile $DestinationFile -ErrorAction 'Stop'
    }
    else
    {
        Copy-Item -Path $Path -Destination $DestinationFile -ErrorAction Stop -Force:$Force
    }
}
#EndRegion '.\Private\Get-nxSourceFile.ps1' 51
#Region '.\Private\nxFileSystem\Convert-nxFileSystemAccessRightToSymbol.ps1' 0
function Convert-nxFileSystemAccessRightToSymbol
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String[]]
        [ValidateScript({$_ -as [nxFileSystemAccessRight] -or $_ -as [nxFileSystemSpecialMode]})]
        $AccessRight,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [nxFileSystemUserClass]
        [Alias('Class')]
        $UserClass,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [System.Management.Automation.SwitchParameter]
        $UseDashWhenAbsent
    )

    process {

        Write-Verbose "Access Right: '$($AccessRight -join "', '")'"

        [nxFileSystemAccessRight]$AccessRightEntry = 'none'
        [nxFileSystemSpecialMode]$SpecialModeEntry = 'none'

        $AccessRight.ForEach({
            if ($_ -as [nxFileSystemAccessRight])
            {
                $AccessRightEntry = $AccessRightEntry -bor [nxFileSystemAccessRight]$_
            }
            elseif ($_ -as [nxFileSystemSpecialMode])
            {
                $SpecialModeEntry = $SpecialModeEntry -bor [nxFileSystemSpecialMode]$_
            }
        })

        Write-Debug -Message "AccessRight: '$AccessRightEntry', SpecialMode: $SpecialModeEntry"

        $Symbols = @(
            $AccessRightEntry -band [nxFileSystemAccessRight]::Read ? 'r' : ($UseDashWhenAbsent ? '-':'')
            $AccessRightEntry -band [nxFileSystemAccessRight]::Write ? 'w' : ($UseDashWhenAbsent ? '-':'')

            if (
                $UserClass -band [nxFileSystemUserClass]::Group -and
                $SpecialModeEntry -band [nxFileSystemSpecialMode]::SetGroupId -and
                $AccessRightEntry -band [nxFileSystemAccessRight]::Execute
            )
            {
                's'
            }
            elseif (
                $UserClass -band [nxFileSystemUserClass]::Group -and
                $SpecialModeEntry -band [nxFileSystemSpecialMode]::SetGroupId
            )
            {
                'S'
            }
            elseif (
                $UserClass -band [nxFileSystemUserClass]::User -and
                $SpecialModeEntry -band [nxFileSystemSpecialMode]::SetUserId -and
                $AccessRightEntry -band [nxFileSystemAccessRight]::Execute
            )
            {
                's'
            }
            elseif (
                $UserClass -band [nxFileSystemUserClass]::User -and
                $SpecialModeEntry -band [nxFileSystemSpecialMode]::SetUserId
            )
            {
                'S'
            }
            elseif (
                $UserClass -band [nxFileSystemUserClass]::Others -and
                $SpecialModeEntry -band [nxFileSystemSpecialMode]::StickyBit -and
                $AccessRightEntry -band [nxFileSystemAccessRight]::Execute
            )
            {
                't'
            }
            elseif (
                $UserClass -band [nxFileSystemUserClass]::Others -and
                $SpecialModeEntry -band [nxFileSystemSpecialMode]::StickyBit
            )
            {
                'T'
            }
            elseif ($AccessRightEntry -band [nxFileSystemAccessRight]::Execute)
            {
                'x'
            }
            elseif ($UseDashWhenAbsent)
            {
                '-'
            }
        )

        Write-Verbose -Message "Symbols: '$($Symbols -join '')'."
        ($Symbols -join '')
    }
}
#EndRegion '.\Private\nxFileSystem\Convert-nxFileSystemAccessRightToSymbol.ps1' 104
#Region '.\Private\nxFileSystem\Convert-nxFileSystemModeComparisonToSymbolicOperation.ps1' 0
function Convert-nxFileSystemModeComparisonToSymbolicOperation
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Class')]
        [nxFileSystemUserClass]
        $UserClass,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]
        [ValidateScript({$_ -as [nxFileSystemAccessRight] -or $_ -as [nxFileSystemSpecialMode]})]
        [Alias('InputObject')]
        $EnumValue,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [string]
        $SideIndicator
    )

    process {
        # FTR the side indicator points where the EnumValue is found: REFERENCE <=> DIFFERENCE
        # The SympolicOperation generated aims to make the DifferenceMode compliante with the reference.

        Write-Debug "[$UserClass] [$EnumValue] [$SideIndicator]"

        if ($SideIndicator -eq '<=')
        {
            # Need to add something that is not in the reference
            $operator = '+'
        }
        else
        {
            # Need to remove something that is not in the reference
            $operator = '-'
        }

        $UserClassSymbol = Convert-nxFileSystemUserClassToSymbol -UserClass $UserClass
        $ModeSymbol = Convert-nxFileSystemAccessRightToSymbol -AccessRight $EnumValue -UserClass $UserClass

        return ('{0}{1}{2}' -f $UserClassSymbol, $operator, $ModeSymbol)
    }
}
#EndRegion '.\Private\nxFileSystem\Convert-nxFileSystemModeComparisonToSymbolicOperation.ps1' 46
#Region '.\Private\nxFileSystem\Convert-nxFileSystemUserClassToSymbol.ps1' 0
function Convert-nxFileSystemUserClassToSymbol
{
    [CmdletBinding()]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [nxFileSystemUserClass]
        [Alias('Class')]
        $UserClass
    )

    $symbols = switch ($UserClass)
    {
        ([nxFileSystemUserClass]::User)   { 'u' }
        ([nxFileSystemUserClass]::Group)  { 'g' }
        ([nxFileSystemUserClass]::Others) { 'o' }
    }

    return ($symbols -join '')
}
#EndRegion '.\Private\nxFileSystem\Convert-nxFileSystemUserClassToSymbol.ps1' 22
#Region '.\Private\nxFileSystem\Convert-nxLsEntryToFileSystemInfo.ps1' 0
function Convert-nxLsEntryToFileSystemInfo
{
    [CmdletBinding()]
    [OutputType([nxFileSystemInfo])]
    param
    (
        [Parameter(ValueFromPipeline = $true)]
        [System.String]
        $lsLine,

        [Parameter()]
        [System.String]
        $InitialPath = '.',

        [Parameter()]
        [scriptblock]
        $ErrorHandler = {
            switch -Regex ($_)
            {
                default { Write-Error -Message $_ }
            }
        }
    )

    begin {
        $lastParent = $null
    }

    process {
        foreach ($lineToParse in $lsLine.Where{$_})
        {
            Write-Verbose -Message "Parsing ls line output: '$lineToParse'."

            if ($lineToParse -is [System.Management.Automation.ErrorRecord])
            {
                Write-Debug -Message 'Dispatching to ErrorHandler...'
                $lineToParse | &$ErrorHandler
            }
            elseif ($lineToParse -match '^/.*ls:\s(?<message>.*)')
            {
                Write-Error -Message $Matches.message
            }
            elseif ($lineToParse -match '^\s*total')
            {
                Write-Verbose -Message $lineToParse
            }
            elseif ($lineToParse -match '^(?<parent>/.*):$')
            {
                $lastParent = $Matches.parent
            }
            else
            {
                $Mode, $nxLinkCount, $nxOwner, $nxGroup, $Length, $lastModifyDate, $lastModifyTime, $lastModifyTimezone, $fileName = $lineToParse -split '\s+',9
                $nxFileSystemItemType = switch ($Mode[0])
                {
                    '-' { 'File' }
                    'd' { 'Directory' }
                    'l' { 'Link' }
                    'p' { 'Pipe' }
                    's' { 'socket' }
                }

                $lastWriteTime = Get-Date -Date ($lastModifyDate + " " + $lastModifyTime + $lastModifyTimezone)

                # Maybe there's no $lastParent yet (top folder from search Path)
                if ($null -eq $lastParent)
                {
                    if ($InitialPath -eq [io.Path]::GetFullPath($fileName, $PWD.Path))
                    {
                        Write-Debug -Message "No `$lastParent and Initial path is '$InitialPath' same as file name is '$fileName'."
                        # no Last parent and the InitialPath is the same as the file Name. (i.e. ./CHANGELOG.md or CHANGELOG.md)
                        $lastParent = [io.path]::GetFullPath("$InitialPath/..")
                    }
                    else
                    {
                        $lastParent = [io.Path]::GetFullPath($InitialPath)
                    }

                    $fullPath = [io.Path]::GetFullPath($fileName, $lastParent)
                }
                else
                {
                    Write-Debug -Message "`$lastParent is '$lastParent', Initial Path is '$InitialPath' and file name is '$fileName'."
                    $fullPath = [io.path]::GetFullPath($fileName, $lastParent)
                }

                [nxFileSystemInfo]::new(
                    @{
                        FullPath                = $fullPath
                        LastWriteTime           = $lastWriteTime
                        nxFileSystemItemType    = $nxFileSystemItemType
                        nxOwner                 = $nxOwner
                        nxGroup                 = $nxGroup
                        Length                  = [long]::Parse($Length)
                        nxLinkCount             = $nxLinkCount
                        Mode                    = $Mode
                    }
                )
            }
        }
    }
}
#EndRegion '.\Private\nxFileSystem\Convert-nxLsEntryToFileSystemInfo.ps1' 103
#Region '.\Private\nxFileSystem\Convert-nxSymbolToFileSystemAccessRight.ps1' 0
function Convert-nxSymbolToFileSystemAccessRight
{
    [CmdletBinding()]
    [OutputType([nxFileSystemAccessRight])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Char[]]
        [Alias('Char')]
        $AccessRightSymbol
    )

    process {
        foreach ($charItem in $AccessRightSymbol)
        {
            switch -CaseSensitive ($charItem)
            {
                'w'
                {
                    [nxFileSystemAccessRight]::Write
                }

                'r'
                {
                    [nxFileSystemAccessRight]::Read
                }

                'x'
                {
                    [nxFileSystemAccessRight]::Execute
                }

                '-'
                {
                    [nxFileSystemAccessRight]::None
                }

                'T'
                {
                    Write-Debug -Message "The UpperCase 'T' means there's no Execute right."
                    [nxFileSystemAccessRight]::None
                }

                't'
                {
                    [nxFileSystemAccessRight]::Execute
                }

                'S'
                {
                    Write-Debug -Message "The UpperCase 'S' means there's no Execute right."
                    [nxFileSystemAccessRight]::None
                }

                's'
                {
                    [nxFileSystemAccessRight]::Execute
                }
            }
        }
    }
}
#EndRegion '.\Private\nxFileSystem\Convert-nxSymbolToFileSystemAccessRight.ps1' 63
#Region '.\Private\nxFileSystem\Convert-nxSymbolToFileSystemSpecialMode.ps1' 0
function Convert-nxSymbolToFileSystemSpecialMode
{
    [CmdletBinding()]
    [OutputType([nxFileSystemSpecialMode])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Char[]]
        [Alias('Char')]
        # the possible char are [sStT], but if other values sucha as [rwx-] are passed, we should just ignore them (no special permission).
        $SpecialModeSymbol,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [nxFileSystemUserClass]
        $UserClass
    )

    process {
        foreach ($charItem in $SpecialModeSymbol)
        {
            Write-Debug -Message "Converting '$charItem' to [nxFileSystemSpecialMode]."
            switch ($charItem)
            {
                't'
                {
                    Write-Debug -Message "Adding StickyBit."
                    [nxFileSystemSpecialMode]::StickyBit
                }

                's'
                {
                    if ($UserClass -eq [nxFileSystemUserClass]::User)
                    {
                        Write-Debug -Message "Adding SetUserId."
                        [nxFileSystemSpecialMode]::SetUserId
                    }

                    if ($UserClass -band [nxFileSystemUserClass]::Group)
                    {
                        Write-Debug -Message "Adding SetGroupId."
                        [nxFileSystemSpecialMode]::SetGroupId
                    }

                    if ((-not $UserClass -band [nxFileSystemUserClass]::Group) -and (-not $UserClass -eq [nxFileSystemUserClass]::User))
                    {
                        Write-Warning -Message "Cannot determine whether to set the SUID or SGID because the User class is invalid: '$UserClass'"
                    }
                }

                default {
                    Write-Debug -Message "Nothing to return for char '$charItem'."
                }
            }
        }
    }
}
#EndRegion '.\Private\nxFileSystem\Convert-nxSymbolToFileSystemSpecialMode.ps1' 57
#Region '.\Private\nxFileSystem\Convert-nxSymbolToFileSystemUserClass.ps1' 0
function Convert-nxSymbolToFileSystemUserClass
{
    [CmdletBinding()]
    [OutputType([nxFileSystemUserClass])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [char[]]
        $Char
    )

    process {
        foreach ($charItem in $char)
        {
            switch ($charItem)
            {
                'u' { [nxFileSystemUserClass]'User'   }
                'g' { [nxFileSystemUserClass]'Group'  }
                'o' { [nxFileSystemUserClass]'Others' }
                'a' { [nxFileSystemUserClass]'User, Group, Others' }
                default { throw "Unexpected char '$CharItem'" }
            }
        }
    }
}
#EndRegion '.\Private\nxFileSystem\Convert-nxSymbolToFileSystemUserClass.ps1' 26
#Region '.\Private\nxFileSystem\Get-FileHashAlgorithmFromHash.ps1' 0
function Get-FileHashAlgorithmFromHash
{
    [CmdletBinding()]
    [OutputType([String])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]
        [Alias('Hash')]
        $FileHash
    )

    switch ($FileHash.Length)
    {
        32
        {
            'MD5'
        }

        40
        {
            'SHA1'
        }

        64
        {
            'SHA256'
        }

        128
        {
            'SHA512'
        }

        default
        {
            throw ('Could not resolve the Algorith used for hash ''{0}''' -f $FileHash)
        }
    }
}
#EndRegion '.\Private\nxFileSystem\Get-FileHashAlgorithmFromHash.ps1' 41
#Region '.\Private\services\systemd\Disable-nxSystemdService.ps1' 0
function Disable-nxSystemdService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Name
    )

    process
    {
        foreach ($serviceName in $Name)
        {
            Write-Verbose -Message ('Disabling service ''{0}''.' -f $serviceName)
            Invoke-NativeCommand -Executable 'systemctl' -Parameters @('disable',$serviceName) | ForEach-Object -Process {
                if ($_ -is [System.Management.Automation.ErrorRecord])
                {
                    Write-Error -Exception $_
                }
                else
                {
                    Write-Verbose -Message $_
                }
            }
        }
    }
}
#EndRegion '.\Private\services\systemd\Disable-nxSystemdService.ps1' 30
#Region '.\Private\services\systemd\Enable-nxSystemdService.ps1' 0
function Enable-nxSystemdService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Name,

        [Parameter()]
        [switch]
        $Now
    )

    process
    {
        foreach ($serviceName in $Name)
        {
            Write-Verbose -Message ('Enabling service ''{0}''.' -f $serviceName)
            $systemctlEnableParams = @('enable',$serviceName)
            if ($Now.IsPresent)
            {
                $systemctlEnableParams += '--now'
            }

            Invoke-NativeCommand -Executable 'systemctl' -Parameters $systemctlEnableParams | ForEach-Object -Process {
                if ($_ -is [System.Management.Automation.ErrorRecord])
                {
                    Write-Error -Exception $_
                }
                elseif (-not [string]::isnullorempty($_))
                {
                    Write-Verbose -Message $_
                }
            }
        }
    }
}
#EndRegion '.\Private\services\systemd\Enable-nxSystemdService.ps1' 40
#Region '.\Private\services\systemd\Get-nxSystemdService.ps1' 0
function Get-nxSystemdService
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [string[]]
        [Alias('Unit')]
        $Name
    )

    if (-not (Get-Command -Name 'systemctl' -ErrorAction SilentlyContinue))
    {
        throw 'systemctl not found'
    }

    $systemctlParams = @('--type=service', '--no-legend', '--all', '--no-pager')
    if ($PSBoundParameters.ContainsKey('Name'))
    {
        # Because systemctl version 219 and below do not support short name (i.e. centos 7.5)
        $Name = $Name.Foreach{
            if ($_ -notmatch '\.service')
            {
                '{0}.service' -f $_
            }
            else
            {
                $_
            }
        }

        $systemctlParams = $systemctlParams + $Name
    }

    Invoke-NativeCommand -Executable 'systemctl' -Parameters (@('list-units') + $systemctlParams) | ForEach-Object -Process {
        if ($_ -is [System.Management.Automation.ErrorRecord])
        {
            Write-Error -Message $_
        }
        else
        {
            $id, $Load, $Active, $Status, $Description = $_ -split '\s+',5
            $State = if ($Active -eq 'Active')
            {
                [nxServiceState]::Running
            }
            else
            {
                [nxServiceState]::Stopped
            }

            $service = [nxSystemdService]@{
                name        = $id
                Load        = $Load
                Active      = $Active
                State       = $State
                Status      = $status
                Description = $Description
            }

            $null = $service.IsEnabled() # runs the systemctl is-enabled and update the property
            return $service
        }
    }
}
#EndRegion '.\Private\services\systemd\Get-nxSystemdService.ps1' 66
#Region '.\Private\services\systemd\Restart-nxSystemdService.ps1' 0
function Restart-nxSystemdService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Name
    )

    process
    {
        foreach ($serviceName in $Name)
        {
            Write-Verbose -Message ('Restarting Service ''{0}''.' -f $serviceName)
            Invoke-NativeCommand -Executable 'systemctl' -Parameters @('restart',$serviceName) | ForEach-Object -Process {
                if ($_ -is [System.Management.Automation.ErrorRecord])
                {
                    Write-Error -Exception $_
                }
                else
                {
                    Write-Verbose -Message $_
                }
            }
        }
    }
}
#EndRegion '.\Private\services\systemd\Restart-nxSystemdService.ps1' 30
#Region '.\Private\services\systemd\Start-nxSystemdService.ps1' 0
function Start-nxSystemdService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Name
    )

    process
    {
        foreach ($serviceName in $Name)
        {
            Write-Verbose -Message ('Starting service ''{0}''.' -f $serviceName)
            Invoke-NativeCommand -Executable 'systemctl' -Parameters @('start',$serviceName) | ForEach-Object -Process {
                if ($_ -is [System.Management.Automation.ErrorRecord])
                {
                    Write-Error -Exception $_
                }
                else
                {
                    Write-Verbose -Message $_
                }
            }
        }
    }
}
#EndRegion '.\Private\services\systemd\Start-nxSystemdService.ps1' 30
#Region '.\Private\services\systemd\Stop-nxSystemdService.ps1' 0
function Stop-nxSystemdService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        $Name
    )

    process
    {
        foreach ($serviceName in $Name)
        {
            Write-Verbose -Message ('Stopping service ''{0}''.' -f $serviceName)
            Invoke-NativeCommand -Executable 'systemctl' -Parameters @('stop',$serviceName) | ForEach-Object -Process {
                if ($_ -is [System.Management.Automation.ErrorRecord])
                {
                    Write-Error -Exception $_
                }
                else
                {
                    Write-Verbose -Message $_
                }
            }

        }
    }
}
#EndRegion '.\Private\services\systemd\Stop-nxSystemdService.ps1' 31
#Region '.\Public\Archive\Compress-nxArchive.ps1' 0

<#
.SYNOPSIS
Command to tar or archive files and folders using the GNU 'tar' command.

.DESCRIPTION
This command saves files and folders together in a single archive, with optional compression.
The command is a wrapper for the command 'tar' that ought to be availble on the system to
be able to use the command.

.PARAMETER Path
Array of Path to the files and folder to add to the archive.

.PARAMETER Destination
Destination of the archive to create or to add the file and folders to.

.PARAMETER Compression
Specify the type of compression to use for the archive: auto, bzip2, xz, lzma, gzip.
By default, the compression is set to 'auto' where the tar command will try to discover what
to use based on the file's extension.

.PARAMETER Exclude
Array of Patterns used to exclude any file matching any of those patterns.

.PARAMETER FollowSymLinks
Follow symlinks to archive the files they refer to.

.PARAMETER Force
Force create the Destination folder if it does not exist.

.EXAMPLE
Compress-nxArchive -Path .\home -Destination ./bkp/homedirs.bzip

.NOTES
If you use the -Verbose parameter, you can see what command is invoked and its parameters.
#>

function Compress-nxArchive
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String[]]
        [Alias('FullName')]
        $Path,

        [Parameter(Mandatory = $true)]
        [String]
        $Destination,

        [Parameter()]
        [nxArchiveAlgorithm[]]
        $Compression = 'Auto',

        [Parameter()]
        [String[]]
        $Exclude,

        [Parameter()]
        [switch]
        $FollowSymLinks,

        [Parameter()]
        [Switch]
        $Force
    )

    begin
    {
        $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])

        $tarVerbose = ''
        if ($verbose)
        {
            $tarVerbose = 'v'
        }

        $tarParams = @('-c{0}' -f $tarVerbose)

        $compressWith = @()

        switch ($Compression)
        {
            'auto'
            {
                Write-Debug -Message 'Skipping algo. Letting Tar discover using the file extension.'
                break
            }

            'bzip2'
            {
                $compressWith += @('j')
            }

            'xz'
            {
                $compressWith += @('J')
            }

            'lzma'
            {
                $compressWith += @('a')
            }

            'gzip'
            {
                $compressWith += @('z')
            }
        }

        if ($compressWith.Count -gt 0)
        {
            $tarParams += @(('-{0}' -f ($compressWith -join '')))
        }
        else
        {
            Write-Debug -Message "Auto compression detection for '$Destination'."
        }

        if ($PSBoundParameters.ContainsKey('Destination'))
        {
            $tarParams += @('-f', (Get-nxEscapedString -String $Destination))
            $destinationParent = Split-Path -Parent -Path ([io.Path]::GetFullPath($Destination))
            if ($Force.IsPresent -and -not (Test-Path -Path $destinationParent))
            {
                $null = New-Item -Path $destinationParent -Force
            }
        }

        if ($FollowSymLinks.IsPresent)
        {
            $tarParams += @('-h')
        }

        foreach ($excludePattern in $Exclude)
        {
            $tarParams += @('--exclude', (Get-nxEscapedString -String $excludePattern))
        }
    }

    process
    {
        foreach ($PathItem in $Path)
        {
            Write-Debug -Message "Preparing to compress $PathItem..."
            $tarParams += @($PathItem)
        }
    }

    end
    {
        if ($PSCmdlet.ShouldProcess(
            "Compressing using the unix command 'tar $($tarParams -join ' ')'.",
            $UserNameItem,
            "Compressing [$($Path -join ',')] to '$Destination'.")
        )
        {
            Invoke-NativeCommand -Executable 'tar' -Parameters $tarParams -Verbose:$verbose |
                ForEach-Object -Process {
                    if ($_ -match '^tar:')
                    {
                        Write-Error $_
                    }
                    else
                    {
                        Write-Verbose -Message $_
                    }
                }

            $destinationFullName = [io.Path]::GetFullPath($Destination)
            if (Test-Path -Path $destinationFullName)
            {
                $destinationFullName
            }
        }
    }
}
#EndRegion '.\Public\Archive\Compress-nxArchive.ps1' 180
#Region '.\Public\Archive\Expand-nxArchive.ps1' 0
function Expand-nxArchive
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String[]]
        $Path,

        [Parameter()]
        [String]
        [ValidateNotNullOrEmpty()]
        [Alias('ExtractTo')]
        $Destination,

        [Parameter()]
        [nxArchiveAlgorithm[]]
        $Compression = 'Auto',

        [Parameter()]
        [Switch]
        $ListOnly,

        [Parameter()]
        [Switch]
        $Force
    )

    begin
    {
        $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])
        $tarParams = @()

        $tarVerbose = ''
        if ($verbose)
        {
            $tarVerbose = 'v'
        }

        if ($ListOnly.IsPresent)
        {
            $tarParams += @('-t{0}' -f $tarVerbose)
        }
        else
        {
            $tarParams += @('-x{0}' -f $tarVerbose)
        }

        switch ($Compression)
        {
            'auto'
            {
                Write-Debug -Message 'Skipping algo. Letting Tar discover using the file extension.'
                break
            }

            'bzip2'
            {
                $compressWith += @('j')
            }

            'xz'
            {
                $compressWith += @('J')
            }

            'lzma'
            {
                $compressWith += @('a')
            }

            'gzip'
            {
                $compressWith += @('z')
            }
        }

        if ($decompressWith.Count -gt 0)
        {
            $tarParams += @(('-{0}' -f ($decompressWith -join '')))
        }
        else
        {
            Write-Debug -Message "Auto compression detection for $Destination."
        }

        if ($PSBoundParameters.ContainsKey('Destination'))
        {
            $tarParams += @('-C', $Destination)
            if ($Force.IsPresent -and -not (Test-Path -Path $Destination))
            {
                $null = New-Item -Path $Destination -ItemType Directory -Force
            }
        }
    }

    process
    {

        foreach ($pathItem in $Path)
        {
            $tarParams += @('-f', (Get-nxEscapedPath -Path $pathItem))

            if ($PSCmdlet.ShouldProcess(
                "Extracting using the unix command 'tar $($tarParams -join ' ')'.",
                $pathItem,
                "Extracting '$pathItem' to '$Destination'.")
            )
            {
                Invoke-NativeCommand -Executable 'tar' -Parameters $tarParams -Verbose:$verbose |
                    ForEach-Object -Process {
                        if ($_ -match '^tar:')
                        {
                            Write-Error $_
                        }
                        else
                        {
                            if ($_ -is [String] -and $ListOnly.IsPresent)
                            {
                                $_
                            }
                            else
                            {
                                Write-Verbose -Message $_
                            }
                        }
                    }

                $destinationFullName = [io.Path]::GetFullPath($Destination)
                if (Test-Path -Path $destinationFullName)
                {
                    $destinationFullName
                }
            }
        }
    }
}
#EndRegion '.\Public\Archive\Expand-nxArchive.ps1' 139
#Region '.\Public\FileContent\Add-nxFileLine.ps1' 0
function Add-nxFileLine
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [string]
        $Line,

        [Parameter()]
        [nxFileLineAddMode]
        $AddLineMode = [nxFileLineAddMode]::Append,

        [Parameter()]
        [regex]
        $LinePattern,

        [Parameter()]
        [switch]
        $CaseSensitive,

        [Parameter()]
        [String]
        $Encoding = 'UTF8'
    )

    Write-Debug -Message "Adding Line to file '$Path'."
    if ($AddLineMode -eq [nxFileLineAddMode]::Append)
    {
        Add-Content -Path $Path -Value $Line -ErrorAction Stop -Encoding $Encoding
        return
    }

    # Else, Insert the line either before or after the first line matching the pattern
    $firstMatch = Select-String -Path $Path -Pattern $LinePattern -CaseSensitive:$CaseSensitive.IsPresent

    if ($null -eq $firstMatch)
    {
        Write-Debug -Message "Could not find pattern '$LinePattern' for insert mode ''."
        Write-Debug -Message "The line '$Line' was not added. Aborting."
        return
    }
    else
    {
        Write-Debug -Message "LinePattern '$LinePattern' was found line $($firstMatch.LineNumber)."
    }

    $indexToInsertLineAt = if ($AddLineMode -eq [nxFileLineAddMode]::BeforeLinePatternMatch)
    {
        $firstMatch.LineNumber - 1
    }
    elseif ($AddLineMode -eq [nxFileLineAddMode]::AfterLinePatternMatch)
    {
        $firstMatch.LineNumber
    }

    Write-Debug -Message "Will insert the line in line $indexToInsertLineAt."

    # Read through the file, inserting the edits and adding all lines to them file.
    $getContentsParams = @{
        Path     = $Path
        Encoding = $Encoding
    }

    $tempFile = [System.IO.Path]::GetTempFileName()
    $setContentParams = $getContentsParams.Clone()
    $setContentParams['Path'] = $tempFile
    [int]$lineNumber = -1 #start at -1 so that as soon as you increment it goes to 0 (the first line).

    Get-Content @getContentsParams | ForEach-Object -Process { # Stream
        $lineNumber++
        if ($lineNumber -eq $indexToInsertLineAt)
        {
            Write-Verbose -Message "Inserting at line $lineNumber."
            $Line # Insert the line at this index
            $_    # Continue with the file content
        }
        else
        {
            $_
        }
    } | Set-Content @setContentParams

    Write-Debug -Message "Content replaced into temp file: '$tempFile'."

    try
    {
        # Override the $Path with the content of $temFile. Use AsByteStream to abstract the encoding.
        Get-Content -Path $tempFile  -AsByteStream | Set-Content -Force -Path $Path -AsByteStream
        Write-Debug -Message "Updated '$Path'."
    }
    finally
    {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        Write-Debug -Message "Removed the temp file '$tempFile'."
    }
}
#EndRegion '.\Public\FileContent\Add-nxFileLine.ps1' 104
#Region '.\Public\FileContent\Invoke-nxFileContentReplace.ps1' 0
function Invoke-nxFileContentReplace
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Position = 1, Mandatory = $true)]
        [string]
        $Path,

        [Parameter(Position = 2, Mandatory = $true)]
        [string]
        $SearchPattern,

        [Parameter(Position = 3)]
        [string]
        $ReplaceWith,

        [Parameter()]
        [switch]
        $CaseSensitive,

        [Parameter()]
        [switch]
        $Multiline,

        [Parameter()]
        [String]
        $Encoding = 'UTF8'
    )


    # Read through the file, inserting the edits and adding all lines to them file.
    $getContentsParams = @{
        Path     = $Path
        Encoding = $Encoding
    }

    $tempFile = [System.IO.Path]::GetTempFileName()
    $setContentParams = $getContentsParams.Clone()
    $setContentParams['Path'] = $tempFile
    [int]$lineNumber = -1 #start at -1 so that as soon as you increment it goes to 0 (the first line).

    if ($Multiline.IsPresent)
    {
        $getContentsParams['Raw'] = $true
    }

    Get-Content @getContentsParams | ForEach-Object -Process { # Stream
        $lineNumber++
        $matchExpr = if ($CaseSensitive.IsPresent)
        {
            {$_ -cmatch $SearchPattern}
        }
        else
        {
            {$_ -imatch $SearchPattern}
        }

        if (&$matchExpr)
        {
            Write-Verbose -Message "The line $lineNumber matches '$SearchPattern'. running '$_' -replace '$SearchPattern','$ReplaceWith'."
            if ($CaseSensitive.IsPresent)
            {
                $_ -creplace $SearchPattern,$ReplaceWith
            }
            else
            {
                $_ -ireplace $SearchPattern,$ReplaceWith
            }
        }
        else
        {
            $_
        }
    } | Set-Content @setContentParams

    Write-Debug -Message "Content replaced into temp file: '$tempFile'."

    try
    {
        # Override the $Path with the content of $temFile. Use AsByteStream to abstract the encoding.
        Get-Content -Path $tempFile  -AsByteStream | Set-Content -Force -Path $Path -AsByteStream
        Write-Debug -Message "Updated '$Path'."
    }
    finally
    {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        Write-Debug -Message "Removed the temp file '$tempFile'."
    }
}
#EndRegion '.\Public\FileContent\Invoke-nxFileContentReplace.ps1' 92
#Region '.\Public\FileContent\Remove-nxFileLine.ps1' 0
function Remove-nxFileLine
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateScript({Test-Path -Path $_})]
        [string]
        $Path,

        [Parameter(Mandatory = $true)]
        [int[]]
        $LineNumber,

        [Parameter()]
        [String]
        $Encoding = 'UTF8'
    )

    Write-Debug -Message "Removing Lines to file '$Path'."

    # Read through the file, inserting the edits and adding all lines to them file.
    $getContentsParams = @{
        Path = $Path
        Encoding = $Encoding
    }

    $tempFile = [System.IO.Path]::GetTempFileName()
    $setContentParams = $getContentsParams.Clone()
    $setContentParams['Path'] = $tempFile
    [int]$CurrentLine = 0 #start at -1 so that as soon as you increment it goes to 0 (the first line).

    Get-Content @getContentsParams | ForEach-Object -Process { # Stream
        $CurrentLine++ # Lines starts at 1
        if ($CurrentLine -in $lineNumber)
        {
            Write-Verbose -Message "Removing line $CurrentLine : '$_'."
        }
        else
        {
            Write-Debug -Message "$($CurrentLine): '$_'."
            $_
        }
    } | Set-Content @setContentParams

    Write-Debug -Message "Content replaced into temp file: '$tempFile'."

    try
    {
        # Override the $Path with the content of $temFile. Use AsByteStream to abstract the encoding.
        Get-Content -Path $tempFile  -AsByteStream | Set-Content -Force -Path $Path -AsByteStream
        Write-Debug -Message "Updated '$Path'."
    }
    finally
    {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
        Write-Debug -Message "Removed the temp file '$tempFile'."
    }
}
#EndRegion '.\Public\FileContent\Remove-nxFileLine.ps1' 61
#Region '.\Public\FileSystem\Compare-nxMode.ps1' 0
function Compare-nxMode
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [nxFileSystemMode]
        $ReferenceMode,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [nxFileSystemMode[]]
        [Alias('Mode')]
        $DifferenceMode,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        [Alias('FullName', 'Path')]
        $DifferencePath,

        [Parameter()]
        [Switch]
        $IncludeEqual
    )

    process {
        foreach ($ModeItem in $DifferenceMode)
        {
            Write-Verbose -Message "Comparing '$ReferenceMode' with '$ModeItem'"

            $diffOwner = $ReferenceMode.OwnerMode -bxor $ModeItem.OwnerMode
            $diffGroup = $ReferenceMode.GroupMode -bxor $ModeItem.GroupMode
            $diffOthers = $ReferenceMode.OthersMode -bxor $ModeItem.OthersMode
            $diffSpecialModeFlags = $ReferenceMode.SpecialModeFlags -bxor $ModeItem.SpecialModeFlags

            foreach ($enumValue in ([Enum]::GetValues([nxFileSystemAccessRight]).Where({$_ -ne [nxFileSystemAccessRight]::None})))
            {
                if ($diffOwner -band $enumValue)
                {
                    $sideIndicator = $ReferenceMode.OwnerMode -band $enumValue ? '<=' : '=>'
                    Write-Verbose -Message "[$([nxFileSystemUserClass]::User)]'$enumValue' is only on this side [REF '$sideIndicator' DIFF]."
                    [PSCustomObject]@{
                        Class                = [nxFileSystemUserClass]::User
                        InputObject          = $enumValue
                        SideIndicator        = $sideIndicator
                        DifferencePath       = $DifferencePath
                    } | Add-Member -PassThru -Name RemediationOperation -MemberType ScriptProperty -Value {$this | Convert-nxFileSystemModeComparisonToSymbolicOperation}
                }
                elseif ($IncludeEqual)
                {
                    [PSCustomObject]@{
                        Class                = [nxFileSystemUserClass]::User
                        InputObject          = $enumValue
                        SideIndicator        = '='
                        RemediationOperation = ''
                        DifferencePath       = $DifferencePath
                    }
                }

                if ($diffGroup -band $enumValue)
                {
                    $sideIndicator = $ReferenceMode.GroupMode -band $enumValue ? '<=' : '=>'
                    Write-Verbose -Message "[$([nxFileSystemUserClass]::Group)]'$enumValue' is only on this side [REF '$sideIndicator' DIFF]."
                    [PSCustomObject]@{
                        Class                = [nxFileSystemUserClass]::Group
                        InputObject          = $enumValue
                        SideIndicator        = $sideIndicator
                        DifferencePath       = $DifferencePath
                    } | Add-Member -PassThru -Name RemediationOperation -MemberType ScriptProperty -Value {$this | Convert-nxFileSystemModeComparisonToSymbolicOperation}
                }
                elseif ($IncludeEqual)
                {
                    [PSCustomObject]@{
                        Class                = [nxFileSystemUserClass]::Group
                        InputObject          = $enumValue
                        SideIndicator        = '='
                        RemediationOperation = ''
                        DifferencePath       = $DifferencePath
                    }
                }

                if ($diffOthers -band $enumValue)
                {
                    $sideIndicator = $ReferenceMode.OthersMode -band $enumValue ? '<=' : '=>'
                    Write-Verbose -Message "[$([nxFileSystemUserClass]::Others)]'$enumValue' is only on this side [REF '$sideIndicator' DIFF]."
                    [PSCustomObject]@{
                        Class                = [nxFileSystemUserClass]::Others
                        InputObject          = $enumValue
                        SideIndicator        = $sideIndicator
                        DifferencePath       = $DifferencePath
                    } | Add-Member -PassThru -Name RemediationOperation -MemberType ScriptProperty -Value {$this | Convert-nxFileSystemModeComparisonToSymbolicOperation}
                }
                elseif ($IncludeEqual)
                {
                    [PSCustomObject]@{
                        Class                = [nxFileSystemUserClass]::Others
                        InputObject          = $enumValue
                        SideIndicator        = '='
                        RemediationOperation = ''
                        DifferencePath       = $DifferencePath
                    }
                }
            }

            foreach ($enumValue in ([Enum]::GetValues([nxFileSystemSpecialMode])))
            {
                if ($diffSpecialModeFlags -band $enumValue)
                {
                    $sideIndicator = $ReferenceMode.SpecialModeFlags -band $enumValue ? '<=' : '=>'
                    Write-Verbose -Message "[$([nxFileSystemUserClass]::None)]'$enumValue' is only on this side [REF '$sideIndicator' DIFF]."
                    [PSCustomObject]@{
                        Class                = [nxFileSystemUserClass]::None
                        InputObject          = $enumValue
                        SideIndicator        = $sideIndicator
                        DifferencePath       = $DifferencePath
                    } | Add-Member -PassThru -Name RemediationOperation -MemberType ScriptProperty -Value {$this | Convert-nxFileSystemModeComparisonToSymbolicOperation}
                }
                elseif ($IncludeEqual)
                {
                    [PSCustomObject]@{
                        Class                = [nxFileSystemUserClass]::None
                        InputObject          = $enumValue
                        SideIndicator        = '='
                        RemediationOperation = ''
                        DifferencePath       = $DifferencePath
                    }
                }
            }
        }
    }
}
#EndRegion '.\Public\FileSystem\Compare-nxMode.ps1' 132
#Region '.\Public\FileSystem\Get-nxChildItem.ps1' 0
function Get-nxChildItem
{
    [CmdletBinding(DefaultParameterSetName = 'default')]
    [OutputType([nxFileSystemInfo[]])]
    param
    (
        [Parameter(ParameterSetName = 'default'         , Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilterDirectory' , Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilterFile'      , Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String[]]
        $Path = '.',

        [Parameter(ParameterSetName = 'default'         , Position = 1, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilterDirectory' , Position = 1, ValueFromPipelineByPropertyName = $true)]
        [Parameter(ParameterSetName = 'FilterFile'      , Position = 1, ValueFromPipelineByPropertyName = $true)]
        [Switch]
        $Recurse,

        [Parameter(ParameterSetName = 'FilterDirectory' , ValueFromPipelineByPropertyName = $true, Position = 2)]
        [Switch]
        $Directory,

        [Parameter(ParameterSetName = 'FilterFile'      , ValueFromPipelineByPropertyName = $true, Position = 2)]
        [Switch]
        $File
    )

    begin
    {
        $verbose   = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters.Verbose) -or $VerbosePreference -ne 'SilentlyContinue'
        $debug     = ($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters['Debug']) -or $DebugPreference -ne 'SilentlyContinue'
        $lsParams  = @('-Al','--full-time','--group-directories-first')

        if ($PSBoundParameters.ContainsKey('Recurse') -and $PSboundParameters['Recurse'])
        {
            $lsParams += '-R' # Alpine linux does not support --recursive
        }
    }

    process
    {
        foreach ($pathItem in $Path.Where{$_})
        {
            $pathItem = [System.IO.Path]::GetFullPath($pathItem, $PWD.Path)
            $unfilteredListCommand = {
                Invoke-NativeCommand -Executable 'ls' -Parameters ($lsParams + @($pathItem)) -Verbose:($verbose -or $debug) |
                    Convert-nxLsEntryToFileSystemInfo -InitialPath $pathItem -Verbose:$debug
            }

            if ($PSCmdlet.ParameterSetName -eq 'FilterFile' -and $PSBoundParameters['File'])
            {
                &$unfilteredListCommand | Where-Object -FilterScript { $_.nxFileSystemItemType -eq [nxFileSystemItemType]::File }
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'FilterDirectory' -and $PSBoundParameters['Directory'])
            {
                &$unfilteredListCommand | Where-Object -FilterScript { $_.nxFileSystemItemType -eq [nxFileSystemItemType]::Directory }
            }
            else
            {
                &$unfilteredListCommand
            }
        }
    }
}
#EndRegion '.\Public\FileSystem\Get-nxChildItem.ps1' 65
#Region '.\Public\FileSystem\Get-nxItem.ps1' 0
function Get-nxItem
{
    [CmdletBinding()]
    [OutputType([nxFileSystemInfo])]
    param
    (
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [System.String[]]
        $Path = '.'
    )

    begin
    {
        $verbose   = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) -or $VerbosePreference -ne 'SilentlyContinue'
        $debug     = ($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters['Debug']) -or $DebugPreference -ne 'SilentlyContinue'
        $lsParams  = @('-Al','--full-time','--group-directories-first','-d')
    }

    process
    {
        foreach ($pathItem in $Path.Where{$_})
        {
            $pathItem = [System.IO.Path]::GetFullPath($pathItem, $PWD.Path)
            Invoke-NativeCommand -Executable 'ls' -Parameters ($lsParams + @($pathItem)) -Verbose:($verbose -or $debug) |
                Convert-nxLsEntryToFileSystemInfo -InitialPath $pathItem -Verbose:$debug
        }
    }
}
#EndRegion '.\Public\FileSystem\Get-nxItem.ps1' 29
#Region '.\Public\FileSystem\Set-nxGroupOwnership.ps1' 0
function Set-nxGroupOwnership
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Default')]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default', Position = 0)]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll', Position = 0)]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath', Position = 0)]
        [System.String[]]
        $Path,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default', Position = 1)]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll', Position = 1)]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath', Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Group,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # affect each symbolic link instead of any referenced file (useful only on systems that can change the ownership of a symlink)
        # -h
        $NoDereference,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # Do not traverse any symbolic links  by default
        $Recurse,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [System.Management.Automation.SwitchParameter]
        # Traverse every symbolic link to a directory encountered
        # -L
        $RecursivelyTraverseSymLink,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # If $Path is a symbolic link to a directory, traverse it.
        # -H
        $OnlyTraversePathIfSymLink,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # Disable root preservation security.
        $Force
    )

    begin {
        $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters.Verbose) -or $VerbosePreference -ne 'SilentlyContinue'
    }

    process {
        foreach ($pathItem in $Path)
        {
            $pathItem = [System.Io.Path]::GetFullPath($pathItem, $PWD.Path)

            $chgrpParams = @()

            if ($PSBoundParameters.ContainsKey('NoDereference') -and $PSBoundParameters['NoDereference'])
            {
                $chgrpParams += '-h'
            }

            if ($PSBoundParameters.ContainsKey('RecursivelyTraverseSymLink') -and $PSBoundParameters['RecursivelyTraverseSymLink'])
            {
                $chgrpParams += '-L'
            }

            if ($PSBoundParameters.ContainsKey('OnlyTraversePathIfSymLink') -and $PSBoundParameters['OnlyTraversePathIfSymLink'])
            {
                $chgrpParams += '-H'
            }

            if ($PSBoundParameters.ContainsKey('Recurse') -and $PSBoundParameters['Recurse'])
            {
                $chgrpParams += '-R'
            }

            $chgrpParams = ($chgrpParams + @($Group, $pathItem))

            if (
                $PSCmdlet.ShouldProcess("Performing the unix command 'chgrp $($chgrpParams -join ' ')'.", $PathItem, "chgrp $($chgrpParams -join ' ')")
            )
            {
                if ($pathItem -eq '/' -and -not ($PSBoundParameters.ContainsKey('Force') -and $Force))
                {
                    # can't use the built-in --preserve-root because it's not available on Alpine linux
                    Write-Warning "You are about to chgrp your root. Please use -Force."
                    return
                }

                Write-Verbose -Message ('chgrp {0}' -f ($chgrpParams -join ' '))
                Invoke-NativeCommand -Executable 'chgrp' -Parameters $chgrpParams -Verbose:$verbose -ErrorAction 'Stop' | Foreach-Object -Process {
                    Write-Error -Message $_
                }
            }
        }
    }
}
#EndRegion '.\Public\FileSystem\Set-nxGroupOwnership.ps1' 107
#Region '.\Public\FileSystem\Set-nxMode.ps1' 0
function Set-nxMode
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Default')]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default', Position = 0)]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll', Position = 0)]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath', Position = 0)]
        [System.String[]]
        $Path,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default', Position = 1)]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll', Position = 1)]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath', Position = 1)]
        [nxFileSystemMode]
        $Mode,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # affect each symbolic link instead of any referenced file (useful only on systems that can change the ownership of a symlink)
        # -h
        $NoDereference,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # Do not traverse any symbolic links  by default
        $Recurse,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [System.Management.Automation.SwitchParameter]
        # Traverse every symbolic link to a directory encountered
        # -L
        $RecursivelyTraverseSymLink,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # If $Path is a symbolic link to a directory, traverse it.
        # -H
        $OnlyTraversePathIfSymLink,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # Disable root preservation security.
        $Force
    )

    begin {
        $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters.Verbose) -or $VerbosePreference -ne 'SilentlyContinue'
    }

    process {
        foreach ($pathItem in $Path)
        {
            $pathItem = [System.Io.Path]::GetFullPath($pathItem, $PWD.Path)

            $chmodParams = @()

            if ($PSBoundParameters.ContainsKey('NoDereference') -and $PSBoundParameters['NoDereference'])
            {
                $chmodParams += '-h'
            }

            if ($PSBoundParameters.ContainsKey('RecursivelyTraverseSymLink') -and $PSBoundParameters['RecursivelyTraverseSymLink'])
            {
                $chmodParams += '-L'
            }

            if ($PSBoundParameters.ContainsKey('OnlyTraversePathIfSymLink') -and $PSBoundParameters['OnlyTraversePathIfSymLink'])
            {
                $chmodParams += '-H'
            }

            if ($PSBoundParameters.ContainsKey('Recurse') -and $PSBoundParameters['Recurse'])
            {
                $chmodParams += '-R'
            }

            $OctalMode = $Mode.ToOctal()
            $chmodParams = ($chmodParams + @($OctalMode, $pathItem))

            Write-Debug "Parameter Set Name: '$($PSCmdlet.ParameterSetName)'."

            if (
                $PSCmdlet.ShouldProcess("Performing the unix command 'chmod $($chmodParams -join ' ')'.", $PathItem, "chmod $($chmodParams -join ' ')")
            )
            {
                if ($pathItem -eq '/' -and -not ($PSBoundParameters.ContainsKey('Force') -and $Force))
                {
                    # can't use the built-in --preserve-root because it's not available on Alpine linux
                    Write-Warning "You are about to chmod your root. Please use -Force."
                    return
                }

                Write-Verbose -Message ('chmod {0}' -f ($chmodParams -join ' '))
                Invoke-NativeCommand -Executable 'chmod' -Parameters $chmodParams -Verbose:$verbose -ErrorAction 'Stop'  | Foreach-Object -Process {
                    Write-Error -Message $_
                }
            }
        }
    }
}
#EndRegion '.\Public\FileSystem\Set-nxMode.ps1' 109
#Region '.\Public\FileSystem\Set-nxOwner.ps1' 0
function Set-nxOwner
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'Default')]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.String[]]
        $Path,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        [Alias('UserName')]
        $Owner,

        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Group,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # affect each symbolic link instead of any referenced file (useful only on systems that can change the ownership of a symlink)
        # -h
        $NoDereference,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # Do not traverse any symbolic links  by default
        $Recurse,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [System.Management.Automation.SwitchParameter]
        # Traverse every symbolic link to a directory encountered
        # -L
        $RecursivelyTraverseSymLink,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # If $Path is a symbolic link to a directory, traverse it.
        # -H
        $OnlyTraversePathIfSymLink,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Default')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursiveAll')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'RecursivePath')]
        [System.Management.Automation.SwitchParameter]
        # Disable root preservation security.
        $Force
    )

    begin {
        $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters.Verbose) -or $VerbosePreference -ne 'SilentlyContinue'
    }

    process {
        foreach ($pathItem in $Path)
        {
            $pathItem = [System.Io.Path]::GetFullPath($pathItem, $PWD.Path)

            $chownParams = @()

            if ($PSBoundParameters.ContainsKey('NoDereference') -and $PSBoundParameters['NoDereference'])
            {
                $chownParams += '-h'
            }

            if ($PSBoundParameters.ContainsKey('RecursivelyTraverseSymLink') -and $PSBoundParameters['RecursivelyTraverseSymLink'])
            {
                $chownParams += '-L'
            }

            if ($PSBoundParameters.ContainsKey('OnlyTraversePathIfSymLink') -and $PSBoundParameters['OnlyTraversePathIfSymLink'])
            {
                $chownParams += '-H'
            }

            if ($PSBoundParameters.ContainsKey('Recurse') -and $PSBoundParameters['Recurse'])
            {
                $chownParams += '-R'
            }

            if ($PSBoundParameters.ContainsKey('Group'))
            {
                $Owner = '{0}:{1}' -f $Owner,$Group
            }

            $chownParams = ($chownParams + @($Owner, $pathItem))

            if (
                $PSCmdlet.ShouldProcess("Performing the unix command 'chown $($chownParams -join ' ')'.", $PathItem, "chown $($chownParams -join ' ')")
            )
            {
                if ($pathItem -eq '/' -and -not ($PSBoundParameters.ContainsKey('Force') -and $Force))
                {
                    # can't use the built-in --preserve-root because it's not available on Alpine linux
                    Write-Warning "You are about to chown your root. Please use -Force."
                    return
                }

                Write-Verbose -Message ('chown {0}' -f ($chownParams -join ' '))
                Invoke-NativeCommand -Executable 'chown' -Parameters $chownParams -Verbose:$verbose -ErrorAction 'Stop' | Foreach-Object -Process {
                    Write-Error -Message $_
                }
            }
        }
    }
}
#EndRegion '.\Public\FileSystem\Set-nxOwner.ps1' 120
#Region '.\Public\Packages\Find-nxPackage.ps1' 0
function Find-nxPackage
{
    [CmdletBinding()]
    [OutputType()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        # Name of the Package fo find in the Cached list of packages. Make sure you update the cache as needed.
        $Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        # Specifc Version of a package that you want to find in the Cached list of packages.
        $Version,

        [Parameter()]
        [switch]
        # Show all versions available for a package.
        $AllVersions,

        [Parameter()]
        [nxSupportedPackageType[]]
        $PackageType = (Get-nxSupportedPackageType)
    )

    begin
    {
        # Work out the $PackageType priority
        # for Find prefer in order: dnf, yum, apt, zapper, snap
        $PackageTypeStrings = [string[]]($PackageType.Foreach({$_.ToString()}))
        $packageTypeToUseInPriority = @('dnf', 'yum', 'apt', 'zapper', 'snap').Where{$_ -in $PackageTypeStrings} | Select-Object -First 1
        Write-Debug -Message "The package type to use in priority to list packages is '$packageTypeToUseInPriority'."
    }

    end
    {
        if ($PSBoundParameters.ContainsKey('PackageType'))
        {
            $null = $PSBoundParameters.Remove('PackageType')
        }

        switch ($packageTypeToUseInPriority)
        {
            'dpkg' { Find-nxAptPackageFromCache @PSBoundParameters }
            'apt'  { Find-nxAptPackageFromCache @PSBoundParameters }
            'yum'  { Find-nxYumPackage @PSBoundParameters }

            default
            {
                throw ('The Package type {0} is not yet supported with ''Find-nxPackage''.' -f $packageTypeToUseInPriority)
            }
        }
    }
}
#EndRegion '.\Public\Packages\Find-nxPackage.ps1' 58
#Region '.\Public\Packages\Get-nxPackage.ps1' 0

function Get-nxPackage
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [String[]]
        $Name,

        [Parameter()]
        [nxSupportedPackageType[]]
        $PackageType = (Get-nxSupportedPackageType)
    )

    # Work out the $PackageType priority
    # for GET prefer in order: dpkg, dnf, yum, apt, zapper, snap
    $PackageTypeStrings = [string[]]($PackageType.Foreach({$_.ToString()}))
    $packageTypeToUseInPriority = @('dpkg', 'dnf', 'yum', 'apt', 'zapper', 'snap').Where{$_ -in $PackageTypeStrings} | Select-Object -First 1
    Write-Debug -Message "The package type to use in priority to list packages is '$packageTypeToUseInPriority'."

    switch ($packageTypeToUseInPriority)
    {
        'dpkg' { Get-nxDpkgPackage -Name $Name -ErrorAction Ignore }
        'yum'  { Get-nxYumPackage -Name $Name -ErrorAction Ignore }

        default
        {
            throw ('The Package type {0} is not yet supported with ''Get-nxPackage''.' -f $packageTypeToUseInPriority)
        }
    }
}
#EndRegion '.\Public\Packages\Get-nxPackage.ps1' 33
#Region '.\Public\Packages\Get-nxPackageInstalled.ps1' 0

function Get-nxPackageInstalled
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [String[]]
        $Name,

        [Parameter()]
        [nxSupportedPackageType[]]
        $PackageType = (Get-nxSupportedPackageType)
    )

    # Work out the $PackageType priority
    # for GET prefer in order: dpkg, dnf, yum, apt, zapper, snap
    $PackageTypeStrings = [string[]]($PackageType.Foreach({$_.ToString()}))
    $packageTypeToUseInPriority = @('dpkg', 'dnf', 'yum', 'apt', 'zapper', 'snap').Where{$_ -in $PackageTypeStrings} | Select-Object -First 1
    Write-Debug -Message "The package type to use in priority to list packages is '$packageTypeToUseInPriority'."

    switch ($packageTypeToUseInPriority)
    {
        'dpkg' { Get-nxDpkgPackageInstalled -Name $Name -ErrorAction Ignore }
        'yum'  { Get-nxYumPackageInstalled -Name $Name -ErrorAction Ignore }

        default
        {
            throw ('The Package type {0} is not yet supported with ''Get-nxPackage''.' -f $packageTypeToUseInPriority)
        }
    }
}
#EndRegion '.\Public\Packages\Get-nxPackageInstalled.ps1' 33
#Region '.\Public\Packages\Get-nxSupportedPackageType.ps1' 0

function Get-nxSupportedPackageType
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter()]
        [nxSupportedPackageType[]]
        $PackageType = [Enum]::GetNames([nxSupportedPackageType])
    )

    $packageUtilFound = Get-Command -Name @($PackageType.Foreach({$_.ToString()})) -ErrorAction Ignore

    return $packageUtilFound.Name
}
#EndRegion '.\Public\Packages\Get-nxSupportedPackageType.ps1' 17
#Region '.\Public\Packages\Install-nxPackage.ps1' 0
function Install-nxPackage
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        # List of Packages to Install on the system.
        $Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $Version,

        [Parameter()]
        [nxSupportedPackageType[]]
        $PackageType = (Get-nxSupportedPackageType)
    )

    begin
    {
        # Work out the $PackageType priority
        # for Find prefer in order: dnf, yum, apt, zapper, snap
        $PackageTypeStrings = [string[]]($PackageType.Foreach({$_.ToString()}))
        $packageTypeToUseInPriority = @('dnf', 'yum', 'apt', 'zapper', 'snap','dpkg').Where{$_ -in $PackageTypeStrings} | Select-Object -First 1
        Write-Debug -Message "The package type to use in priority to install packages is '$packageTypeToUseInPriority'."
    }

    end
    {
        if ($PSBoundParameters.ContainsKey('PackageType'))
        {
            $null = $PSBoundParameters.Remove('PackageType')
        }

        switch ($packageTypeToUseInPriority)
        {
            'dpkg' { Install-nxAptPackage @PSBoundParameters }
            'apt'  { Install-nxAptPackage @PSBoundParameters }
            'yum'  { Install-nxYumPackage @PSBoundParameters  }

            default
            {
                throw ('The Package type {0} is not yet supported with ''Install-nxPackage''.' -f $packageTypeToUseInPriority)
            }
        }
    }
}
#EndRegion '.\Public\Packages\Install-nxPackage.ps1' 50
#Region '.\Public\Packages\Remove-nxPackage.ps1' 0
function Remove-nxPackage
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        # List of Packages to remove from the system.
        $Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $Version,

        [Parameter()]
        [nxSupportedPackageType[]]
        $PackageType = (Get-nxSupportedPackageType)
    )

    begin
    {
        # Work out the $PackageType priority
        # for Find prefer in order: dnf, yum, apt, zapper, snap
        $PackageTypeStrings = [string[]]($PackageType.Foreach({$_.ToString()}))
        $packageTypeToUseInPriority = @('dnf', 'yum', 'apt', 'zapper', 'snap','dpkg').Where{$_ -in $PackageTypeStrings} | Select-Object -First 1
        Write-Debug -Message "The package type to use in priority to list packages is '$packageTypeToUseInPriority'."
    }

    end
    {
        if ($PSBoundParameters.ContainsKey('PackageType'))
        {
            $null = $PSBoundParameters.Remove('PackageType')
        }

        switch ($packageTypeToUseInPriority)
        {
            'dpkg' { Remove-nxAptPackage @PSBoundParameters }
            'apt'  { Remove-nxAptPackage @PSBoundParameters }
            'yum'  { Remove-nxYumPackage @PSBoundParameters  }

            default
            {
                throw ('The Package type {0} is not yet supported with ''Remove-nxPackage''.' -f $packageTypeToUseInPriority)
            }
        }
    }
}
#EndRegion '.\Public\Packages\Remove-nxPackage.ps1' 50
#Region '.\Public\Packages\Apt\Find-nxAptPackageFromCache.ps1' 0
function Find-nxAptPackageFromCache
{
    [CmdletBinding()]
    [OutputType([nxAptPackage])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        # Name of the Package fo find in the Cached list of packages. Make sure you update the cache as needed.
        $Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        # Specifc Version of a package that you want to find in the Cached list of packages.
        $Version,

        [Parameter()]
        [switch]
        # Show all versions available for a package.
        $AllVersions
    )

    begin
    {
        $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])
    }

    process
    {
        $aptCacheParams = @('show')

        if ($PSBoundParameters.ContainsKey('Name'))
        {
            $Name.ForEach({
                if ($_ -cmatch '[A-Z]')
                {
                    Write-Warning -Message "Please keep in mind the package name is case sensitive ('$_')."
                }

                if ($PSBoundParameters.Keys -notcontains 'Version')
                {
                    $aptCacheParams += $_
                }
                else
                {
                    $aptCacheParams += ('{0}={1}' -f $_, $Version)
                }
            })
        }

        if (-not $AllVersions.IsPresent)
        {
            $aptCacheParams += '--no-all-versions'
        }
        elseif ($PSBoundParameters.Keys -contains 'Version')
        {
            Write-Debug -Message "Searching specific version of packages."
        }
        else
        {
            $aptCacheParams += '--all-versions'
        }

        $aptCacheParams += '-q' #quiet with no progress bars
        $outputFromCurrentObject = @()
        Invoke-NativeCommand -Executable 'apt-cache' -Parameters $aptCacheParams -Verbose:$verbose | ForEach-Object -Process {
            if (-not [string]::IsNullOrEmpty($_))
            {
                Write-Debug -Message "Adding > $_"
                $outputFromCurrentObject += $_
            }
            else
            {
                [nxAptPackage]($outputFromCurrentObject | Get-PropertyHashFromListOutput -AddExtraPropertiesAsKey AdditionalFields -AllowedPropertyName ([nxAptPackage].GetProperties().Name))
                Write-Verbose -Message "Cleaning up `$outputFromCurrentObject."
                $outputFromCurrentObject = @()
            }
        } -End {
            if ($outputFromCurrentObject.Count -gt 0)
            {
                [nxAptPackage]($outputFromCurrentObject | Get-PropertyHashFromListOutput -AddExtraPropertiesAsKey AdditionalFields -AllowedPropertyName ([nxAptPackage].GetProperties().Name))
            }
        }
    }
}
#EndRegion '.\Public\Packages\Apt\Find-nxAptPackageFromCache.ps1' 88
#Region '.\Public\Packages\Apt\Install-nxAptPackage.ps1' 0
function Install-nxAptPackage
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        # Name of the Package fo find in the Cached list of packages. Make sure you update the cache as needed.
        $Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        # Specifc Version of a package that you want to find in the Cached list of packages.
        $Version
    )

    begin
    {
        $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])
    }

    process
    {
        # apt-get install
        $aptGetInstallParams = @('install','--quiet')
        foreach ($packageName in $Name)
        {
            $packageToInstall = $packageName
            if ($PSBoundParameters.ContainsKey('Version'))
            {
                Write-Verbose -Message "Trying to install package '$packageName' at the specified version '$Version'."
                # Overriding $packageToInstall
                $packageToInstall = '{0}={1}' -f $packageName, $Version
            }

            Invoke-NativeCommand -Executable 'apt-get' -Parameters @($aptGetInstallParams+$packageToInstall) -Verbose:$verbose |
            ForEach-Object -Process {
                if ($_ -is [System.Management.Automation.ErrorRecord])
                {
                    Write-Error -Message $_
                }
                else
                {
                    Write-Verbose -Message ($_+"`r").TrimEnd('\+')
                }
            }
        }
    }
}
#EndRegion '.\Public\Packages\Apt\Install-nxAptPackage.ps1' 52
#Region '.\Public\Packages\Apt\Remove-nxAptPackage.ps1' 0
function Remove-nxAptPackage
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        # List of Packages to remove from the system.
        $Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $Version,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        # Uninstall all related packages and configuration files.
        $Purge
    )

    begin
    {
        $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])
    }

    process
    {
        # apt-get update
        $aptGetRemoveParams = @('remove','--quiet','--yes')
        if ($Purge.IsPresent)
        {
            $aptGetRemoveParams[0] = 'purge'
        }

        $packageToRemove = $Name
        if ($PSBoundParameters.ContainsKey('Version'))
        {
            Write-Verbose -Message "Trying to remove package '$Name' at the specified version '$Version'."
            # Overriding $packageToRemove with specified version
            $packageToRemove = $Name.ForEach({'{0}={1}' -f $_, $Version})
        }

        Invoke-NativeCommand -Executable 'apt-get' -Parameters @($aptGetRemoveParams+$packageToRemove) -Verbose:$verbose |
        ForEach-Object -Process {
            if ($_ -is [System.Management.Automation.ErrorRecord])
            {
                Write-Error -Message $_
            }
            else
            {
                Write-Verbose -Message ($_+"`r").TrimEnd('\+')
            }
        }
    }
}
#EndRegion '.\Public\Packages\Apt\Remove-nxAptPackage.ps1' 57
#Region '.\Public\Packages\Apt\Update-nxAptPackageCache.ps1' 0
function Update-nxAptPackageCache
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        # dono
    )

    begin
    {
        $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])
    }

    process
    {
        # apt-get update
        $aptGetUpdateParams = @('update','--quiet')

        Invoke-NativeCommand -Executable 'apt-get' -Parameters $aptGetUpdateParams -Verbose:$verbose |
        ForEach-Object -Process {
            if ($_ -is [System.Management.Automation.ErrorRecord])
            {
                Write-Error -Message $_
            }
            else
            {
                Write-Verbose -Message ($_+"`r").TrimEnd('\+')
            }
        }
    }
}
#EndRegion '.\Public\Packages\Apt\Update-nxAptPackageCache.ps1' 33
#Region '.\Public\Packages\dpkg\Get-nxDpkgPackage.ps1' 0

function Get-nxDpkgPackage
{
    [CmdletBinding(DefaultParameterSetName = 'dpkgInstalledPackage')]
    param
    (
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'dpkgInstalledPackage', Position = 0)]
        [Alias('Package')]
        [string[]]
        $Name,

        [Parameter(ValueFromPipelineByPropertyName, ParameterSetName = 'dpkgFile', Position = 0)]
        $Path
    )

    process
    {

        switch ($PSCmdlet.ParameterSetName)
        {
            'dpkgInstalledPackage' {
                $PackageToParse = { Get-nxDpkgPackageInstalled -Name $Name | Where-Object {$null -ne $_.Version} }
            }

            'dpkgFile'  {
                $PackageToParse = { Get-Item -Path $Path }
            }
        }

        &$PackageToParse | ForEach-Object {
            if ($_ -is [System.IO.FileInfo])
            {
                # dpkg --info ./localpackage.deb for getting info of non-installed package
                $dpkgParams = @('--info', $_.FullName)
            }
            else
            {
                # dpkg --status packageName for having details of the installed package
                $dpkgParams = @('--status', $_.Name)
            }

            Write-Verbose "Fetching details for '$($_.Name)'"
            $getPropertyHashFromListOutputParams = @{
                AllowedPropertyName     = ([nxDpkgPackage].GetProperties().Name)
                AddExtraPropertiesAsKey = 'AdditionalFields'
                ErrorVariable           = 'packageError'
            }

            $properties = Invoke-NativeCommand -Executable 'dpkg' -Parameters $dpkgParams |
                Get-PropertyHashFromListOutput @getPropertyHashFromListOutputParams

            # Making sure we replicate the package property to Name property
            # To correctly make the Base object (Package class)
            #TODO: This should probably go in the nxDpkgPackage class constructors
            $properties['PackageType'] = 'dpkg'
            $properties.add('Name', $properties['Package'])

            if (-not $packageError)
            {
                [nxDpkgPackage]$properties
            }
        }
    }
}
#EndRegion '.\Public\Packages\dpkg\Get-nxDpkgPackage.ps1' 65
#Region '.\Public\Packages\dpkg\Get-nxDpkgPackageInstalled.ps1' 0
function Get-nxDpkgPackageInstalled
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('Package')]
        [string[]]
        $Name
    )

    process
    {
        # Debian policy says Package name must be lowercase, making the user a service by forcing ToLower()
        # https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-source
        $Name = $Name.ForEach({$_.ToLower()})

        Invoke-NativeCommand -Executable 'dpkg-query' -Parameters @('-W',($Name -join ' ')) |
            ForEach-Object -Process {
                if ($_ -is [System.Management.Automation.ErrorRecord])
                {
                    switch -Regex ($_)
                    {
                        # this Adds a way to process the error stream in a customized way.
                        # 'no\spackages\sfound' { throw "Package $($Name) not found." } # Use this if you wan to throw when this error is raised
                        default { Write-Error "$_." }
                    }
                }
                else
                {
                    $dpkgPackage = $_ -split "`t"
                    [PSCustomObject]@{
                        PSTypeName  = 'nxDpkgPackage.Installed'
                        Name        = $dpkgPackage[0]
                        Version     = $dpkgPackage[1]
                    }
                }
            }
    }
}
#EndRegion '.\Public\Packages\dpkg\Get-nxDpkgPackageInstalled.ps1' 41
#Region '.\Public\Packages\yum\Find-nxYumPackage.ps1' 0
function Find-nxYumPackage
{
    [CmdletBinding()]
    [OutputType([nxAptPackage])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        # Name of the Package fo find in the Cached list of packages. Make sure you update the cache as needed.
        $Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        # Specifc Version of a package that you want to find in the Cached list of packages.
        $Version,

        [Parameter()]
        [switch]
        # Show all versions available for a package.
        $AllVersions
    )

    begin
    {
        $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])
    }

    process
    {
        $yumInfoParams = @('info','-q')

        if ($AllVersions.IsPresent -or $PSBoundParameters.ContainsKey('Version'))
        {
            $yumInfoParams += '--show-duplicates'
        }

        if ($PSBoundParameters.ContainsKey('Name'))
        {
            $Name.ForEach({
                $yumInfoParams += $_
            })
        }

        $outputFromCurrentObject = @()
        Invoke-NativeCommand -Executable 'yum' -Parameters $yumInfoParams -Verbose:$verbose | ForEach-Object -Process {
            if (-not [string]::IsNullOrEmpty($_))
            {
                Write-Debug -Message "Adding > $_"
                $outputFromCurrentObject += $_
            }
            else
            {
                [nxYumPackage]($outputFromCurrentObject | Get-PropertyHashFromListOutput -Regex '^\s*(?<property>[\w][\w-\s]*):\s*(?<val>.*)' -AddExtraPropertiesAsKey AdditionalFields -AllowedPropertyName ([nxYumPackage].GetProperties().Name))
                Write-Verbose -Message "Cleaning up `$outputFromCurrentObject."
                $outputFromCurrentObject = @()
            }
        } -End {
            if ($outputFromCurrentObject.Count -gt 0)
            {
                [nxYumPackage]($outputFromCurrentObject | Get-PropertyHashFromListOutput -Regex '^\s*(?<property>[\w][\w-\s]*):\s*(?<val>.*)' -AddExtraPropertiesAsKey AdditionalFields -AllowedPropertyName ([nxYumPackage].GetProperties().Name))
            }
        } |
        Where-Object -FilterScript { # return specific version if $Version is set
            if ($_.repo -eq 'installed')
            {
                $false
            }
            elseif (-not $PSBoundParameters.ContainsKey('Version'))
            {
                $true
            }
            elseif ($PSBoundParameters.ContainsKey('Version') -and $_.Version -Like $Version)
            {
                $true
            }
            else
            {
                $false
            }
        }
    }
}
#EndRegion '.\Public\Packages\yum\Find-nxYumPackage.ps1' 85
#Region '.\Public\Packages\yum\Get-nxYumPackage.ps1' 0
function Get-nxYumPackage
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name
    )

    process
    {
        $getNxYumPackageInstalledParams = @{ }

        if ($PSBoundParameters.ContainsKey('Name'))
        {
            $getNxYumPackageInstalledParams['Name'] = $Name
            $getNxYumPackageInstalledParams['ErrorAction'] = 'Ignore'
        }

        Get-nxYumPackageInstalled @getNxYumPackageInstalledParams | ForEach-Object -Process {
            $yumInfoParams = @('info','-q', $_.Name)
            $oneObjectOutput = [System.Collections.ArrayList]::new()
            Invoke-NativeCommand -Executable 'yum' -Parameters $yumInfoParams -ErrorAction Ignore |
                Foreach-Object -Process {
                    switch -Regex ($_)
                    {
                        '^Available\sPackages'
                        {
                            Write-Verbose -Message $_
                            break
                        }

                        '^Installed\sPackages'
                        {
                            Write-Verbose -Message $_
                            break
                        }

                        '^$'
                        {
                            Write-Debug -Message "Empty line reached."
                            if ($oneObjectOutput.count -gt 0)
                            {
                                ,$oneObjectOutput.Clone()
                                $oneObjectOutput.Clear()
                            }
                        }

                        default
                        {
                            Write-Debug -Message "Adding line to object: $($_)"
                            $null = $oneObjectOutput.Add($_)
                        }
                    }
                } | ForEach-Object -Process {
                    $getPropertyHashFromListOutputParams = @{
                        AllowedPropertyName     = ([nxYumPackage].GetProperties().Name)
                        # AddExtraPropertiesAsKey = 'AdditionalFields'
                        ErrorVariable           = 'packageError'
                        Regex                   = '^(?<property>[\w][\w-\s]*):\s*(?<val>.*)'
                        DiscardExtraProperties = $true
                    }

                    $properties = $_.GetEnumerator() | Get-PropertyHashFromListOutput @getPropertyHashFromListOutputParams
                    $properties['PackageType'] = 'yum'

                    $properties['Description'] = ($properties['Description'] -split '\n').Foreach({
                        $_ -replace '^\s+\:'
                    }) -join "`n"

                    if (-not $packageError)
                    {
                        [nxYumPackage]$properties
                    }
                }
        }
    }
}
#EndRegion '.\Public\Packages\yum\Get-nxYumPackage.ps1' 81
#Region '.\Public\Packages\yum\Get-nxYumPackageInstalled.ps1' 0
function Get-nxYumPackageInstalled
{
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName, Position = 0)]
        [Alias('Package')]
        [string[]]
        $Name
    )

    process
    {
        $Name = $Name.ForEach({$_.ToLower()})
        $yumParams = @('list','installed',($Name -join ' '),'--quiet')
        Write-Debug -Message "Running shell command: yum $($yumParams -join ' ')"

        Invoke-NativeCommand -Executable 'yum' -Parameters $yumParams -ErrorAction SilentlyContinue |
            ForEach-Object -Process {
                if ($_ -is [System.Management.Automation.ErrorRecord])
                {
                    switch -Regex ($_)
                    {
                        # this Adds a way to process the error stream in a customized way.
                        # 'no\spackages\sfound' { throw "Package $($Name) not found." } # Use this if you wan to throw when this error is raised
                        default { Write-Error "$_." }
                    }
                }
                else
                {
                    switch -Regex ($_)
                    {
                        '^Installed\sPackages'
                        {
                            Write-Verbose -Message $_
                            break
                        }

                        default
                        {
                            $yumPackage = $_ -split "\s+"
                            $packageName, $packageArch = $yumPackage[0] -split '\.'

                            [PSCustomObject]@{
                                PSTypeName  = 'nxYumPackage.Installed'
                                Name        = $packageName
                                Arch        = $packageArch
                                Version     = $yumPackage[1]
                                Vendor      = $yumPackage[2]
                            }
                        }
                    }
                }
            }
    }
}
#EndRegion '.\Public\Packages\yum\Get-nxYumPackageInstalled.ps1' 57
#Region '.\Public\Packages\yum\Install-nxYumPackage.ps1' 0

function Install-nxYumPackage
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        # Name of the Package fo find in the Cached list of packages. Make sure you update the cache as needed.
        $Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        # Specifc Version of a package that you want to find in the Cached list of packages.
        $Version
    )

    begin
    {
        $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])
    }

    process
    {
        # Yum-get install
        $yumGetInstallParams = @('install','-q','-y')
        foreach ($packageName in $Name)
        {
            $packageToInstall = $packageName
            if ($PSBoundParameters.ContainsKey('Version'))
            {
                Write-Verbose -Message "Trying to install package '$packageName' at the specified version '$Version'."
                # Overriding $packageToInstall
                $packageToInstall = '{0}-{1}' -f $packageName, $Version
            }

            Invoke-NativeCommand -Executable 'yum' -Parameters @($yumGetInstallParams+$packageToInstall) -Verbose:$verbose |
            ForEach-Object -Process {
                if ($_ -is [System.Management.Automation.ErrorRecord])
                {
                    if (-not [string]::IsNullOrEmpty($_.Exception.Message))
                    {
                        Write-Error -Message $_
                    }
                }
                else
                {
                    Write-Verbose -Message ($_+"`r").TrimEnd('\+')
                }
            }
        }
    }
}
#EndRegion '.\Public\Packages\yum\Install-nxYumPackage.ps1' 56
#Region '.\Public\Packages\yum\Remove-nxYumPackage.ps1' 0
function Remove-nxYumPackage
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]
        # List of Packages to remove from the system.
        $Name,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [string]
        $Version
    )

    begin
    {
        $verbose = $VerbosePreference -ne 'SilentlyContinue' -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])
    }

    process
    {
        # yum remove
        $yumGetRemoveParams = @('remove','-q','-y')

        $packageToRemove = $Name
        if ($PSBoundParameters.ContainsKey('Version'))
        {
            Write-Verbose -Message "Trying to remove package '$Name' at the specified version '$Version'."
            # Overriding $packageToRemove with specified version
            $packageToRemove = $Name.ForEach({'{0}-{1}' -f $_, $Version})
        }

        Invoke-NativeCommand -Executable 'yum' -Parameters @($yumGetRemoveParams+$packageToRemove) -Verbose:$verbose |
        ForEach-Object -Process {
            if ($_ -is [System.Management.Automation.ErrorRecord])
            {
                Write-Error -Message $_
            }
            else
            {
                Write-Verbose -Message ($_+"`r").TrimEnd('\+')
            }
        }
    }
}
#EndRegion '.\Public\Packages\yum\Remove-nxYumPackage.ps1' 48
#Region '.\Public\Services\Disable-nxService.ps1' 0
function Disable-nxService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $Name,

        [Parameter()]
        [nxInitSystem]
        $Controller = (Get-nxInitSystem)
    )

    if ($PSBoundParameters.ContainsKey('Controller'))
    {
        $null = $PSBoundParameters.Remove('Controller')
    }

    foreach ($serviceName in $Name)
    {
        switch ($Controller)
        {
            'systemd' { Disable-nxSystemdService @PSboundParameters }

            default
            {
                throw ('The controller ''{0}'' is not yet supported with ''Disable-nxService''.' -f $Controller)
            }
        }
    }
}
#EndRegion '.\Public\Services\Disable-nxService.ps1' 34
#Region '.\Public\Services\Enable-nxService.ps1' 0
function Enable-nxService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $Name,

        [Parameter()]
        [nxInitSystem]
        $Controller = (Get-nxInitSystem)
    )

    if ($PSBoundParameters.ContainsKey('Controller'))
    {
        $null = $PSBoundParameters.Remove('Controller')
    }

    foreach ($serviceName in $Name)
    {
        switch ($Controller)
        {
            'systemd' { Enable-nxSystemdService @PSboundParameters }

            default
            {
                throw ('The controller {0} is not yet supported with ''Enable-nxService''.' -f $Controller)
            }
        }
    }
}
#EndRegion '.\Public\Services\Enable-nxService.ps1' 34
#Region '.\Public\Services\Get-nxService.ps1' 0

function Get-nxService
{
    [CmdletBinding()]
    [OutputType([nxService])]
    param
    (
        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $Name,

        [Parameter()]
        [nxInitSystem]
        $Controller = (Get-nxInitSystem)
    )

    if ($PSBoundParameters.ContainsKey('Controller'))
    {
        $null = $PSBoundParameters.Remove('Controller')
    }

    if (-not $PSBoundParameters.ContainsKey('Name'))
    {
        switch ($Controller)
        {
            'systemd' { Get-nxSystemdService @PSBoundParameters}

            default
            {
                throw ('The controller {0} is not yet supported with ''Get-nxService''.' -f $Controller)
            }
        }
    }
    else
    {
        foreach ($serviceName in $Name)
        {
            switch ($Controller)
            {
                'systemd' { Get-nxSystemdService @PSboundParameters }

                default
                {
                    throw ('The controller {0} is not yet supported with ''Get-nxService''.' -f $Controller)
                }
            }
        }
    }
}
#EndRegion '.\Public\Services\Get-nxService.ps1' 50
#Region '.\Public\Services\Restart-nxService.ps1' 0
function Restart-nxService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $Name,

        [Parameter()]
        [nxInitSystem]
        $Controller = (Get-nxInitSystem)
    )

    if ($PSBoundParameters.ContainsKey('Controller'))
    {
        $null = $PSBoundParameters.Remove('Controller')
    }

    foreach ($serviceName in $Name)
    {
        switch ($Controller)
        {
            'systemd' { Restart-nxSystemdService @PSBoundParameters }

            default
            {
                throw ('The controller {0} is not yet supported with ''Restart-nxService''.' -f $Controller)
            }
        }
    }
}
#EndRegion '.\Public\Services\Restart-nxService.ps1' 34
#Region '.\Public\Services\Start-nxService.ps1' 0
function Start-nxService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $Name,

        [Parameter()]
        [nxInitSystem]
        $Controller = (Get-nxInitSystem)
    )

    if ($PSBoundParameters.ContainsKey('Controller'))
    {
        $null = $PSBoundParameters.Remove('Controller')
    }

    foreach ($serviceName in $Name)
    {
        switch ($Controller)
        {
            'systemd' { Start-nxSystemdService @PSboundParameters }

            default
            {
                throw ('The controller {0} is not yet supported with ''Start-nxService''.' -f $Controller)
            }
        }
    }
}
#EndRegion '.\Public\Services\Start-nxService.ps1' 34
#Region '.\Public\Services\Stop-nxService.ps1' 0
function Stop-nxService
{
    [CmdletBinding()]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $Name,

        [Parameter()]
        [nxInitSystem]
        $Controller = (Get-nxInitSystem)
    )

    if ($PSBoundParameters.ContainsKey('Controller'))
    {
        $null = $PSBoundParameters.Remove('Controller')
    }

    foreach ($serviceName in $Name)
    {
        switch ($Controller)
        {
            'systemd' { Stop-nxSystemdService @PSboundParameters }

            default
            {
                throw ('The controller {0} is not yet supported with ''Stop-nxService''.' -f $Controller)
            }
        }
    }
}
#EndRegion '.\Public\Services\Stop-nxService.ps1' 34
#Region '.\Public\System\Get-nxDistributionInfo.ps1' 0
function Get-nxDistributionInfo
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String[]]
        $InfoFilePath = '/etc/*-release'
    )

    $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters.Verbose) -or $VerbosePreference -ne 'SilentlyContinue'

    $InfoFilePath = [string[]](Get-Item $InfoFilePath -ErrorAction Stop -Verbose:$Verbose)
    Write-Verbose -Message "Extracting distro info from '$($InfoFilePath -join "', '")'"

    $properties = Get-Content -Path $InfoFilePath |
        Get-PropertyHashFromListOutput -Regex '^\s*(?<property>[\w-\s]*)=\s*"?(?<val>.*)\b'

    [PSCustomObject]$properties | Add-Member -TypeName 'nx.DistributionInfo' -PassThru
}
#EndRegion '.\Public\System\Get-nxDistributionInfo.ps1' 21
#Region '.\Public\System\Get-nxKernelInfo.ps1' 0
function Get-nxKernelInfo
{
    [CmdletBinding()]
    param
    (

    )

    $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters.Verbose) -or $VerbosePreference -ne 'SilentlyContinue'

    $unameOutput = Invoke-NativeCommand -Executable 'uname' -Parameters @(
        # MacOS does not support long arguments
        '-s' # '--kernel-name',
        '-n' # '--nodename',
        '-r' # '--kernel-release',
        '-m' # '--machine',
        '-p' # '--processor',
        '-i' # '--hardware-platform',
        '-o' # '--operating-system'
    ) -Verbose:$verbose -ErrorAction 'Stop'

    if ($unameOutput -match '^\/.*uname:\s+')
    {
        throw $unameOutput
    }

    $kernelName, $ComputerName, $kernelRelease, $machineHardware, $processor, $hardwarePlatform, $OS = $unameOutput -split '\s'

    # uname --kernel-version
    $kernelVersion = Invoke-NativeCommand -Executable 'uname' -Parameters '-v' -Verbose:$verbose -ErrorAction 'Stop'

    [PSCustomObject]@{
        kernelName       = $kernelName
        ComputerName     = $ComputerName
        KernelRelease    = $kernelRelease
        KernelVersion    = $kernelVersion
        MachineHardware  = $machineHardware
        processor        = $processor
        hardwarePlatform = $hardwarePlatform
        OS               = $OS
    } | Add-Member -TypeName 'nx.KernelInfo' -PassThru
}
#EndRegion '.\Public\System\Get-nxKernelInfo.ps1' 43
#Region '.\Public\System\Get-nxLinuxStandardBaseRelease.ps1' 0
# By default on Debian 10, lsb-release package is not installed, so lsb_release
# gives a command not found.
function Get-nxLinuxStandardBaseRelease
{
    [OutputType([PSCustomObject])]
    [CmdletBinding()]
    param
    (
    )

    $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters.Verbose) -or $VerbosePreference -ne 'SilentlyContinue'

    $properties = Invoke-NativeCommand -Executable 'lsb_release' -Parameters '--all' -Verbose:$Verbose |
        Get-PropertyHashFromListOutput -ErrorHandling {
            switch -Regex ($_)
            {
                ''                 { }
                'No\sLSB\smodules' { Write-Verbose $_ }
                default            { Write-Error "$_" }
            }
        }

    [PSCustomObject]$properties | Add-Member -TypeName 'nx.LsbRelease' -PassThru
}

Set-Alias -Name Get-LsbRelease -Value Get-nxLinuxStandardBaseRelease
#EndRegion '.\Public\System\Get-nxLinuxStandardBaseRelease.ps1' 27
#Region '.\Public\usersAndGroups\Add-nxLocalGroupMember.ps1' 0
function Add-nxLocalGroupMember
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'medium')]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String]
        $GroupName,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String[]]
        [Alias('Member')]
        $UserName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Switch]
        $PassThru
    )

    begin
    {
        $verbose = $VerbosePreference -or ($PSBoundParameters.ContainsKey('verbose') -and $PSBoundParameters['verbose'])
        $hasGroupChanged = $false
    }

    process
    {
        foreach ($UserNameItem in $UserName)
        {
            $gpasswdParams = @('-a', $UserNameItem, $GroupName)

            if ($PSCmdlet.ShouldProcess(
                "Performing the unix command 'gpasswd $($gpasswdParams -join ' ')'.",
                $UserNameItem,
                "Removing $userNameItem grom group '$GroupName'.")
            )
            {
                Invoke-NativeCommand -Executable 'gpasswd' -Parameters $gpasswdParams -Verbose:$verbose |
                    ForEach-Object -Process {
                        if ($_ -match '^gpasswd:')
                        {
                            throw $_
                        }
                        else
                        {
                            Write-Verbose -Message $_
                        }
                    }

                $hasGroupChanged = $true
            }
        }

        if ($hasGroupChanged -and $PassThru)
        {
            Get-nxLocalGroup -GroupName $GroupName
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Add-nxLocalGroupMember.ps1' 61
#Region '.\Public\usersAndGroups\Add-nxLocalUserToGroup.ps1' 0
function Add-nxLocalUserToGroup
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'medium')]
    [OutputType([void])]
    param
    (

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $UserName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $GroupName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $PrimaryGroupName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Switch]
        $PassThru
    )

    begin
    {
        $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) -or $VerbosePreference -ne 'SilentlyContinue'
    }

    process
    {
        $userModParams = @('-a', '-G')

        $userModParams += @($GroupName -join ',')


        if ($PSBoundParameters.ContainsKey('PrimaryGroupName'))
        {
            $userModParams += @('-g', $PrimaryGroupName)
        }

        $userModParams += @($UserName)

        if (
            $PScmdlet.ShouldProcess(
                "Performing the unix command 'usermod $(($userModParams -join ' '))'.",
                $UserName,
                "adding $userName to groups: '$($groupName -join ',')."
            )
        )
        {
            Invoke-NativeCommand -Executable 'usermod' -Parameters $userModParams -Verbose:$verbose -ErrorAction 'Stop' | ForEach-Object -Process {
                throw $_
            }

            if ($PSBoundParameters.ContainsKey('PassThru') -and $PSBoundParameters['PassThru'])
            {
                # return the created user
                Get-nxLocalUser -UserName $Username -ErrorAction Stop -Verbose:$verbose
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Add-nxLocalUserToGroup.ps1' 67
#Region '.\Public\usersAndGroups\Disable-nxLocalUser.ps1' 0
function Disable-nxLocalUser
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    [outputType([nxLocalUser])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [System.String[]]
        $UserName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $LockOnly,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $SkipNologinShell,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $DoNotExpireAccount,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $PassThru
    )

    begin
    {
        $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) -or $VerbosePreference -ne 'SilentlyContinue'
    }

    process
    {
        foreach ($UserNameItem in $UserName)
        {
            $usermodParams = @()

            # at the very least, we lock the account (does not impact ssh pub keys or PAM except pam_unix)
            $usermodParams += @('-L')

            if (-not $SkipNologinShell)
            {
                $usermodParams += @('-s','/sbin/nologin')
            }

            $usermodParams += @($UserNameItem)

            if (-not $LockOnly.IsPresent -and -not $DoNotExpireAccount.IsPresent)
            {
                $chageParams = @('-E0',$UserNameItem)
                $ShouldProcessMessage = "Disabling account '$UserNameItem': 'usermod $(($usermodParams -join ' ')) && chage $(($chageParams -join ' '))'."
            }
            else
            {
                $ShouldProcessMessage = "Locking account '$UserNameItem': 'usermod $(($usermodParams -join ' '))'."
            }

            if ($PSCmdlet.ShouldProcess(
                    $ShouldProcessMessage,
                    "$UserNameItem",
                    "Disabling account '$UserNameItem'."
                )
            )
            {

                Invoke-NativeCommand -Executable 'usermod' -Parameters $usermodParams -Verbose:$verbose -ErrorAction 'Stop' |
                    ForEach-Object -Process {
                        throw $_
                    }

                if (-not $LockOnly.IsPresent -and -not $DoNotExpireAccount.IsPresent)
                {
                    Invoke-NativeCommand -Executable 'chage' -Parameters $chageParams -Verbose:$verbose -ErrorAction 'Stop' |
                        ForEach-Object -Process {
                            throw $_
                        }
                }


                if ($PassThru.IsPresent)
                {
                    Get-nxLocalUser -UserName $UserName
                }
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Disable-nxLocalUser.ps1' 89
#Region '.\Public\usersAndGroups\Enable-nxLocalUser.ps1' 0
function Enable-nxLocalUser
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [System.String[]]
        $UserName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateSet([ValidShell],ErrorMessage="Value '{0}' is invalid. Try one of: {1}")]
        [String]
        $ShellCommand,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [datetime]
        $ExpireOn,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $PassThru
    )

    begin
    {
        $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) -or $VerbosePreference -ne 'SilentlyContinue'
    }

    process
    {
        foreach ($UserNameItem in $UserName)
        {
            $usermodParams = @()

            # at the very least, we lock the account (does not impact ssh pub keys or PAM except pam_unix)
            $usermodParams += @('-U')

            if ($PSBoundParameters.ContainsKey('ShellCommand'))
            {
                $usermodParams += @('-s', $ShellCommand)
            }

            if ($PSBoundParameters.ContainsKey('ExpireOn') -and $PSBoundParameters['ExpireOn'])
            {
                $usermodParams += @('-e', $ExpireOn.ToString('yyyy-MM-dd'))
            }

            $usermodParams += @($UserNameItem)

            if ($PSCmdlet.ShouldProcess(
                    "Performing the unix command 'usermod $(($usermodParams -join ' '))'.",
                    "$UserNameItem",
                    "Enabling account '$UserNameItem'."
                )
            )
            {
                Invoke-NativeCommand -Executable 'usermod' -Parameters $usermodParams -Verbose:$verbose -ErrorAction 'Stop' |
                    ForEach-Object -Process {
                        throw $_
                    }

                if ($PassThru.IsPresent)
                {
                    Get-nxLocalUser -UserName $UserName
                }
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Enable-nxLocalUser.ps1' 71
#Region '.\Public\usersAndGroups\Get-nxEtcShadow.ps1' 0
function Get-nxEtcShadow
{
    [CmdletBinding(DefaultParameterSetName = 'byUserName')]
    [outputType([nxEtcShadowEntry])]
    param
    (
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'byUserName', Position = 0)]
        [System.String[]]
        [Alias('GroupMember')]
        $UserName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'byRegexPattern', Position = 0)]
        [regex]
        $Pattern
    )

    begin
    {
        $readEtcShadow = {
            Get-Content -Path '/etc/shadow' | ForEach-Object -Process {
                [nxEtcShadowEntry]$_
            }
        }
    }

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'byUserName' -and -not $PSBoundParameters.ContainsKey('UserName'))
        {
            Write-Debug -Message "[Get-nxEtcShadowEntry] Reading /etc/shadow without filter."
            &$readEtcShadow
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'byRegexPattern')
        {
            Write-Debug -Message "[Get-nxEtcShadowEntry] Matching 'UserName' with regex pattern '$Pattern'."
            &$readEtcShadow | Where-Object -FilterScript {
                $_.username -match $Pattern
            }
        }
        else
        {
            $allUsers = &$readEtcShadow
            foreach ($userNameEntry in $UserName)
            {
                Write-Debug -Message "[Get-nxEtcShadowEntry] Finding Local users by UserName '$userNameEntry'."
                $allUsers | Where-Object -FilterScript {
                    $_.username -eq $userNameEntry
                }
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Get-nxEtcShadow.ps1' 53
#Region '.\Public\usersAndGroups\Get-nxLocalGroup.ps1' 0
function Get-nxLocalGroup
{
    [CmdletBinding(DefaultParameterSetName = 'byGroupName')]
    [OutputType()]
    param
    (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'byGroupName', Position = 0)]
        [System.String[]]
        [Alias('Group')]
        $GroupName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'byRegexPattern', Position = 0)]
        [regex]
        $Pattern
    )

    begin
    {
        # by doing this, we prefer content accuracy than IO/Speed (the /etc/group may be read many times).
        $readEtcGroupCmd = {
            Get-Content -Path '/etc/group' | ForEach-Object -Process {
                [nxLocalGroup]$_
            }
        }
    }

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'byGroupName' -and -not $PSBoundParameters.ContainsKey('GroupName'))
        {
            Write-Debug -Message "[Get-nxLocalGroup] Reading /etc/group without filter."
            &$readEtcGroupCmd
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'byRegexPattern')
        {
            Write-Debug -Message "[Get-nxLocalGroup] Matching 'GroupName' with regex pattern '$Pattern'."
            &$readEtcGroupCmd | Where-Object -FilterScript {
                $_.GroupName -match $Pattern
            }
        }
        else
        {
            $allGroups = &$readEtcGroupCmd
            foreach ($GroupNameEntry in $GroupName)
            {
                Write-Debug -Message "[Get-nxLocalGroup] Finding Local group by GroupName '$GroupNameEntry'."
                $allGroups | Where-Object -FilterScript {
                    $_.Groupname -eq $GroupNameEntry
                }
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Get-nxLocalGroup.ps1' 54
#Region '.\Public\usersAndGroups\Get-nxLocalUser.ps1' 0
function Get-nxLocalUser
{
    [CmdletBinding(DefaultParameterSetName = 'byUserName')]
    [OutputType()]
    param
    (
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, ParameterSetName = 'byUserName', Position = 0)]
        [System.String[]]
        [Alias('GroupMember')]
        $UserName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'byRegexPattern', Position = 0)]
        [regex]
        $Pattern
    )

    begin
    {
        $readPasswdCmd = {
            Get-Content -Path '/etc/passwd' | ForEach-Object -Process {
                [nxLocalUser]$_
            }
        }
    }

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'byUserName' -and -not $PSBoundParameters.ContainsKey('UserName'))
        {
            Write-Debug -Message "[Get-nxLocalUser] Reading /etc/passwd without filter."
            &$readPasswdCmd
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'byRegexPattern')
        {
            Write-Debug -Message "[Get-nxLocalUser] Matching 'UserName' with regex pattern '$Pattern'."
            &$readPasswdCmd | Where-Object -FilterScript {
                $_.username -match $Pattern
            }
        }
        else
        {
            $allUsers = &$readPasswdCmd
            foreach ($userNameEntry in $UserName)
            {
                Write-Debug -Message "[Get-nxLocalUser] Finding Local users by UserName '$userNameEntry'."
                $allUsers | Where-Object -FilterScript {
                    $_.username -eq $userNameEntry
                }
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Get-nxLocalUser.ps1' 53
#Region '.\Public\usersAndGroups\Get-nxLocalUserMemberOf.ps1' 0
function Get-nxLocalUserMemberOf
{
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.String[]]
        [Alias('UserName','UserId')]
        $User
    )

    process {
        foreach ($UserItem in $User)
        {
            [string] $UserName = ''
            if ($UserItem -match '^\d+$')
            {
                # by User ID
                $UserName = Get-nxLocalUser | Where-Object -FilterScript { $_.UserId -eq $UserItem }
            }
            else
            {
                # by User Name
                $UserName = $UserItem
            }

            $memberOf = (Invoke-NativeCommand -Executable 'id' -Parameters @('-G', '-n', $UserName) -ErrorAction 'Stop') -split '\s+' | Foreach-Object -Process {
                if ($_ -match '^id:\s')
                {
                    throw $_
                }
                else
                {
                    Get-nxLocalGroup -GroupName $_
                }
            }

            [PSCustomObject]@{
                PsTypeName = 'nx.LocalUser.MemberOf'
                User       = $UserName
                MemberOf   = $memberOf
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Get-nxLocalUserMemberOf.ps1' 47
#Region '.\Public\usersAndGroups\New-nxLocalGroup.ps1' 0
function New-nxLocalGroup
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$')]
        [System.String]
        [Alias('Group','Name')]
        $GroupName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [System.String]
        [Alias('Password')]
        # The encrypted password, as returned by crypt(3).
        # Note: This option is not recommended because the password (or encrypted password) will be visible by users listing the processes.
        # You should make sure the password respects the system's password policy.
        $EncryptedPassword,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        # Overrides /etc/login.defs defaults (UID_MIN, UID_MAX, UMASK, PASS_MAX_DAYS and others).
        # Example: -K PASS_MAX_DAYS=-1 can be used when creating system account to turn off password ageing, even though system account has no password at all.
        # Multiple -K options can be specified, e.g.: -K UID_MIN=100 -K UID_MAX=499
        # Note: -K UID_MIN=10,UID_MAX=499 doesn't work yet.
        [hashtable]
        $LoginDefsOverride,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        # Allow the creation of a group with a duplicate (non-unique) GID.
        # This option is only valid in combination with the -preferredGID option.
        [switch]
        $AllowNonUniqueGID,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        # Create a system group.
        [switch]
        $SystemAccount,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        # -R
        # Directory to chroot into
        $ChrootDirectory,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        # Preferred GID if not already used (unless -AllowNonUniqueUID is used).
        [Int]
        [Alias('GroupID', 'GID')]
        $preferredGID,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Force,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $PassThru
    )

    begin
    {
        $verbose = $PSBoundParameters.ContainsKey('verbose') -and $PSBoundParameters['Verbose']
    }

    process
    {
        if ([nxLocalGroup]::Exists($GroupName))
        {
            throw ("A group account named '{0}' is already present." -f $GroupName)
        }

        $groupAddParams = @()

        if ($PSBoundParameters.ContainsKey('Force') -and $PSBoundParameters['Force'])
        {
            $groupAddParams += @('-f')
        }

        if ($PSBoundParameters.ContainsKey('EncryptedPassword') -and $PSBoundParameters['EncryptedPassword'])
        {
            $groupAddParams += @('-p', $EncryptedPassword)
        }

        if ($PSBoundParameters.ContainsKey('AllowNonUniqueGID') -and $PSBoundParameters['AllowNonUniqueGID'])
        {
            $groupAddParams += '-o'
        }

        if ($PSBoundParameters.ContainsKey('SystemAccount') -and $PSBoundParameters['SystemAccount'])
        {
            $groupAddParams += '-r'
        }

        if ($PSBoundParameters.ContainsKey('ChrootDirectory') -and $PSBoundParameters['ChrootDirectory'])
        {
            $groupAddParams += @('-R', $ChrootDirectory)
        }

        if ($PSBoundParameters.ContainsKey('preferredGID') -and $PSBoundParameters['preferredGID'])
        {
            $groupAddParams += @('-g', $preferredGID)
        }

        # LoginDefsOverride
        if ($PSBoundParameters.ContainsKey('LoginDefsOverride') -and $PSBoundParameters['LoginDefsOverride'])
        {
            $LoginDefsOverride.Keys.ForEach({
                $groupAddParams += ('-K {0}={1}' -f $_, $LoginDefsOverride[$_])
            })
        }

        if ($PScmdlet.ShouldProcess("Performing the unix command 'groupadd $(($groupAddParams + @($GroupName)) -join ' ')'.", "$GroupName", "Adding LocalGroup to $(hostname)?") -or $Force.IsPresent)
        {
            Invoke-NativeCommand -Executable 'groupadd' -Parameter ($groupAddParams + @($GroupName)) -Verbose:$verbose -ErrorAction 'Stop' | Foreach-Object {
                throw $_
            }

            if ($PSBoundParameters.ContainsKey('PassThru') -and $PSBoundParameters['PassThru'])
            {
                # return the created group
                Get-nxLocalGroup -GroupName $GroupName -ErrorAction Stop
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\New-nxLocalGroup.ps1' 131
#Region '.\Public\usersAndGroups\New-nxLocalUser.ps1' 0
function New-nxLocalUser
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-z_]([a-z0-9_-]{0,31}|[a-z0-9_-]{0,30}\$)$')]
        [System.String]
        $UserName,

        [Parameter()]
        [System.String]
        [Alias('Password')]
        # The encrypted password, as returned by crypt(3).
        # Note: This option is not recommended because the password (or encrypted password) will be visible by users listing the processes.
        # You should make sure the password respects the system's password policy.
        $EncryptedPassword,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        # Any text string. It is generally a short description of the login, and is currently used as the field for the user's full name.
        [System.String]
        [Alias('Comment')]
        $UserInfo,

        [Parameter()]
        # The new user will be created using HOME_DIR as the value for the user's login directory.
        # The default is to append the LOGIN name to BASE_DIR and use that as the login directory name.
        # The directory HOME_DIR does not have to exist but will not be created if it is missing.
        [ValidateNotNullOrEmpty()]
        [System.String]
        $HomeDirectory,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        [Alias('shell')]
        # The name of the user's login shell.
        # The default is to leave this field blank, which causes the system to select the default login shell
        # specified by the SHELL variable in /etc/default/useradd, or an empty string by default.
        $ShellCommand,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [datetime]
        # The date on which the user account will be disabled. The date is specified in the format YYYY-MM-DD.
        # If not specified, useradd will use the default expiry date specified by the EXPIRE variable in /etc/default/useradd,
        # or an empty string (no expiry) by default.
        $ExpireOn,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        # The default base directory for the system if -d HOME_DIR is not specified. BASE_DIR is concatenated with the account name to define the home directory.
        # If the -m option is not used, BASE_DIR must exist.
        # If this option is not specified, useradd will use the base directory specified by the HOME variable in /etc/default/useradd, or /home by default.
        [System.String]
        $HomeDirectoryBase,

        [Parameter()]
        # The number of days after a password expires until the account is permanently disabled.
        # A value of 0 disables the account as soon as the password has expired,
        # and a value of -1 disables the feature.
        # If not specified, useradd will use the default inactivity period specified by the INACTIVE variable in /etc/default/useradd, or -1 by default.)
        [int]
        $DayPasswordExpiredBeforeAutoDisable,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        # The group name or number of the user's initial login group. The group name must exist.
        # A group number must refer to an already existing group.
        # If not specified, the bahavior of useradd will depend on the USERGROUPS_ENAB variable in /etc/login.defs.
        # If this variable is set to yes (or -U/--user-group is specified on the command line),
        # a group will be created for the user, with the same name as her loginname.
        # If the variable is set to no (or -N/--no-user-group is specified on the command line),
        # useradd will set the primary group of the new user to the value specified by the GROUP variable in /etc/default/useradd,
        # or 100 by default.
        [System.String]
        [Alias('GroupId')]
        $PrimaryGroup,

        [Parameter()]
        # A list of supplementary groups which the user is also a member of.
        # The groups are subject to the same restrictions as the group given with the -g option. The default is for the user to belong only to the initial group.
        [System.String[]]
        $SupplementaryGroup,

        [Parameter()]
        # Overrides /etc/login.defs defaults (UID_MIN, UID_MAX, UMASK, PASS_MAX_DAYS and others).
        # Example: -K PASS_MAX_DAYS=-1 can be used when creating system account to turn off password ageing, even though system account has no password at all.
        # Multiple -K options can be specified, e.g.: -K UID_MIN=100 -K UID_MAX=499
        # Note: -K UID_MIN=10,UID_MAX=499 doesn't work yet.
        [hashtable]
        $LoginDefsOverride,

        [Parameter()]
        # -M
        # Do not create the user's home directory, even if the system wide setting from /etc/login.defs (CREATE_HOME) is set to yes.
        [switch]
        $SkipCreateHomeDirectory,

        [Parameter()]
        [switch]
        # Do not add the user to the lastlog and faillog databases.
        # By default, the user's entries in the lastlog and faillog databases are resetted to avoid reusing the
        # entry from a previously deleted user.
        $NoLogInit,

        [Parameter()]
        # Do not create a group with the same name as the user, but add the user to the group specified
        # by the -g option or by the GROUP variable in /etc/default/useradd.
        # The default behavior (if the -g, -N, and -U options are not specified) is defined by the
        # USERGROUPS_ENAB variable in /etc/login.defs.
        [switch]
        $SkipCreateUserGroup,

        [Parameter()]
        # Allow the creation of a user account with a duplicate (non-unique) UID.
        # This option is only valid in combination with the -preferredUID option.
        [switch]
        $AllowNonUniqueUID,

        [Parameter()]
        # Create a system account.
        # System users will be created with no aging information in /etc/shadow,
        # and their numeric identifiers are choosen in the SYS_UID_MIN-SYS_UID_MAX range, defined in /etc/login.defs,
        # instead of UID_MIN-UID_MAX (and their GID counterparts for the creation of groups).
        # Note that useradd will not create a home directory for such an user,
        # regardless of the default setting in /etc/login.defs (CREATE_HOME).
        # You have to specify the -m options if you want a home directory for a system account to be created.
        [switch]
        $SystemAccount,

        [Parameter()]
        # The skeleton directory, which contains files and directories to be copied in the user's home directory,
        # when the home directory is created by useradd.
        # This option is only valid if the -m (or --create-home) option is specified.
        #
        # If this option is not set, the skeleton directory is defined by the SKEL variable in
        # /etc/default/useradd or, by default, /etc/skel.
        [String]
        $SkeletonDirectory,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [System.String]
        # -R
        # Directory to chroot into
        $ChrootDirectory,

        [Parameter()]
        # Preferred UID if not already used (unless -AllowNonUniqueUID is used).
        [Int]
        [Alias('UserID', 'uid')]
        $preferredUID,

        [Parameter()]
        [switch]
        $PassThru
    )

    begin
    {
        $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) -or $VerbosePreference -ne 'SilentlyContinue'
    }

    process
    {
        if ([nxLocalUser]::Exists($UserName))
        {
            throw ("A user account for '{0}' is already present." -f $UserName)
        }

        $userAddParams = @()

        if ($PSBoundParameters.ContainsKey('EncryptedPassword') -and $PSBoundParameters['EncryptedPassword'])
        {
            $userAddParams += @('-p', $EncryptedPassword)
        }

        if ($PSBoundParameters.ContainsKey('ShellCommand') -and $PSBoundParameters['ShellCommand'])
        {
            $userAddParams += @('-s', (Get-nxEscapedPath -Path $ShellCommand))
        }

        if ($PSBoundParameters.ContainsKey('HomeDirectory') -and $PSBoundParameters['HomeDirectory'])
        {
            $userAddParams += @('-d', (Get-nxEscapedPath -Path $HomeDirectory))
        }

        if ($PSBoundParameters.ContainsKey('UserInfo') -and $PSBoundParameters['UserInfo'])
        {
            $userAddParams += @('-c', $UserInfo)
        }

        if ($PSBoundParameters.ContainsKey('ExpireOn') -and $PSBoundParameters['ExpireOn'])
        {
            $userAddParams += @('-e', $ExpireOn.ToString('yyyy-MM-dd'))
        }

        if ($PSBoundParameters.ContainsKey('HomeDirectoryBase') -and $PSBoundParameters['HomeDirectoryBase'])
        {
            $userAddParams += @('-b', (Get-nxEscapedPath -Path $HomeDirectoryBase))
        }

        if ($PSBoundParameters.ContainsKey('DayPasswordExpiredBeforeAutoDisable') -and $PSBoundParameters['DayPasswordExpiredBeforeAutoDisable'])
        {
            $userAddParams += @('-f', $DayPasswordExpiredBeforeAutoDisable)
        }

        if ($PSBoundParameters.ContainsKey('PrimaryGroup') -and $PSBoundParameters['PrimaryGroup'])
        {
            $userAddParams += @('-f', $PrimaryGroup)
        }

        if ($PSBoundParameters.ContainsKey('NoLogInit') -and $PSBoundParameters['NoLogInit'])
        {
            $userAddParams += '-l'
        }

        if ($PSBoundParameters.ContainsKey('SkipCreateHomeDirectory') -and $PSBoundParameters['SkipCreateHomeDirectory'])
        {
            $userAddParams += '-M'
        }

        if ($PSBoundParameters.ContainsKey('SkipCreateUserGroup') -and $PSBoundParameters['SkipCreateUserGroup'])
        {
            $userAddParams += '-N'
        }
        else
        {
            # --user-group  create a group with the same name as the user (by default)
            $userAddParams += '-U'
        }

        if ($PSBoundParameters.ContainsKey('AllowNonUniqueUID') -and $PSBoundParameters['AllowNonUniqueUID'])
        {
            $userAddParams += '-o'
        }

        if ($PSBoundParameters.ContainsKey('SystemAccount') -and $PSBoundParameters['SystemAccount'])
        {
            $userAddParams += '-r'
        }

        if ($PSBoundParameters.ContainsKey('SkeletonDirectory') -and $PSBoundParameters['SkeletonDirectory'])
        {
            $userAddParams += @('-k', $SkeletonDirectory)
        }

        if ($PSBoundParameters.ContainsKey('ChrootDirectory') -and $PSBoundParameters['ChrootDirectory'])
        {
            $userAddParams += @('-R', $ChrootDirectory)
        }

        if ($PSBoundParameters.ContainsKey('SupplementaryGroup') -and $PSBoundParameters['SupplementaryGroup'])
        {
            $userAddParams += @('-G', ($SupplementaryGroup -join ','))
        }

        if ($PSBoundParameters.ContainsKey('preferredUID') -and $PSBoundParameters['preferredUID'])
        {
            $userAddParams += @('-u', $preferredUID)
        }

        # LoginDefsOverride
        if ($PSBoundParameters.ContainsKey('LoginDefsOverride') -and $PSBoundParameters['LoginDefsOverride'])
        {
            $LoginDefsOverride.Keys.ForEach({
                $userAddParams += ('-K {0}={1}' -f $_, $LoginDefsOverride[$_])
            })
        }

        if ($PScmdlet.ShouldProcess("Performing the unix command 'useradd $(($userAddParams + @($UserName)) -join ' ')'.", "$UserName", "Adding LocalUser to $(hostname)"))
        {
            $warn = $false
            Invoke-NativeCommand -Executable 'useradd' -Parameter ($userAddParams + @($UserName)) -Verbose:$verbose -ErrorAction 'Stop' | Foreach-Object {
                if ($_.ToString() -match '^useradd: warning:(?<message>.*)')
                {
                    # we're seeing a warning only
                    $warn = $true
                }
                elseif ($_.ToString() -match '^Usage:')
                {
                    throw ('Invalid Syntax. useradd {0}' -f (($userAddParams + @($UserName)) -join ' '))
                }
                elseif ($_.ToString() -match '^useradd:|^Usage:')
                {
                    # We're seeing an error, what comes after is an error.
                    $warn = $false
                }

                if ($true -eq $warn)
                {
                    Write-Warning -Message $_
                }
                else
                {
                    Write-Error -Message $_
                }
            }

            if ($PSBoundParameters.ContainsKey('PassThru') -and $PSBoundParameters['PassThru'])
            {
                # return the created user
                Get-nxLocalUser -UserName $Username -ErrorAction Stop
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\New-nxLocalUser.ps1' 314
#Region '.\Public\usersAndGroups\Remove-nxLocalGroup.ps1' 0
function Remove-nxLocalGroup
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([void])]
    param
    (

        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]]
        [Alias('Group')]
        $GroupName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Force
    )

    begin
    {
        $verbose = $PSBoundParameters.ContainsKey('verbose') -and $PSBoundParameters['Verbose']
        $groupDelParams += @()
    }

    process
    {
        if ($PSBoundParameters.ContainsKey('RemoveHomeDirAndMailSpool') -and $PSBoundParameters['RemoveHomeDirAndMailSpool'])
        {
            $groupDelParams += @('-r')
        }

        if ($PSBoundParameters.ContainsKey('Force') -and $PSBoundParameters['Force'])
        {
            $groupDelParams += @('-f')
        }

        foreach ($GroupNameItem in $GroupName)
        {
            if ($PScmdlet.ShouldProcess("Performing the unix command 'groupdel $(($groupDelParams + @($GroupNameItem)) -join ' ')'.", $GroupNameItem, "Removing local group '$GroupNameItem' from '$(hostname)'."))
            {
                Invoke-NativeCommand -Executable 'groupdel' -Parameter ($groupDelParams + @($GroupNameItem)) -Verbose:$verbose -ErrorAction 'Stop' | Foreach-Object {
                    throw $_
                }
            }
        }
    }




}
#EndRegion '.\Public\usersAndGroups\Remove-nxLocalGroup.ps1' 51
#Region '.\Public\usersAndGroups\Remove-nxLocalGroupMember.ps1' 0
function Remove-nxLocalGroupMember
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $UserName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]
        $GroupName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Switch]
        $PassThru
    )

    begin
    {
        $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) -or $VerbosePreference -ne 'SilentlyContinue'
        $hasGroupChanged = $false
    }

    process
    {

        foreach ($UserNameItem in $UserName)
        {
            $gpasswdParams = @('-d', $UserNameItem, $GroupName)
            if ($PSCmdlet.ShouldProcess(
                    "Performing the unix command 'gpasswd $($gpasswdParams -join ' ')'.",
                    $UserNameItem,
                    "Removing $userNameItem grom group '$GroupName'."
                )
            )
            {
                Invoke-NativeCommand -Executable 'gpasswd' -Parameters $gpasswdParams -Verbose:$verbose -ErrorAction 'Stop' |
                    ForEach-Object -Process {
                        if ($_ -match '^gpasswd:')
                        {
                            throw $_
                        }
                        else
                        {
                            Write-Verbose -Message $_
                        }
                    }

                $hasGroupChanged = $true
            }
        }

        if ($hasGroupChanged -and $PassThru)
        {
            Get-nxLocalGroup -GroupName $GroupName
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Remove-nxLocalGroupMember.ps1' 60
#Region '.\Public\usersAndGroups\Remove-nxLocalUser.ps1' 0
function Remove-nxLocalUser
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([void])]
    param
    (

        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)]
        [string[]]
        [Alias('User','Name')]
        $UserName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $RemoveHomeDirAndMailSpool,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Force
    )

    begin
    {
        $verbose = $PSBoundParameters.ContainsKey('verbose') -and $PSBoundParameters['Verbose']
        $userDelParams += @()
    }

    process
    {
        if ($PSBoundParameters.ContainsKey('RemoveHomeDirAndMailSpool') -and $PSBoundParameters['RemoveHomeDirAndMailSpool'])
        {
            $userDelParams += @('-r')
        }

        if ($PSBoundParameters.ContainsKey('Force') -and $PSBoundParameters['Force'])
        {
            $userDelParams += @('-f')
        }

        foreach ($UserNameItem in $UserName)
        {
            if ($PScmdlet.ShouldProcess("Performing the unix command 'userdel $(($userDelParams + @($userNameItem)) -join ' ')'.", $UserNameItem, "Removing local user '$UserNameItem' from '$(hostname)'."))
            {
                Invoke-NativeCommand -Executable 'userdel' -Parameter ($userDelParams + @($userNameItem)) -Verbose:$verbose -ErrorAction 'Stop' | Foreach-Object {
                    throw $_
                }
            }
        }
    }




}
#EndRegion '.\Public\usersAndGroups\Remove-nxLocalUser.ps1' 55
#Region '.\Public\usersAndGroups\Set-nxLocalGroup.ps1' 0
function Set-nxLocalGroup
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'removePassword')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'restrict')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'setMemberOrAdmin')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'setMember')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'setAdmin')]
        [String]
        $GroupName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'removePassword')]
        [Switch]
        $RemovePassword,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'restrict')]
        [Switch]
        $Restrict,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'setMemberOrAdmin')]
        [String[]]
        $Member,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'setMemberOrAdmin')]
        [String[]]
        $Administrators,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'removePassword')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'restrict')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'setMemberOrAdmin')]
        [switch]
        $PassThru
    )

    begin
    {
        $verbose = ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) -or $VerbosePreference -ne 'SilentlyContinue'
    }

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'setMemberOrAdmin' -and -not ($PSBoundParameters.ContainsKey('Administrators') -or $PSBoundParameters.ContainsKey('Member')))
        {
            throw "Parameter set cannot be resolved using the specified named parameters. One or more parameters issued cannot be used together or an insufficient number of parameters were provided."
            return
        }

        $gpasswdParams = @()

        if ($PSBoundParameters.ContainsKey('RemovePassword') -and $PSBoundParameters['RemovePassword'])
        {
            $gpasswdParams += @('-r')
        }

        if ($PSBoundParameters.ContainsKey('Restrict') -and $PSBoundParameters['Restrict'])
        {
            $gpasswdParams += @('-R')
        }

        if ($PSBoundParameters.ContainsKey('Member') -and $PSBoundParameters['Member'])
        {
            $gpasswdParams += @('-M', ($Member -join ','))
        }

        if ($PSBoundParameters.ContainsKey('Administrators') -and $PSBoundParameters['Administrators'])
        {
            $gpasswdParams += @('-A', ($Administrators -join ','))
        }

        $gpasswdParams += @($GroupName)

        if ($PSCmdlet.ShouldProcess(
                "Performing the unix command 'gpasswd $(($gpasswdParams -join ' '))'.",
                $GroupName,
                "Setting LocalGroup $GroupName"
            )
        )
        {
            Invoke-NativeCommand -Executable 'gpasswd' -Parameters $gpasswdParams -Verbose:$verbose | ForEach-Object -Process {
                if ($_ -match '^gpasswd:')
                {
                    throw $_
                }
                else
                {
                    Write-Verbose -Message "$_"
                }
            }

            if ($PSBoundParameters.ContainsKey('PassThru') -and $PSBoundParameters['PassThru'])
            {
                # return the group
                Get-nxLocalGroup -GroupName $GroupName -ErrorAction Stop
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Set-nxLocalGroup.ps1' 101
#Region '.\Public\usersAndGroups\Set-nxLocalGroupGID.ps1' 0

function Set-nxLocalGroupGID
{
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([void])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $GroupName,

        [Parameter(Mandatory = $true)]
        [int]
        [Alias('GID')]
        $GroupID
    )

    $gpasswdParams = @('-g', $GroupID, $GroupName)


    if ($PSCmdlet.ShouldProcess(
                "Performing the unix command 'gpasswd $(($gpasswdParams -join ' '))'.",
                "$GroupName",
                "Setting LocalGroup $GroupName"
            )
        )
    {
        Invoke-NativeCommand -Executable 'groupmod' -Parameters $groupmodParams -Verbose:$verbose |
        Foreach-Object -ScriptBlock {
            throw $_
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Set-nxLocalGroupGID.ps1' 34
#Region '.\Public\usersAndGroups\Set-nxLocalGroupMember.ps1' 0
function Set-nxLocalGroupMember
{
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String[]]
        $Member,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]
        $GroupName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Switch]
        $PassThru
    )

    process
    {
        Set-nxLocalGroup @PSBoundParameters
    }
}
#EndRegion '.\Public\usersAndGroups\Set-nxLocalGroupMember.ps1' 25
#Region '.\Public\usersAndGroups\Set-nxLocalUser.ps1' 0
function Set-nxLocalUser
{
    [CmdletBinding(DefaultParameterSetName = 'ParameterizedGECOSAddGroupExpireOn', SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    param
    (

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [System.String]
        $UserName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [System.String]
        # compose with Description and build for -c
        $FullName,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [System.String]
        # same as above
        $Office,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [System.String]
        # same as above
        $OfficePhone,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [System.String]
        # same as above
        $HomePhone,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [System.String]
        # same as above
        $Description,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [ValidateNotNullOrEmpty()]
        [System.String]
        [Alias('Password')]
        # -p
        $EncryptedPassword,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [System.Management.Automation.SwitchParameter]
        # -L
        $Locked,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [ValidateNotNullOrEmpty()]
        [datetime]
        # The date on which the user account will be disabled. The date is specified in the format YYYY-MM-DD.
        # If not specified, useradd will use the default expiry date specified by the EXPIRE variable in /etc/default/useradd,
        # or an empty string (no expiry) by default.
        $ExpireOn,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [System.Management.Automation.SwitchParameter]
        $RequirePasswordChange,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [int]
        # -u
        $UserID,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [int]
        # -g
        $PrimaryGroup,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [System.String[]]
        # -a  -G
        $GroupToSet,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [System.String[]]
        # -a  -G
        $GroupToAdd,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [System.String]
        [Alias('GECOS')]
        # Set new value for GECOS field
        $UserInfo,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [System.String]
        # -d
        $HomeDirectory,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [System.Management.Automation.SwitchParameter]
        # -m only when -HomeDirectory is used
        $MoveHomeToNewHomeDirectory,

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'ParameterizedGECOSSetGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSAddGroupRequirePwdChange')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupExpireOn')]
        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'GECOSSetGroupRequirePwdChange')]
        [System.String]
        # -s
        $ShellCommand
    )

    begin
    {
        $verbose = $VerbosePreference -or ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose'])
    }

    process
    {
        $usermodParams = @()

        # Do we need to set the GECOS field?
        $compareObjectParams = @{
            ReferenceObject  = $PSBoundParameters.Keys
            DifferenceObject = @(
                'FullName'
                'Office'
                'OfficePhone'
                'HomePhone'
                'Description'
            )
            IncludeEqual     = $true
            ExcludeDifferent = $true
        }

        $ShouldChangeGECOS = $null -ne (Compare-Object @compareObjectParams)

        if (
            $PSCmdlet.ParameterSetName -match 'ParameterizedGECOS' -and
            $ShouldChangeGECOS
        )
        {
            $existingUser = Get-nxLocalUser -UserName $UserName -ErrorAction 'SilentlyContinue'
            $FullNameToSet = $existingUser.FullName
            $OfficeToSet = $existingUser.Office
            $OfficePhoneToSet = $existingUser.OfficePhone
            $HomePhoneToSet = $existingUser.HomePhone
            $DescriptionToSet = $existingUser.Description

            switch ($PSBoundParameters.keys)
            {
                'FullName'
                {
                    $FullNameToSet = $FullName
                }

                'Office'
                {
                    $OfficeToSet = $Office
                }

                'OfficePhone'
                {
                    $OfficePhoneToSet = $OfficePhone
                }

                'HomePhone'
                {
                    $HomePhoneToSet = $HomePhone
                }

                'Description'
                {
                    $DescriptionToSet = $Description
                }
            }

            $gecosField = '{0},{1},{2},{3},{4}' -f $FullNameToSet, $OfficeToSet, $OfficePhoneToSet, $HomePhoneToSet, $DescriptionToSet
            $usermodParams += @('-c', ($gecosField | Get-nxEscapedString))
        }
        elseif ($PSBoundParameters.ContainsKey('UserInfo'))
        {
            $usermodParams += @('-c', ($UserInfo | Get-nxEscapedString))
        }

        if ($PSBoundParameters.ContainsKey('EncryptedPassword'))
        {
            $usermodParams += @('-p', ($EncryptedPassword | Get-nxEscapedString))
        }

        if ($Locked.IsPresent)
        {
            $usermodParams += @('-L')
        }

        if ($PSBoundParameters.ContainsKey('ExpireOn') -and $PSBoundParameters['ExpireOn'])
        {
            $userAddParams += @('-e', $ExpireOn.ToString('yyyy-MM-dd'))
        }
        elseif ($RequirePasswordChange.IsPresent)
        {
            # Set the password as Expired
            $yesterday = ([DateTime]::Now).AddDays(-1)

            $usermodParams = @('-e', $yesterday.ToString('yyyy-MM-dd'))
        }

        if ($PSBoundParameters.ContainsKey('UserID'))
        {
            $usermodParams += @('-u', $UserID)
        }

        if ($PSBoundParameters.ContainsKey('PrimaryGroup'))
        {
            $usermodParams += @('-g', $PrimaryGroup)
        }

        if ($PSBoundParameters.ContainsKey('GroupToSet'))
        {
            $usermodParams += @('-G', $GroupToSet)
        }
        elseif ($PSBoundParameters.ContainsKey('GroupToAdd'))
        {
            $usermodParams += @('-a','-G', $($GroupToAdd -join ','))
        }

        if ($PSBoundParameters.ContainsKey('HomeDirectory'))
        {
            $usermodParams += @('-d', ($HomeDirectory | Get-nxEscapedPath))

            if ($MoveHomeToNewHomeDirectory.IsPresent)
            {
                $usermodParams += @('-m')
            }
        }

        if ($PSBoundParameters.ContainsKey('ShellCommand'))
        {
            $usermodParams += @('-s', ($ShellCommand | Get-nxEscapedPath))
        }

        $usermodParams += @($UserName)

        if ($PSCmdlet.ShouldProcess(
                "Performing the unix command 'usermod $(($usermodParams -join ' '))'.",
                $UserName,
                "Setting LocalUser $UserName"
            )
        )
        {
            Invoke-NativeCommand -Executable 'usermod' -Parameters $usermodParams -Verbose:$verbose | ForEach-Object -Process {
                if ($_ -match '^usermod:')
                {
                    Write-Error $_
                }
                else
                {
                    Write-Verbose -Message "$_"
                }
            }
        }
    }
}
#EndRegion '.\Public\usersAndGroups\Set-nxLocalUser.ps1' 349

