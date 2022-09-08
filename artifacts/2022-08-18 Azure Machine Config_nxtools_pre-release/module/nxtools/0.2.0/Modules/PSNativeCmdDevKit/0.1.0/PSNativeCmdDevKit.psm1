#Region './Public/Add-SudoPreferenceRule.ps1' 0
# Add-SudoPreferenceRule -Executable dpkg -ParameterFilterRule {$_.parameters -contains '-i' -or $_.parameters -contains '--install')}
# Add-SudoPreferenceRule -Executable dpkg -ParameterFilterRule {$_.parameters -contains '-W' -or $_.parameters -contains '--show')} -SudoUser otheruser
# Add-SudoPreferenceRule -EnableSudoForAllCommands
# Add-SudoPreferenceRule -EnableSudoForAllCommands -SudoUser otheruser
# Add-SudoPreferenceRule -DisableSudoForAllCommands

function  Add-SudoPreferenceRule
{
    param
    (

        [Parameter(ParameterSetName = 'Sudo', Mandatory = $true)]
        [Alias('Command')]
        # The binary or command the rule will affect.
        [string]
        $Executable,

        [Parameter(ParameterSetName = 'Sudo', Mandatory = $true)]
        # The Parameter filter to be evaluated for the command.
        # if you want to use sudo for an Executable, regardless of the parameters, use:
        # `-ParameterFilterRule *` or `-ParameterFilterRule {$true}`
        # Otherwise, you can evaluate the Parameters to be used, populated the $Args variable:
        # `-ParameterFilterRule {$args -contains '-i' -or $args -contains '--install'}
        [string]
        $ParameterFilterRule,

        [Parameter(ParameterSetName = 'SudoAll', Mandatory = $true)]
        # This will Enable sudo for any command, but won't destroy your
        # registered settings. You can set a $SudoUser to be used along.
        [switch]
        $EnableSudoForAllCommands,

        [Parameter(ParameterSetName = 'NoSudoAll', Mandatory = $true)]
        # This will ensure sudo is not automatically added to each command,
        # instead it will use the Sudo Preference rules registered with `Add-SudoPreferenceRule`.
        [switch]
        $DisableSudoForAllCommands,

        [Parameter(ParameterSetName = 'Sudo')]
        [Parameter(ParameterSetName = 'SudoAll')]
        # The executable that is invoked with sudo should be run as this user.
        # the resulting command invoked will be `sudo <sudo user> <executable> <parameters>`.
        [string]
        $SudoUser
    )

    if ($script:SudoPreferenceRules -isnot [System.Collections.ArrayList])
    {
        # There is no default rules store, let's create an array list
        $script:SudoPreferenceRules = [System.Collections.ArrayList]::new()
    }

    if ($EnableSudoForAllCommands.IsPresent -or $DisableSudoForAllCommands.IsPresent)
    {
        $Script:SudoAll = switch ($PSCmdlet.ParameterSetName)
        {
            NoSudoAll   { $false  }
            SudoAll     { $true   }
        }

        # If sudoUser is specified, set to SudoAllAs. Clean up if disabling SudoAll
        $script:SudoAllAs = $SudoUser
        return
    }
    elseif ($Executable -eq '*')
    {
        $Script:SudoAll = switch -regex ($ParameterFilterRule.Trim())
        {
            '^\$true$'  { $true }
            '^\$false$' { $false }
            Default     { $true }
        }

        $script:SudoAllAs = $SudoUser
    }

    $index = $null

    if (Get-SudoPreferenceRule -Executable $Executable -ParameterFilterRule $ParameterFilterRule)
    {
        Write-Warning "Sudo Preference Rule found. Replacing"
        $index = [int](Remove-SudoPreferenceRule -Executable $Executable -ParameterFilterRule $ParameterFilterRule)
    }

    # copy hash with Executable, ParameterFilterRule, and SudoUser if present
    $newRule = @{
        Executable          = $Executable
        ParameterFilterRule = $ParameterFilterRule
        SudoUser            = $SudoUser
    }

    if ($index)
    {
        Write-Debug "Replacing Sudo rule for '$Executable' with filter '$ParameterFilterRule' at index $index"
        $null = $script:SudoPreferenceRules.Insert($index, $newRule)
    }
    else
    {
        Write-Debug "Adding Sudo rule for '$Executable' with filter '$ParameterFilterRule'"
        $null = $script:SudoPreferenceRules.Add($newRule)
    }
}
#EndRegion './Public/Add-SudoPreferenceRule.ps1' 102
#Region './Public/Get-PropertyHashFromListOutput.ps1' 0
function Get-PropertyHashFromListOutput
{
    [CmdletBinding(DefaultParameterSetName = 'AddExtraPropertiesUnderKey')]
    [OutputType([hashtable])]
    param
    (
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Mandatory = $true)]
        [Object]
        # Output from a command, typically the result of Invoke-LinuxCommand.
        # Error records will be handled by the scriptblock in -ErrorHandling parameter.
        # The latter defaults to send the error record to Write-Error.
        $Output,

        [Parameter()]
        # Regex with 'property' & 'val' Named groups
        # of a string to extract an hashtable key/value pair from a string.
        [regex]
        $Regex = '^\s*(?<property>[\w-\s]*):\s*(?<val>.*)',

        [Parameter()]
        # List of property names allowed to be parsed.
        # Default to '*' for all properties, otherwise the parsed properties
        # not listed here will either be discarded if -DiscardExtraProperties is set
        # or will be added to a hashtable under the key named $AddExtraPropertiesAsKey.
        [string[]]
        $AllowedPropertyName = '*',

        [Parameter(ValueFromPipelineByPropertyName = $true, ParameterSetName = 'DiscardExtraProperties')]
        # When only a limited number of Property named is allowed using -AllowedPropertyName
        # parameter, the extra properties will be discarded.
        [switch]
        $DiscardExtraProperties,

        [Parameter(ParameterSetName = 'AddExtraPropertiesUnderKey')]
        # When only a limited number of Property named is allowed using -AllowedPropertyName
        # parameter, the extra properties will be added under the `$property[$AddExtraPropertiesAsKey]`
        # hash. For instance, `$property['ExtraProperties']['NotAllowedPropertyName'] = $ParsedValue`
        [string]
        $AddExtraPropertiesAsKey = 'ExtraProperties',

        [Parameter()]
        # When the output of a native command has had its `STDERR` redirected
        # using `2>&1`, we'll send the ErrorRecords (output from STDERR) to
        # this scriptblock. By default: `$errorRecord | &{ Write-Error $_}`.
        [scriptblock]
        $ErrorHandling = { Write-Error $_ }
    )

    begin
    {
        $properties = @{}
        if (-not $DiscardExtraProperties.isPresent)
        {
            $properties[$AddExtraPropertiesAsKey] = @{}
        }
    }

    process
    {
        foreach ($line in $Output)
        {
            Write-Debug "Output Line: $line"
            if ($line -is [System.Management.Automation.ErrorRecord])
            {
                $line | &$ErrorHandling
            }
            elseif ($line -match $Regex)
            {
                $propertyName = $Matches.property.replace('-','').replace(' ','')
                if ($AllowedPropertyName -contains '*' -or $AllowedPropertyName -contains $propertyName)
                {
                    $properties.Add($propertyName, $Matches.val)
                }
                else
                {
                    if (-not $DiscardExtraProperties.isPresent)
                    {
                        Write-Debug " Adding Property '$propertyName' to $AddExtraPropertiesAsKey"
                        $properties[$AddExtraPropertiesAsKey].Add($propertyName, $Matches.val)
                    }
                }

                $lastProperty = $propertyName
            }
            else
            {
                if (-not $lastProperty)
                {
                    Write-Verbose $line
                }
                elseif ($AllowedPropertyName -contains '*' -or $AllowedPropertyName -contains $lastProperty)
                {
                    Write-Debug "  Adding second line to property $lastProperty"
                    $properties[$lastProperty] += "`n" + $line.TrimEnd()
                }
                else
                {
                    $properties[$AddExtraPropertiesAsKey][$lastProperty] += $line.Trim()
                }
            }
        }
    }

    end
    {
        if ($properties[$AddExtraPropertiesAsKey].Count -eq 0)
        {
            Write-Debug "No Extra properties where found, removing unnecessary key '$AddExtraPropertiesAsKey'"
            $properties.Remove($AddExtraPropertiesAsKey)
        }

        $properties
    }
}
#EndRegion './Public/Get-PropertyHashFromListOutput.ps1' 114
#Region './Public/Get-SudoPreference.ps1' 0
function Get-SudoPreference
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [Alias('Command')]
        # The binary or command to be executed.
        [string]
        $Executable,

        [Parameter()]
        # List of parameters to pass to the invocation that will be
        # evaluated against the registered Sudo Preference Rules.
        [String[]]
        $Parameters
    )

    if ($script:SudoAll)
    {
        @{
            $Sudo = $true
            $SudoAs = $script:SudoAllAs
        }
    }
    elseif ($script:SudoPreferenceRules)
    {
        $enumerator = $script:SudoPreferenceRules.GetEnumerator()
        $RuleMatchFound = $false
        while ($enumerator.MoveNext() -and -not $RuleMatchFound)
        {
            $RuleMatchFound = $script:SudoPreferenceRules | Where-Object -FilterScript {
                $Executable -eq $_.Executable -and
                ($_.ParameterFilterRule.ToString().Trim() -eq '*' -or [scriptblock]::create($_.ParameterFilterRule).Invoke($Parameters))
            } | Select-Object -First 1
        }

        if ($RuleMatchFound)
        {
            return [hashtable]$RuleMatchFound
        }
        else
        {
            Write-Debug "No matching rules for '$Executable' with params '$Parameters'"
        }
    }
}
#EndRegion './Public/Get-SudoPreference.ps1' 48
#Region './Public/Get-SudoPreferenceRule.ps1' 0
function  Get-SudoPreferenceRule
{
    [CmdletBinding(DefaultParameterSetName = 'all')]
    [OutputType([System.Object[]])]
    param
    (

        [Parameter(ParameterSetName = 'byCommand', Mandatory = $true)]
        [Alias('Command')]
        # The binary or command to be executed.
        [string]
        $Executable,

        [Parameter(ParameterSetName = 'byCommand')]
        [string]
        $ParameterFilterRule,

        [Parameter(ParameterSetName = 'all')]
        [switch]
        $All

    )

    if ($script:SudoPreferenceRules -isnot [System.Collections.ArrayList])
    {
        # There is no default rules store, let's create an array list and return it
        $script:SudoPreferenceRules = [System.Collections.ArrayList]::new()
    }

    if ($PSCmdlet.ParameterSetName -eq 'All')
    {
        $script:SudoPreferenceRules
    }
    else
    {
        $script:SudoPreferenceRules.Where{
            $_.Executable -eq $Executable -and
            $(
                if ($ParameterFilterRule -and $ParameterFilterRule.Trim() -ne '*')
                {
                    $_.ParameterFilterRule -eq $ParameterFilterRule
                }
                else
                {
                    $true
                }
            )
        }
    }
}
#EndRegion './Public/Get-SudoPreferenceRule.ps1' 50
#Region './Public/Invoke-NativeCommand.ps1' 0
function Invoke-NativeCommand
{
    [cmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Alias('Command')]
        # The binary or command you would like to execute.
        [string]
        $Executable,

        [Parameter()]
        # Whether you want to sudo the command invocation, on non-windows OSes.
        # If you want to sudo as a different user, use the parameter `-SudoAs`.
        [switch]
        $Sudo,

        [Parameter()]
        # Specify a user to sudo he command as. i.e.: `sudo otheruser ls -alh`
        [String]
        $SudoAs,

        [Parameter()]
        # list of Parameters to pass to the invocation.
        # For binaries and commands requiring a specific order
        # make sure it is respected as no further check is done.
        [String[]]
        $Parameters
    )

    # If Sudo or SudoAs is not specified, lookup in the Module variable DefaultCommandToSudo
    if ( -not ($PSBoundParameters.ContainsKey('Sudo') -or $PSBoundParameters.ContainsKey('SudoAs')) )
    {
        if ($DefaultSudo = Get-SudoPreference @PSBoundParameters)
        {
            $Sudo   = $DefaultSudo.Sudo
            $SudoAs = $DefaultSudo.SudoAs
        }
    }

    [string[]]$CommandExpression = @()

    if ($SudoAs -and ($IsLinux -or $IsMacOS))
    {
        $commandExpression += "sudo -u $SudoAs $Executable"
    }
    elseif ($Sudo -and ($IsLinux -or $IsMacOS))
    {
        $commandExpression += "sudo $Executable"
    }
    else
    {
        $commandExpression += $Executable
    }

    $commandExpression += $Parameters

    # Mixes the Error stream and the success streams (redirect STDERR with STDOUT)
    # What was in STDERR will be of type [ErrorRecord] if you need to differentiate for parsing.
    $commandExpression += '2>&1'

    Write-Verbose -Message "Running #> $commandExpression"
    [scriptblock]$commandExpression = [scriptblock]::create($commandExpression)

    # Stream the output through the pipeline
    & $commandExpression
}
#EndRegion './Public/Invoke-NativeCommand.ps1' 67
#Region './Public/Remove-SudoPreferenceRule.ps1' 0
function Remove-SudoPreferenceRule
{
    [cmdletBinding()]
    param
    (
        [Parameter(ParameterSetName = 'ByValue', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('Command')]
        # The executable that has the rule applied to.
        [string]
        $Executable,

        [Parameter(ParameterSetName = 'ByValue', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        # The parameter filter rule to match with the executable to remve.
        [string]
        $ParameterFilterRule,

        [Parameter(Dontshow = $true, ParameterSetName = 'ByIndex', Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        # Remove the Rule stored in the module's $script:SudoPreferenceRules by its index (advanced user only)
        [int]
        $index,

        [Parameter(ParameterSetName = 'All', Mandatory = $true)]
        # Remove all previously registered rules.
        [switch]
        $All
    )

    begin
    {
        if ($script:SudoPreferenceRules -isnot [System.Collections.ArrayList])
        {
            # There is no default rules store
            return
        }
    }

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'ByIndex')
        {
            $script:SudoPreferenceRules.RemoveAt($Index)
            return
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'All')
        {
            $script:SudoPreferenceRules.Clear()
            return
        }

        $CurrentIndex = 0
        $indexesToRemove = $script:SudoPreferenceRules.Foreach{
            if ($_.Executable -eq $Executable -and
                ($_.ParameterFilterRule.ToString().Trim() -eq '*' -or $_.ParameterFilterRule -eq $ParameterFilterRule)
            )
            {
                $CurrentIndex
            }

            $CurrentIndex++
        }

        $indexesToRemove.Foreach{
            $script:SudoPreferenceRules.RemoveAt($_)
            # return the Indexes where the rule has been removed
            $_
        }
    }
}
#EndRegion './Public/Remove-SudoPreferenceRule.ps1' 68
