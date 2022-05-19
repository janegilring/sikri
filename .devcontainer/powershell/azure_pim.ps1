Install-Module JaZ.PIM
Install-Module Microsoft.Graph.DeviceManagement.Enrolment

Import-Module JaZ.PIM
Update-Module JaZ.PIM

Select-MgProfile 'Beta'

gcm -mod JaZ.PIM

Get-JAzADRole

Enable-JAzRole 'Owner -> IT (b33cf45a-bfa5-4a75-8d06-05f95ed25536)' -Justification 'Daily elevation' -Hours 8

# Modules that must be imported into the global environment prior to importing this module
RequiredModules  = @('Az.Resources', 'Microsoft.Graph.DeviceManagement.Enrolment')

Install-Module JAz.Pim
Import-Module JAz.Pim
Connect-AzAccount -UseDeviceAuthentication
Enable-JAzRole <tab or shift-enter>
Disable-JAzRole <tab or shift-enter>

#Connect-MgGraph with an appropriate scope like 'RoleEligibilitySchedule.ReadWrite.Directory' or 'RoleManagement.ReadWrite.Directory'
Connect-MgGraph -Scopes 'RoleEligibilitySchedule.ReadWrite.Directory','RoleManagement.ReadWrite.Directory' -ContextScope Process -UseDeviceAuthentication

Get-JAzADRole

Enable-JAzADRole <tab or shift-enter>
Disable-JAzADRole <tab or shift-enter>

Enable-JAzADRole