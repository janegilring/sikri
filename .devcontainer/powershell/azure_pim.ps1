Install-Module JaZ.PIM
Install-Module Microsoft.Graph.DeviceManagement.Enrolment

function pim {

Import-Module JaZ.PIM
Select-MgProfile 'Beta'

Connect-MgGraph -Scopes 'RoleEligibilitySchedule.ReadWrite.Directory','RoleManagement.ReadWrite.Directory' -ContextScope Process -UseDeviceAuthentication
Enable-JAzADRole 'Global Administrator (65e16447-3c6c-42ba-adec-7bb113c64d7b)' -Justification 'Daily elevation' -Hours 8

Connect-AzAccount -Tenant b716bd50-85d2-417b-8540-2a4d8d97f738 -UseDeviceAuthentication
Enable-JAzRole 'Owner -> IT (b33cf45a-bfa5-4a75-8d06-05f95ed25536)' -Justification 'Daily elevation' -Hours 8

}

pim

# Modules that must be imported into the global environment prior to importing this module
RequiredModules  = @('Az.Resources', 'Microsoft.Graph.DeviceManagement.Enrolment')

Install-Module JAz.Pim
Import-Module JAz.Pim
Connect-AzAccount -UseDeviceAuthentication
Enable-JAzRole <tab or shift-enter>
Disable-JAzRole <tab or shift-enter>

#Connect-MgGraph with an appropriate scope like 'RoleEligibilitySchedule.ReadWrite.Directory' or 'RoleManagement.ReadWrite.Directory'


Get-JAzADRole

Enable-JAzADRole <tab or shift-enter>
Disable-JAzADRole <tab or shift-enter>

Enable-JAzADRole

