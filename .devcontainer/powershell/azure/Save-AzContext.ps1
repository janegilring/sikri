# Example on how to persist credentials for Azure PowerShell in a dev container

# After starting the container

Connect-AzAccount -UseDeviceAuthentication -Tenant b716bd50-85d2-417b-8540-2a4d8d97f738

Set-AzContext "AI" -Tenant b716bd50-85d2-417b-8540-2a4d8d97f738
Set-AzContext "Sikri AI Dev" -Tenant b716bd50-85d2-417b-8540-2a4d8d97f738

Set-AzContext Management

# credentials.azure.json is added to .gitignore
Save-AzContext -Path /workspaces/sikri/.devcontainer/powershell/azure/credentials.azure.json

# After restarting the container

Get-AzContext

Import-AzContext -Path /workspaces/sikri/.devcontainer/powershell/azure/credentials.azure.json

Get-AzContext

Get-AzContextAutosaveSetting
Disable-AzContextAutosave
Enable-AzContextAutosave -Scope CurrentUser

Clear-AzContext

dir /home/vscode/.IdentityService

# An alternative approach is to mount a folder from the host machine
# "mounts": ["source=${localEnv:USERPROFILE}//OneDrive//Kunder//Sikri//devcontainer/.azure,target=/home/vscode/.azure,type=bind,consistency=cached"],