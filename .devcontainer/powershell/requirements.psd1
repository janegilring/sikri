@{
    PSDependOptions                         = @{
        Target     = 'AllUsers'
        Parameters = @{
            Repository      = 'PSGallery'
            AllowPrerelease = $false
        }
    }
    'Az.Accounts'                           = '2.2.8'
    'Az.Aks'                                = '2.1.0'
    'Az.Compute'                            = '4.12.0'
    'Az.Storage'                            = '3.6.0'
    'Az.Resources'                          = '3.5.0'
    'Az.Functions'                          = '2.0.0'
    'Microsoft.PowerShell.SecretManagement' = 'latest'
    'Microsoft.PowerShell.SecretStore'      = 'latest'
    'Microsoft.PowerShell.UnixCompleters'   = 'latest'
    'Microsoft.PowerShell.ConsoleGuiTools'  = 'latest'
    'oh-my-posh'                            = 'latest'
    'tftools'                               = 'latest'
}