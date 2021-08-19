@{
    PSDependOptions                         = @{
        Target     = 'AllUsers'
        Parameters = @{
            Repository      = 'PSGallery'
            AllowPrerelease = $false
        }
    }
    'Az.Accounts'                           = '2.5.2'
    'Az.Aks'                                = '2.3.0'
    'Az.ContainerInstance'                  = '2.1.0'
    'Az.ContainerRegistry'                  = '2.2.3'
    'Az.Compute'                            = '4.16.0'
    'Az.KeyVault'                           = '3.4.4'
    'Az.Storage'                            = '3.10.0'
    'Az.Resources'                          = '4.3.0'
    'Az.Functions'                          = '3.1.0'
    'Az.Network'                            = '4.10.0'
    'Az.Monitor'                            = '2.7.0'
    'Microsoft.PowerShell.SecretManagement' = 'latest'
    'Microsoft.PowerShell.SecretStore'      = 'latest'
    'Microsoft.PowerShell.UnixCompleters'   = 'latest'
    'Microsoft.PowerShell.ConsoleGuiTools'  = 'latest'
    'subnet'                                = 'latest'
    'Terminal-Icons'                        = 'latest'
    'tftools'                               = 'latest'
}