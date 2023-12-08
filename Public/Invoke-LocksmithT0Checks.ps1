function Invoke-LocksmithT0Checks {
<#
    .SYNOPSIS
        ADCS checks that require elevated (tier-0) privileged roles.

    .DESCRIPTION
        This base function could probably be rolled into Invoke-Locksmith
        and the following functions broken into separate private functions.
#>
}

function Get-StrongCertificateBindingEnforcement {
    <#
    .SYNOPSIS
    This script checks all domain controllers in a forest for the value of StrongCertificateBindingEnforcement.

    .DESCRIPTION
    The script retrieves all domain controllers in the Active Directory forest and checks the data in the
    StrongCertificateBindingEnforcement value. This is an important protection against ESC9 and ESC10 abuses.

    .PARAMETER None
    This script does not take any parameters.

    .EXAMPLE
    Get-CheckStrongCertificateBindingEnforcement

    This command runs the script and outputs the value of StrongCertificateBindingEnforcement for each domain
    controller in the forest.

    .NOTES
    Permissions required: one (or more) of the following:
      - local admin on domain controllers (Domain Admin) - basically just this
      - server administrator on domain controllers
      - (?) remote registry on domain controllers + connect to this computer from the network
    #>

    Import-Module ActiveDirectory

    $DomainControllers = Get-ADDomainController -Filter *

    foreach ($dc in $DomainControllers) {
        # Establish a remote session
        $Session = New-PSSession -ComputerName $dc.HostName

        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc"

        # Check if the path exists
        if (Test-Path -Path $path) {
            # Get the value of StrongCertificateBindingEnforcement
            $value = Invoke-Command -Session $session -ScriptBlock {

                # What is "using"? Scope? Bing hallucinating?
                Get-ItemProperty -Path $using:path -Name "StrongCertificateBindingEnforcement"
            }

            Write-Output "Domain Controller: $($dc.HostName), StrongCertificateBindingEnforcement: $($value.StrongCertificateBindingEnforcement)"
        }
        else {
            Write-Output "Domain Controller: $($dc.HostName), StrongCertificateBindingEnforcement: Key not found"
        }

        Remove-PSSession -Session $session
    }
}

function Get-UsersWithAltSecurityIdentities {
    <#
    .SYNOPSIS
        Get all  Active Directory users that have a value in altSecurityIdentities

    .NOTES
        Could this be useful?

        Not a highly privileged query.
        Permissions Required: Read permissions on user accounts
    #>

    Import-Module ActiveDirectory

    # Get all users where altSecurityIdentities is not null or not empty
    $UsersWithAltSecurityIdentities = Get-ADUser -LDAPFilter "(altSecurityIdentities=*)" -Properties altSecurityIdentities

    foreach ($user in $UsersWithAltSecurityIdentities) {
        # Output the user and altSecurityIdentities
        Write-Output "User: $($user.SamAccountName), altSecurityIdentities: $($user.altSecurityIdentities)"
    }
}
