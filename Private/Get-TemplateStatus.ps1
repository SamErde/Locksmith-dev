function Get-TemplateStatus {
    <#
        .SYNOPSIS
            Checks if a specific AD CS certificate template is published to Active Directory.

        .DESCRIPTION
            Get-TemplateStatus checks if a specific certificate certificate template is published in Active Directory or not.

        .PARAMETER TemplateName
            Specifies the name of the certificate template to check.

        .EXAMPLE
            Get-TemplateStatus -TemplateName "WebServer"

            Description
            -----------
            Checks if the "WebServer" certificate template is published to Active Directory.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$TemplateName
    )

    try {
        # This has not yet been tested.
        # "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADRootDSE).defaultNamingContext)"
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=msPKI-Enterprise-Oid)(cn=$TemplateName))"
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
        $searcher.SearchScope = "Subtree"
        $searcher.PropertiesToLoad.AddRange(@("cn", "msPKI-Cert-Template-OID"))

        $result = $searcher.FindOne()

        if ($result) {
            Write-Output "The '$TemplateName' certificate template is published to Active Directory."
        } else {
            Write-Output "The '$TemplateName' certificate template is not published to Active Directory."
        }
    } catch {
        Write-Error "An error occurred while checking the template status: $_"
    }
}
