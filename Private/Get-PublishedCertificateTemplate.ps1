function Get-PublishedCertificateTemplate {
    <#
        .SYNOPSIS
            Lists published certificate templates in Active Directory.

        .DESCRIPTION
            This function uses ADSISearcher to query Active Directory for all published certificate templates.

        .EXAMPLE
            Get-PublishedCertificateTemplate # Specify DC or naming context
            Lists all published certificate templates in the specified Active Directory context.

        .EXAMPLE
            Get-PublishedCertificateTemplate
            Lists all published certificate templates in the current Active Directory domain.

        .NOTES
            Can I simplify the searcher below by checking the templates container directly? Will that show which CA
            each template is published to?
            "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$((Get-ADRootDSE).defaultNamingContext)"
    #>

    [CmdletBinding()]
    param (
        # The name of a specific certificate authority to check for published certificate templates.
        # If not specified, all CAs will be included.
        [Parameter()]
        [string]$Server,

        # The name of a specific certificate template to check for publication.
        # If not specified, all templates will be returned.
        [Parameter()]
        [string]$TemplateName

        # Need to test and determine if forest or domain parameters are needed.
        # The searcher should be able to find the templates in the current domain.
    )

    try {
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher
        $EnrollmentServicesPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,"+[string](New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")).ConfigurationNamingContext
        $Searcher.SearchRoot = $EnrollmentServicesPath
        $Searcher.Filter = "(&(objectClass=pKIEnrollmentService))"
        $Searcher.SearchScope = "Subtree"
        #$searcher.PropertiesToLoad.AddRange(@("displayName", "cn"))

        <#
            $ConfigurationNamingContext = (New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")).configurationNamingContext
            $Searcher.SearchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,"+$($ConfigurationNamingContext)
        #>

        $Results = $searcher.FindAll()

        <#
        foreach ($result in $Results) {
            $TemplateName = $result.Properties["displayName"][0]
            $TemplateCN = $result.Properties["cn"][0]
            Write-Output "$TemplateName ($TemplateCN)"
        }
        #>

        [string[]]$CertificateTemplates = @()
        foreach ($EnrollmentService in $Results) {
            $CAName = $EnrollmentService.Properties["displayname"]
            foreach ($template in $EnrollmentService.Properties["certificatetemplates"]) {
                $CertificateTemplates += $template
            }
            $CAName
            $CertificateTemplates
        }
    }
    catch {
        Write-Error "An error occurred while retrieving the published certificate templates: $_"
    }

    # Get all published certificate templates using the Get-ADObject cmdlet from the ActiveDirectory PowerShell module.
    # Wait, shouldn't there be a template class I can directly search for?
    Get-ADObject -Filter {ObjectClass -eq "pKIEnrollmentService"} -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com" -Properties certificateTemplates
}
