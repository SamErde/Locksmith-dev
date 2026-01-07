function Update-ESC9Remediation {
    <#
    .SYNOPSIS
        This function asks the user a set of questions to provide the most appropriate remediation for ESC9 issues.

    .DESCRIPTION
        This function takes a single ESC9 issue as input then asks a series of questions to determine the correct
        remediation.

        Questions:
        1. Does the identified principal need to enroll in this template? [Yes/No/Unsure]
        2. Is this certificate widely used and/or frequently requested? [Yes/No/Unsure]

        Depending on answers to these questions, the Issue and Fix attributes on the Issue object are updated.

        TODO: More questions:
        Should the identified principal be able to request certs that include a SAN or SANs?

    .PARAMETER Issue
        A pscustomobject that includes all pertinent information about the ESC1 issue.

    .OUTPUTS
        This function updates ESC9 remediations customized to the user's needs.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $ESC9Issues = Find-ESC9 -ADCSObjects $ADCSObjects -SafeUsers $SafeUsers
        foreach ($issue in $ESC9Issues) { Update-ESC9Remediation -Issue $Issue }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Issue
    )

    $Header = "`n[!] ESC9 Issue detected in $($Issue.Name)"
    Write-Host $Header -ForegroundColor Yellow
    Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
    Write-Host @"
The $($Issue.Name) template has the szOID_NTDS_CA_SECURITY_EXT security extension
disabled. Certificates issued from this template will not enforce strong
certificate binding. Manager approval is not required for a certificate to be issued.
To provide the most appropriate remediation for this issue, Locksmith will now
ask you a few questions.
"@

    $Enroll = ''
    do {
        $Enroll = Read-Host "`n[?] Does $($Issue.IdentityReference) need to Enroll in the $($Issue.Name) template? [y/n/unsure]"
    } while ( ($Enroll -ne 'y') -and ($Enroll -ne 'n') -and ($Enroll -ne 'unsure'))

    if ($Enroll -eq 'y') {
        $Frequent = ''
        do {
            $Frequent = Read-Host "`n[?] Is the $($Issue.Name) certificate frequently requested? [y/n/unsure]"
        } while ( ($Frequent -ne 'y') -and ($Frequent -ne 'n') -and ($Frequent -ne 'unsure'))

        if ($Frequent -ne 'n') {
            $Issue.Fix = @"
# Locksmith cannot currently determine the best remediation course.
# Remediation Options:
# 1. If $($Issue.IdentityReference) is a group, remove its Enroll/AutoEnroll rights and grant those rights
#   to a smaller group or a single user/service account.

# 2. Enable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 2}

# 3. Enable the szOID_NTDS_CA_SECURITY_EXT security extension.
TODO
"@

            $Issue.Revert = @"
# 1. Replace Enroll/AutoEnroll rights from the smaller group/single user/service account and grant those rights
#   back to $($Issue.IdentityReference).

# 2. Disable Manager Approval
`$Object = '$($_.DistinguishedName)'
Get-ADObject `$Object | Set-ADObject -Replace @{'msPKI-Enrollment-Flag' = 0}

# 3. Disable the szOID_NTDS_CA_SECURITY_EXT security extension.
TODO
"@
        }
    } elseif ($Enroll -eq 'n') {
        $Issue.Fix = @"
<#
    1. Open the Certification Templates Console: certtmpl.msc
    2. Double-click the $($Issue.Name) template to open its Properties page.
    3. Select the Security tab.
    4. Select the entry for $($Issue.IdentityReference).
    5. Uncheck the "Enroll" and/or "Autoenroll" boxes.
    6. Click OK.
#>
"@

        $Issue.Revert = @"
<#
    1. Open the Certification Templates Console: certtmpl.msc
    2. Double-click the $($Issue.Name) template to open its Properties page.
    3. Select the Security tab.
    4. Select the entry for $($Issue.IdentityReference).
    5. Check the "Enroll" and/or "Autoenroll" boxes depending on your specific needs.
    6. Click OK.
#>
"@
    } # end if ($Enroll -eq 'y')/elseif ($Enroll -eq 'n')
}
