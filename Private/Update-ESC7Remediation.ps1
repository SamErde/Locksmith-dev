function Update-ESC7Remediation {
    <#
    .SYNOPSIS
        This function asks the user a set of questions to provide the most appropriate remediation for ESC7 issues.

    .DESCRIPTION
        This function takes a single ESC7 issue as input. It then prompts the user if the principal with the ESC7 rights
        administers the Certification Authority (CA) in question.
        If the principal is an admin of the CA:
          - the Issue attribute is updated to indicate this configuration is expected
          - the Fix attribute for the issue is updated to indicate no remediation is needed
          - the Risk Value and Risk Scoring are set to
        If the the principal is not an admin of the CA,
        Depending on the answers to the listed questions, the Fix attribute is updated accordingly.

    .PARAMETER Issue
        A pscustomobject that includes all pertinent information about the ESC7 issue.

    .OUTPUTS
        This function updates ESC7 remediations customized to the user's needs.

    .EXAMPLE
        $Targets = Get-Target
        $ADCSObjects = Get-ADCSObject -Targets $Targets
        $DangerousRights = @('GenericAll', 'WriteProperty', 'WriteOwner', 'WriteDacl')
        $SafeOwners = '-512$|-519$|-544$|-18$|-517$|-500$'
        $SafeUsers = '-512$|-519$|-544$|-18$|-517$|-500$|-516$|-521$|-498$|-9$|-526$|-527$|S-1-5-10'
        $SafeObjectTypes = '0e10c968-78fb-11d2-90d4-00c04f79dc55|a05b8cc2-17bc-4802-a710-e7c15ab866a2'
        $ESC7Issues = Find-ESC7 -ADCSObjects $ADCSObjects -DangerousRights $DangerousRights -SafeOwners $SafeOwners -SafeUsers $SafeUsers -SafeObjectTypes $SafeObjectTypes -Mode 1
        foreach ($issue in $ESC7Issues) { Update-ESC7Remediation -Issue $Issue }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Issue
    )

    if ($Issue.Right -eq 'CA Administrator') {
        $Header = "`n[!] ESC7 Issue detected on $($Issue.Name)"
        Write-Host $Header -ForegroundColor Yellow
        Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
        Write-Host "$($Issue.IdentityReference) has CA Administrator rights on this Certification Authority (CA).`n"
        Write-Host 'To provide the most appropriate remediation for this issue, Locksmith will now ask you a few questions.'

        $Admin = ''
        do {
            $Admin = Read-Host "`n[?] Does $($Issue.IdentityReference) administer and/or maintain the $($Issue.Name) CA? [y/n]"
        } while ( ($Admin -ne 'y') -and ($Admin -ne 'n') )

        if ($Admin -eq 'y') {
            $Issue.Issue = @"
$($Issue.IdentityReference) has CA Administrator rights on this CA, but this is expected.

Note:
These rights grant $($Issue.IdentityReference) control of the forest.
This principal should be considered a Tier 0/control plane object and protected as such.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
            $Issue.Fix = "No immediate remediation required."
            $Issue | Add-Member -NotePropertyName RiskValue -NotePropertyValue 0 -Force
            $Issue | Add-Member -NotePropertyName RiskName -NotePropertyValue 'Informational' -Force
            $Issue | Add-Member -NotePropertyName RiskScoring -NotePropertyValue "$($Issue.IdentityReference) administers this CA" -Force
        }
    }

    if ($Issue.Right -eq 'Certificate Manager') {
        $Header = "`n[!] ESC7 Issue detected on $($Issue.Name)"
        Write-Host $Header -ForegroundColor Yellow
        Write-Host $('-' * $Header.Length) -ForegroundColor Yellow
        Write-Host "$($Issue.IdentityReference) has Certificate Manager rights on this Certification Authority (CA).`n"
        Write-Host 'To provide the most appropriate remediation for this issue, Locksmith will now ask you a few questions.'

        $Admin = ''
        do {
            $Admin = Read-Host "`n[?] Does $($Issue.IdentityReference) need to approve pending certificate requests on the $($Issue.Name) CA? [y/n]"
        } while ( ($Admin -ne 'y') -and ($Admin -ne 'n') )

        if ($Admin -eq 'y') {
            $Issue.Issue = @"
$($Issue.IdentityReference) has Certificate Manager rights on this CA, but this is expected.

More info:
  - https://posts.specterops.io/certified-pre-owned-d95910965cd2

"@
            $Issue.Fix = "No immediate remediation required."
            $Issue | Add-Member -NotePropertyName RiskValue -NotePropertyValue 0 -Force
            $Issue | Add-Member -NotePropertyName RiskName -NotePropertyValue 'Informational' -Force
            $Issue | Add-Member -NotePropertyName RiskScoring -NotePropertyValue "$($Issue.IdentityReference) approves pending certificate requests on this CA" -Force
        }
    }
}
