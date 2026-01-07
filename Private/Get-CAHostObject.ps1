function Get-CAHostObject {
    <#
    .SYNOPSIS
        Retrieves Certificate Authority (CA) host object(s) from Active Directory.

    .DESCRIPTION
        This script retrieves CA host object(s) associated with every CA configured in the target Active Directory forest.
        If a Credential is provided, the script retrieves the CA host object(s) using the specified credentials.
        If no Credential is provided, the script retrieves the CA host object(s) using the current credentials.

    .PARAMETER ADCSObjects
        Specifies an array of AD CS objects to retrieve the CA host object for.

    .PARAMETER Credential
        Specifies the credentials to use for retrieving the CA host object(s). If not provided, current credentials will be used.

    .EXAMPLE
        $ADCSObjects = Get-ADCSObjects
        $Credential = Get-Credential
        Get-CAHostObject -ADCSObjects $ADCSObjects -Credential $Credential

        This example retrieves the CA host object(s) associated with every CA in the target forest using the provided credentials.

    .INPUTS
        System.Array

    .OUTPUTS
        System.Object

    #>
    [CmdletBinding()]
    param (
        [parameter(
            Mandatory,
            ValueFromPipeline = $true)]
        [Microsoft.ActiveDirectory.Management.ADEntity[]]$ADCSObjects,
        [System.Management.Automation.PSCredential]$Credential,
        $ForestGC
    )
    process {
        if ($Credential) {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                if ($_.CAHostDistinguishedName) { Get-ADObject $_.CAHostDistinguishedName -Properties * -Server $ForestGC -Credential $Credential } else { Write-Warning "Get-CAHostObject: Unable to get information from $($_.DisplayName)" }
            }
        } else {
            $ADCSObjects | Where-Object objectClass -Match 'pKIEnrollmentService' | ForEach-Object {
                if ($_.CAHostDistinguishedName) { Get-ADObject -Identity $_.CAHostDistinguishedName -Properties * -Server $ForestGC } else { Write-Warning "Get-CAHostObject: Unable to get information from $($_.DisplayName)" }
            }
        }
    }
}
