function Find-AuditingGPO {
    # WIP
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$CAHosts
    )
    # Find GPOs that are applied to certificate authority computer objects
    # Pass target CAs and credentials. Handle multiple domains.
    $GpoNames = @()

    foreach ($item in $CAHosts) {
        # For each CA, check all GPOs for CA auditing settings
        # Keep a count of any found and pass if >0, fail if <1

        if (($CAHosts) -and ($CAHosts.Length -gt 0)) {
            $ComputerName = $item.dnsHostName
        }
        else {
            $ComputerName = [System.Net.Dns]::GetHostName()
        }
        $RsopPath = "$($executioncontext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\'))\RSOP_$ComputerName.xml"
        $RsopParams = @{
            ReportType = 'xml'
            Path = "$RsopPath"
            Computer = $ComputerName
        }
        Write-Output $ComputerName
        Get-GPResultantSetOfPolicy @RsopParams -Verbose
        [xml]$RsopXml = Get-Content -Path $RsopPath
        $GpoNames += $RsopXml.Rsop.ComputerResults.GPO.Name

        $GpoNames | ForEach-Object {
            if (
                Get-GPRegistryValue -Name $_ -Key 'HKLM\SOFTWARE\Policies\Microsoft\Cryptography\OID\EncodingType 0\CertDllCreateCertificateChainEngine\Configurations' -ValueName 'EnableCertSrvAudit' -ErrorAction SilentlyContinue
            ) {
                Write-Output "Eureka, I found it in $_!"
            }
            else {
                Write-Output "The key was not found in $_."
            }
        }
    }
} # End function Find-AuditingGPOs
