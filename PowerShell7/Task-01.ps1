<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/PowerShell/releases/tag/v7.3.3
#>

Import-Module .\dell.dpa.psm1 -Force

<#
    CREATE AN ANALYSIS POLICY
    NAME:
        Cyber Threat Anomaly Detection
    TEMPLATE:
        .\Task-01-AnalysisPolicyTemplate.xml
#>
$dpa = 'dpa-01.vcorp.local'

new-authobject -Server $dpa

#CREATE THE CYBER THREAT ANALiSYS POLICY
$policy = new-policy -Path '.\Task-01-AnalysisPolicyTemplate.xml'

$policy.aePolicy | Format-List