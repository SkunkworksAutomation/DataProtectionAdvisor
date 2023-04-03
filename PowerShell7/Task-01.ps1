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
        .\Template-AnalysisPolicy.xml
#>
$dpa = 'dpa-01.vcorp.local'

new-authobject -Server $dpa

#CREATE THE CYBER THREAT ANALiSYS POLICY
$policy = new-policy -Path .\Template-AnalysisPolicy.xml

$policy.aePolicy | Format-List