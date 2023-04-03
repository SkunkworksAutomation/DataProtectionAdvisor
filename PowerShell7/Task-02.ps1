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

# VARS
$dpa = 'dpa-01.vcorp.local'
$page = 1
$pagesize = 100
$policy = 'Cyber Threat Anomaly Detection'
$report = @()
$file = 'alerts.csv'

# GENERAL FILTER ALL ALERTS        
$filter = @"
       <alertsFilter sortBy="lastUpdated" sortOrder="Descending">
        <type>Advanced</type>
       </alertsFilter>
"@

<#

# CONDITIONAL FILTER FOR CYBER THREAT ANOMALY DETECTION
# name = Cyber Threat Anomaly Detection
# state = new
# severity = Error

$filter = @"
<alertsFilter sortBy="policy" sortOrder="Ascending">
<name>Cyber Threat Filter</name>
<userId>46c9a9d5-a645-4dcb-b288-3d30ff930ad7</userId>
<type>Advanced</type>
<rootFilterEntity type="CompoundCondition"><leftSide type="CompoundCondition">
    <leftSide type="ScalarCondition">
    <field>policy</field>
    <operand>IS</operand>
    <value>$($policy)</value>
    </leftSide>
    <logicalOperator>AND</logicalOperator>
    <rightSide type="ScalarCondition">
    <field>state</field>
    <operand>IS</operand>
    <value>New</value>
    </rightSide>
    </leftSide><logicalOperator>AND</logicalOperator>
    <rightSide type="ScalarCondition">
    <field>severity</field>
    <operand>IS</operand>
    <value>Error</value>
    </rightSide>
    </rootFilterEntity>
</alertsFilter>
"@

#>

# CREATE THE AUTH OBJECT
new-authobject -Server $dpa

# GATHER THE ALERTS
$alerts = get-alerts -Page $page -PageSize $pagesize -Filter $filter

# BUILD THE RESULTS
$alerts | ForEach-Object {
    $object = [ordered]@{
        id = $_.id
        link = $_.link.href
        parent = $_.parentObject.name
        child = $_.childObject.name
        policy = $_.policy.name
        issued = [datetime]$_.issued
        lastUpdated = [datetime]$_.lastUpdated
        severity = $_.severity
        category = $_.category
        state = $_.state
        message = $_.message
        description = $_.description
        count = $_.count
    }
    $report += New-Object -TypeName pscustomobject -Property $object
}


$exists = Test-Path -Path ".\$($file)" -PathType Leaf                                                             
if($exists) {
    # IMPORT THE CSV FILE
    $csv = Import-Csv ".\$($file)" | Sort-Object {[datetime]$_.issued} | Select-Object -Last 1
    if($csv.count -gt 0) {
        foreach($row in $report) {
            if([datetime]$row.issued -gt [datetime]$csv.issued) {
                # APPEND NEW RECORDS
                $row | Export-Csv ".\$($file)" -Append -NoTypeInformation
            }
        }
    } else {
        # WRITE ALL OF THE ALERTS TO A NEW FILE
        $report | Sort-Object {[datetime]$_.issued} | Export-Csv ".\$($file)" -NoTypeInformation
    }
    
} else {
    # WRITE ALL OF THE ALERTS TO A NEW FILE
    $report | Sort-Object {[datetime]$_.issued} | Export-Csv ".\$($file)" -NoTypeInformation
}


# DISPLAY REPORT IN CONSOLE
$report | Format-List
# GET THE SIZE OF THE REPORT
$report.length