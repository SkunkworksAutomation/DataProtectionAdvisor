<#
    THIS CODE REQUIRES POWWERSHELL 7.x.(latest)
    https://github.com/PowerShell/PowerShell/releases/tag/v7.3.0
#>

$global:AuthObject = $null

function new-authobject {
    [CmdletBinding()]
    param (
        [Parameter( Mandatory=$false)]
        [string]$Server
    )
    begin {
       
        # CHECK TO SEE IF CREDS FILE EXISTS IF NOT CREATE ONE
        $exists = Test-Path -Path ".\$($Server).xml" -PathType Leaf
        if($exists) {
            $admin = Import-CliXml ".\$($Server).xml"
        } else {
            $admin = Get-Credential -Message "Please specify your DPA credentials."
            $admin | Export-CliXml ".\$($Server).xml"
        }

        # BASE64 ENCODE USERNAME AND PASSWORD
        $password="$(ConvertFrom-SecureString -SecureString $admin.password -AsPlainText)"
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
            (
                "{0}:{1}" -f $admin.username,$password
            )
          )
        )
       
    }
    process {
       
        #BUILD THE AUTHOBJECT FOR SUBESEQUENT REST API CALLS
        $object = @{
            server ="https://$($Server):9002/dpa-api"
            token = @{Authorization=("Basic {0}" -f $base64AuthInfo)}
        } # END

        # SET THE AUTHOBJECT VALUES
        $global:AuthObject = $object
        $global:AuthObject | Format-List
    }
}

function get-alerts {
     [CmdletBinding()]
    param (
        [Parameter( Mandatory=$true)]
        [int]$PageSize,
        [Parameter( Mandatory=$true)]
        [int]$Page,
        [Parameter( Mandatory=$true)]
        [string]$Filter

    )
    begin {}
    process {
        $Results = @()

        # OMIT /MC_RETIRED AND /MC_SYSTEM DOMAINS
        $Query = Invoke-RestMethod `
        -Uri "$($AuthObject.server)/alert/alerts?page=$($Page)&pagesize=$($PageSize)&orderby=policy_A" `
        -Method POST `
        -ContentType 'application/vnd.emc.apollo-v1+xml' `
        -Headers ($AuthObject.token) `
        -Body $Filter `
        -SkipCertificateCheck
      
        # IF THE RESULTS ARE GREATER THAN 1 PAGE, GET ALL PAGED RESULTS
        [decimal]$NoPages = $Query.alerts.totalRecords /  $Query.alerts.pageSize
        if($NoPages -ge 1) {
            for($i=0;$i -lt $NoPages;$i++) {
                <#
                Write-Progress `
                -Activity "Processing pages..." `
                -Status "$($Page+$i) of $($NoPages) - $([math]::round((($i/$NoPages)*100),2))% " `
                -PercentComplete (($i/$NoPages)*100)
                #>
                $Pages = Invoke-RestMethod `
                -Uri "$($AuthObject.server)/alert/alerts?page=$($Page+$i)&pagesize=$($PageSize)&orderby=policy_A" `
                -Method POST `
                -ContentType 'application/vnd.emc.apollo-v1+xml' `
                -Headers ($AuthObject.token) `
                -Body $Filter `
                -SkipCertificateCheck
                $Results += $Pages.alerts.alert
            } # END FOR
        } else {
            $Results = $Query.alerts.alert
        }
       
        return $Results;
    } # END PROCESS
} # END FUNCTION

function new-policy {
    [CmdletBinding()]
   param (
    [Parameter( Mandatory=$true)]
    [string]$Path
   )
   begin {
    $exists = Test-Path -Path $Path -PathType Leaf
    if($exists) {
        $Policy = Get-Content -Path $Path
    } else {
        Write-Host "[Data Protection Advisor]: Policy template not in script directory!" -ForegroundColor Red
        exit;
    }
   }
   process {
    # OMIT /MC_RETIRED AND /MC_SYSTEM DOMAINS
    $Action = Invoke-RestMethod `
    -Uri "$($AuthObject.server)/ae-policy" `
    -Method POST `
    -ContentType 'application/vnd.emc.apollo-v1+xml' `
    -Headers ($AuthObject.token) `
    -Body $Policy `
    -SkipCertificateCheck
    return $Action
   } # END PROCESS
   
} # END FUNCTION