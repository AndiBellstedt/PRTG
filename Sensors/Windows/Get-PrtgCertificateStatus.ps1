<#
    .SYNOPSIS
        PRTG Advanced Sensor - Windows check system certificates

    .DESCRIPTION
        Advanced Sensor will query certificates stored in machine account and report expiring certificates in a give days of time

    .PARAMETER Computername
        Name of Server to be queried

    .PARAMETER DaysToExpireWarning
        Amount of days when sensor goes on warning status
        default is 30

    .PARAMETER DaysToExpireError
        Amount of days when sensor goes on error status
        Standard 21

    .PARAMETER Exclude
        Thumbsprint(s) to exclude

    .PARAMETER Credential
        Credential to connect to remote system and/or Veeam B&R Service

    .EXAMPLE
        PS C:\> Get-PrtgCertificateStatus.ps1 -ComputerName srv01.corp.customer.com

        Get all certificates from server 'srv01.corp.customer.com' and report every certificate expiring / explired

    .EXAMPLE
        PS C:\> Get-PrtgCertificateStatus.ps1 -ComputerName srv01.corp.customer.com -DaysToExpireWarning 40 -DaysToExpireError 30 -ExcludeCertificateThumb "010123234A4ABBCECEFF"

        Get all certificates from server 'srv01.corp.customer.com' and report every certificate expiring / explired with customized warning and error limits
        Existing certificate with thumbprint "010123234A4ABBCECEFF" will be ignored in the query

    .NOTES
        Get-PrtgCertificateStatus
        Author: Andreas Bellstedt
        LASTEDIT: 2023/01/01
        VERSION:  1.0.1
        KEYWORDS: PRTG, Windows, Certificates

    .LINK
        https://github.com/AndiBellstedt/PRTG


#>
#Requires -Version 5
[CmdletBinding(
    PositionalBinding = $true,
    ConfirmImpact = "Low"
)]
Param (
    [ValidateNotNullOrEmpty()]
    [Alias("Server")]
    [string]
    $ComputerName = (.{ if ($env:prtg_host) { $env:prtg_host } else { $env:COMPUTERNAME } }),

    [ValidateNotNullOrEmpty()]
    [int]
    $DaysToExpireWarning = 30,

    [ValidateNotNullOrEmpty()]
    [int]
    $DaysToExpireError = 21,

    [ValidateNotNullOrEmpty()]
    [string[]]
    $ExcludeCertificate,

    [pscredential]
    $Credential = (.{ if ($env:prtg_windowsuser -and $env:prtg_windowspassword) { [pscredential]::new( "$(if($env:prtg_windowsdomain){ "$($env:prtg_windowsdomain)\"})$($env:prtg_windowsuser)", $("$($env:prtg_windowspassword)" | ConvertTo-SecureString -AsPlainText -Force)) } })

)



#region Helper functions
trap {
    # Catch all unhadled errors and close Pssession to avoid this issue:
    # Thanks for https://github.com/klmj for the idea
    # http://www.checkyourlogs.net/?p=54583

    #Disconnect-VBRServer -ErrorAction SilentlyContinue
    if ($RemoteSession) { Remove-PSSession -Session $RemoteSession }

    Write-Output "<prtg>"
    Write-Output " <error>1</error>"
    Write-Output " <text>$($_.ToString())</text>"
    Write-Output "</prtg>"

    exit 1
}

function Out-PrtgChannel {
    Param (
        [Parameter(Position = 0, mandatory = $True)]
        [string]
        $Channel,

        [Parameter(Position = 1, mandatory = $True)]
        $Value,

        [Parameter(Position = 2)]
        [string]
        $Unit,

        [alias('mw')]
        [string]
        $MaxWarn,

        [alias('minw')]
        [string]
        $MinWarn,

        [alias('me')]
        [string]
        $MaxError,

        [alias('mine')]
        [string]
        $MinError,

        [alias('wm')]
        [string]
        $WarnMsg,

        [alias('em')]
        [string]
        $ErrorMsg,

        [alias('mo')]
        [ValidateSet("Absolute", "Difference")]
        [string]
        $Mode,

        [alias('sc')]
        [switch]
        $ShowChart,

        [alias('st')]
        [switch]
        $ShowTable,

        [alias('ss')]
        [ValidateSet("One", "Kilo", "Mega", "Giga", "Tera", "Byte", "KiloByte", "MegaByte", "GigaByte", "TeraByte", "Bit", "KiloBit", "MegaBit", "GigaBit", "TeraBit")]
        [string]
        $SpeedSize,

        [ValidateSet("One", "Kilo", "Mega", "Giga", "Tera", "Byte", "KiloByte", "MegaByte", "GigaByte", "TeraByte", "Bit", "KiloBit", "MegaBit", "GigaBit", "TeraBit")]
        [string]
        $VolumeSize,

        [alias('fl')]
        [bool]
        $Float,

        [alias('dm')]
        [string]
        $DecimalMode,

        [alias('w')]
        [switch]
        $Warning,

        [string]
        $ValueLookup
    )

    # variables
    $StandardUnits = @("BytesBandwidth", "BytesMemory", "BytesDisk", "Temperature", "Percent", "TimeResponse", "TimeSeconds", "Custom", "Count", "CPU", "BytesFile", "SpeedDisk", "SpeedNet", "TimeHours")
    $LimitMode = $false

    # build result
    $Result = "  <result>`n"
    $Result += "    <channel>$Channel</channel>`n"
    $Result += "    <value>$Value</value>`n"

    if ($StandardUnits -contains $Unit) {
        $Result += "    <unit>$Unit</unit>`n"
    } elseif ($Unit) {
        $Result += "    <unit>custom</unit>`n"
        $Result += "    <customunit>$Unit</customunit>`n"
    }

    #if (!($Value -is [int])) { $Result += "    <float>1</float>`n" }
    if ($Mode) { $Result += "    <mode>$Mode</mode>`n" }
    if ($MaxWarn) { $Result += "    <limitmaxwarning>$MaxWarn</limitmaxwarning>`n"; $LimitMode = $true }
    if ($MinWarn) { $Result += "    <limitminwarning>$MinWarn</limitminwarning>`n"; $LimitMode = $true }
    if ($MaxError) { $Result += "    <limitmaxerror>$MaxError</limitmaxerror>`n"; $LimitMode = $true }
    if ($MinError) { $Result += "    <limitminerror>$MinError</limitminerror>`n"; $LimitMode = $true }
    if ($WarnMsg) { $Result += "    <limitwarningmsg>$WarnMsg</limitwarningmsg>`n"; $LimitMode = $true }
    if ($ErrorMsg) { $Result += "    <limiterrormsg>$ErrorMsg</limiterrormsg>`n"; $LimitMode = $true }
    if ($LimitMode) { $Result += "    <limitmode>1</limitmode>`n" }
    if ($SpeedSize) { $Result += "    <speedsize>$SpeedSize</speedsize>`n" }
    if ($VolumeSize) { $Result += "    <volumesize>$VolumeSize</volumesize>`n" }
    if ($Float -eq $true) { $Result += "    <float>1</float>`n" } elseif ($Float -eq $false) { $Result += "    <float>0</float>`n" }
    if ($DecimalMode) { $Result += "    <decimalmode>$DecimalMode</decimalmode>`n" }
    if ($Warning) { $Result += "    <warning>1</warning>`n" }
    if ($ValueLookup) { $Result += "    <ValueLookup>$ValueLookup</ValueLookup>`n" }
    if ($ShowChart) { $Result += "    <showchart>1</showchart>`n" } else { $Result += "    <showchart>0</showchart>`n" }
    if ($ShowTable) { $Result += "    <showTable>1</showTable>`n" } else { $Result += "    <showTable>0</showTable>`n" }
    $Result += "  </result>`n"

    $Result
}
#endregion Helper functions



#region Variables and Prereqs
[array]$result = ""
$MsgText = ""
$PrtgWarning = ""
$PrtgError = ""
$PrtgExpired = ""
$PrtgWarningCount = 0
$PrtgErrorCount = 0
$PrtgExpiredCount = 0

$scriptBlock = {
    Get-ChildItem "Cert:\LocalMachine\my" -ErrorAction Stop | Where-Object { $_.Archived -ne $true }
}
[array]$certificateList = @()
#endregion Variables and Prereqs



#region Script

# Query base info
Write-Verbose "Getting certificates from $($ComputerName)"
if (($ComputerName -like $env:ComputerName) -and (-not $Credential)) {
    $certificateList = . $scriptBlock
} else {
    $param = @{
        "ComputerName" = $ComputerName
        "ErrorAction" =  "Stop"
        "ScriptBlock" = $scriptBlock
    }
    if($Credential) { $param.Add("Credential", $Credential) }
    $certificateList = Invoke-Command @param
}

# Filter
Write-Verbose "Filter excluded certificates"
if ($ExcludeCertificate -and $certificateList) {
    $filterResult = ""
    $filterResult = foreach ($filterItem in $ExcludeCertificate) {
        $certificateList | Where-Object Thumbprint -ne $filterItem
    }
    $certificateList = $filterResult | Sort-Object Thumbprint -Unique
}

Write-Verbose "Count certificates in warning and error range, fill `$MsgText"
foreach ($cert in $certificateList) {
    if ($cert.notAfter -le ([datetime]::Today)) {

        $PrtgExpiredCount++
        $PrtgExpired += "Thumb=$($cert.Thumbprint) ($($cert.Subject.trim()) $(($cert.FriendlyName).trim()))"

    } elseif ($cert.notAfter -le (([datetime]::Today).Date.AddDays($DaysToExpireError))) {

        $PrtgErrorCount++
        $PrtgError += "Thumb=$($cert.Thumbprint) ($($cert.Subject.trim()) $(($cert.FriendlyName).trim()))"

    } elseif ($cert.notAfter -le (([datetime]::Today).Date.AddDays($DaysToExpireWarning))) {

        $PrtgWarningCount++
        $PrtgWarning += "Thumb=$($cert.Thumbprint) ($($cert.Subject.trim()) $(($cert.FriendlyName).trim()))"

    }
}

# Setting $MsgText
if ($certificateList) {
    if ($PrtgWarningCount -gt 0) { $MsgText += "$($PrtgWarningCount) Warning$(if($PrtgWarningCount -gt 1){'s'}): $([string]::Join(", ", $PrtgWarning))" }
    if ($PrtgErrorCount -gt 0) { $MsgText += "$($PrtgErrorCount) Error$(if($PrtgErrorCount -gt 1){'s'}): $([string]::Join(", ", $PrtgError))" }
    if ($PrtgExpiredCount -gt 0) { $MsgText += "$($PrtgExpiredCount) Expired: $([string]::Join(", ", $PrtgExpired))" }
    if (($PrtgWarningCount + $PrtgErrorCount + $PrtgExpiredCount) -eq 0) { $MsgText = "Ok, no expired certificates found." }
} else {
    $MsgText = "Ok, no active certificates found."
}

# Build PRTG result
Write-Verbose "Creating XML output for PRTG"
$result += '<prtg>'

# Number of all (active) certificates
$result += Out-PrtgChannel -Channel "Overall number of certificates" -Value ([array]$certificateList).Count -Unit Count -ShowTable

# Number of certificates that will expired in $DaysToExpireWarning days. Raise an warning
$result += Out-PrtgChannel -Channel "Expiring in $($DaysToExpireWarning) days" -Value $PrtgWarningCount -Unit Count -ShowChart -ShowTable -MaxWarn 0.5 -WarnMsg "The following certificates will exipre:"

# Number of certificates which will expired in the next $DaysToExpireError days. Raise an error
$result += Out-PrtgChannel -Channel "Expiring in $($DaysToExpireError) days" -Value $PrtgErrorCount -Unit Count -ShowChart -ShowTable -MaxError 0.5 -ErrorMsg "The following certificates will exipre:"

# Number of certificates which are expired and raises an error, if one or more Certificates fit the criterion.
$result += Out-PrtgChannel -Channel "Expired already" -Value $PrtgExpiredCount -Unit Count -ShowChart -ShowTable -MaxError 0.5 -ErrorMsg "The following certificates are already expired:"

$result += "<text>" + $MsgText + "</text>"
$result += "</prtg>"

# Output PRTG result
$result

#endregion