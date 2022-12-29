<#
    .SYNOPSIS
        PRTG Advanced Sensor - Exchange Server (Onpremises) - Mobile device types

    .DESCRIPTION
        Advanced Sensor will report device types registerd in exchange services

        Requirements:
        - HTTP (TCP Port 80) to exchange server specified in $ComputerName
        - priviledged (admin) account connecting to exchange backend

    .PARAMETER ComputerName
        Name of Server

    .PARAMETER Credential
        Credential to connect to remote system

    .EXAMPLE
        PS C:\> Get-PrtgExchange2016MobileDeviceTypes.ps1 -ComputerName ex01.corp.customer.com

        Get all mobile devices from organization while connected to server 'ex01.corp.customer.com' and report count per status

    .EXAMPLE
        PS C:\> Get-PrtgExchange2016MobileDeviceTypes.ps1 -ComputerName ex01.corp.customer.com -Credential $Cred

        Get all mobile devices from organization while connected to server 'ex01.corp.customer.com' and report count per status
        Connection to exchange will be done with credentials '$Cred'.

    .Notes
        Get-PrtgExchange2016MobileDeviceTypes
        Author: Andreas Bellstedt
        LASTEDIT: 2022/12/29
        VERSION:  1.0.1
        KEYWORDS: PRTG, Exchange, OnPremise, ActiveSync, MobileDevices, DeviceTypes

    .LINK
        https://github.com/AndiBellstedt/PRTG
#>
#Requires -Version 5
[cmdletbinding(
    ConfirmImpact = "Low",
    PositionalBinding = $true
)]
param(
    [Alias("Server")]
    [string]
    $ComputerName = (.{ if ($env:prtg_host) { $env:prtg_host } else { $env:COMPUTERNAME } }),

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

# Connection to Exchange service
$paramsExchange = @{
    "ConfigurationName" = "Microsoft.Exchange"
    "ConnectionUri"     = "http://$($ComputerName)/PowerShell"
    "ErrorAction"       = "Continue"
}
if ($Credential) { $paramsExchange.Add("Credential", $Credential) }

$exSession = New-PSSession @paramsExchange
if (-not $exSession) { throw "Cannot open remote session to '$($ComputerName)' with user '$($username)'" }
Import-PSSession -Session $exSession -CommandName "Set-AdServerSettings", "Get-MobileDevice", "Get-ActiveSyncDevice" -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null

#endregion Variables and Prereqs



#region Main script

# Query base info
Set-AdServerSettings -ViewEntireForest $true

if (Get-Command -Name Get-MobileDevice) {
    [array]$deviceList = Get-MobileDevice -ResultSize unlimited
} else {
    [array]$deviceList = Get-ActiveSyncDevice -ResultSize unlimited
}
if ($deviceList) { [array]$groupDeviceType = $deviceList | Group-Object Devicetype | Sort-Object Name }


# Build PRTG result
$result += "<prtg>"

$result += Out-PrtgChannel -Channel "All devices" -Value ([Array]($groupDeviceType.group)).Count -Mode Absolute -Unit Count -ShowTable -ShowChart

foreach ($deviceType in $groupDeviceType) {
    $result += Out-PrtgChannel -Channel $deviceType.Name -Value ([Array]($deviceType.group)).Count -Mode Absolute -Unit Count -ShowTable -ShowChart
}

$result += "</prtg>"

# Output PRTG result
$result

# kill remoting session
$exSession | Remove-PSSession

#endregion
