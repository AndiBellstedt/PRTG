<#
    .SYNOPSIS
        PRTG Veeam Advanced Sensor

    .DESCRIPTION
        Advanced Sensor will Report Statistics about Backups during last 24 Hours and Actual Repository usage.

    .PARAMETER PSRemote
        Switch to use PSRemoting instead of locally installed VeeamPSSnapin.
        Use "Get-Help about_remote_requirements" for more information

    .EXAMPLE
        PRTG-VeeamBRStats.ps1 -BRHost veeam01.lan.local

    .Notes
        NAME:  PRTG-VeeamBRStats.ps1
        Author: Andreas Bellstedt
        LASTEDIT: 2022/11/26
        VERSION:  1.0.1
        KEYWORDS: PRTG, Veeam, VBR

    .LINK
        https://github.com/AndiBellstedt/PRTG
#>
#Requires -Version 3
[cmdletbinding(
    ConfirmImpact = "Low",
    PositionalBinding = $true
)]
param(
    [string]
    $BRHost = (.{ if ($env:prtg_host) { $env:prtg_host } else { $env:COMPUTERNAME } }),

    [int]
    $MinErrorInGB = 50,

    [int]
    $MinFreePrct = 10,

    [switch]
    $PSRemote,

    [switch]
    $DebugConsoleOutput
)



#region Variables and Prereqs
# Set error handling
trap {
    # Catch all unhadled errors and close Pssession to avoid this issue:
    # Thanks for https://github.com/klmj for the idea
    # http://www.checkyourlogs.net/?p=54583

    if ($RemoteSession) { Remove-PSSession -Session $RemoteSession }

    # build PRTG result object with error output
    "<prtg>"
    " <error>1</error>"
    " <text>$($_.ToString())</text>"
    "</prtg>"

    exit 1
}

# Start Load VEEAM Snapin (in local or remote session)
if ($PSRemote) {
    # Remoting on VBR server
    $RemoteSession = New-PSSession -Authentication Kerberos -ComputerName $BRHost
    if (-not $RemoteSession) { throw "Cannot open remote session on '$BRHost' with user '$env:USERNAME'" }

    # Loading PSSnapin then retrieve commands
    Invoke-Command -Session $RemoteSession -ScriptBlock { Add-PSSnapin VeeamPSSnapin -Verbose:$false; $WarningPreference = "SilentlyContinue" } -ErrorAction Stop -Verbose:$false # muting warning about powershell version
    Import-PSSession -Session $RemoteSession -Module VeeamPSSnapin -Verbose:$false -AllowClobber -WarningAction SilentlyContinue | Out-Null
} else {
    if (-not (Get-PSSnapin -Name VeeamPSSnapIn -ErrorAction SilentlyContinue)) {
        try {
            Add-PSSnapin -PassThru VeeamPSSnapIn -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to load VeeamPSSnapIn"
        }
    }
}

# Start BRHost Connection
Write-Verbose "Starting to Process Connection to '$BRHost' with user '$env:USERNAME' ..."
$OpenConnection = (Get-VBRServerSession).Server
if ($OpenConnection -eq $BRHost) {
    Write-Verbose "BRHost '$BRHost' is Already Connected..."
} elseif ($null -eq $OpenConnection) {
    Write-Verbose "Connecting BRHost '$BRHost' with user '$env:USERNAME'..."
    try {
        Connect-VBRServer -Server $BRHost -Verbose:$false
    } catch {
        Throw "Failed to connect to Veeam BR Host '$BRHost' with user '$env:USERNAME'"
    }
} else {
    Write-Verbose "Disconnection current BRHost..."
    Disconnect-VBRServer -Verbose:$false
    Write-Verbose "Connecting new BRHost '$BRHost' with user '$env:USERNAME'..."
    try {
        Connect-VBRServer -Server $BRHost -Verbose:$false
    } catch {
        Throw "Failed to connect to Veeam BR Host '$BRHost' with user '$env:USERNAME'"
    }
}

if (-not (Get-VBRServerSession).Server ) {
    Throw "Failed to connect to Veeam BR Host '$BRHost' with user '$env:USERNAME'"
}
#endregion Variables and Prereqs



#region Functions
function Set-PrtgResult {
    Param (
        [Parameter(mandatory = $True, Position = 0)]
        [string]
        $Channel,

        [Parameter(mandatory = $True, Position = 1)]
        $Value,

        # Standard Units: "BytesBandwidth", "BytesMemory", "BytesDisk", "Temperature", "Percent", "TimeResponse", "TimeSeconds", "Custom", "Count", "CPU", "BytesFile", "SpeedDisk", "SpeedNet", "TimeHours"
        [Parameter(mandatory = $True, Position = 2)]
        [string]
        $Unit,

        [Parameter(mandatory = $False)]
        [alias('mw')]
        [string]
        $MaxWarn,

        [Parameter(mandatory = $False)]
        [alias('minw')]
        [string]
        $MinWarn,

        [Parameter(mandatory = $False)]
        [alias('me')]
        [string]
        $MaxError,

        [Parameter(mandatory = $False)]
        [alias('mine')]
        [string]
        $MinError,

        [Parameter(mandatory = $False)]
        [alias('wm')]
        [string]
        $WarnMsg,

        [Parameter(mandatory = $False)]
        [alias('em')]
        [string]
        $ErrorMsg,

        [Parameter(mandatory = $False)]
        [alias('mo')]
        [string]
        $Mode,

        [Parameter(mandatory = $False)]
        [alias('sc')]
        [switch]
        $ShowChart,

        [Parameter(mandatory = $False)]
        [alias('ss')]
        [ValidateSet("One", "Kilo", "Mega", "Giga", "Tera", "Byte", "KiloByte", "MegaByte", "GigaByte", "TeraByte", "Bit", "KiloBit", "MegaBit", "GigaBit", "TeraBit")]
        [string]
        $SpeedSize,

        [Parameter(mandatory = $False)]
        [ValidateSet("One", "Kilo", "Mega", "Giga", "Tera", "Byte", "KiloByte", "MegaByte", "GigaByte", "TeraByte", "Bit", "KiloBit", "MegaBit", "GigaBit", "TeraBit")]
        [string]
        $VolumeSize,

        [Parameter(mandatory = $False)]
        [alias('dm')]
        [ValidateSet("Auto", "All")]
        [string]
        $DecimalMode,

        [Parameter(mandatory = $False)]
        [alias('w')]
        [switch]
        $Warning,

        [Parameter(mandatory = $False)]
        [string]
        $ValueLookup
    )

    # variables
    $StandardUnits = @("BytesBandwidth", "BytesMemory", "BytesDisk", "Temperature", "Percent", "TimeResponse", "TimeSeconds", "Custom", "Count", "CPU", "BytesFile", "SpeedDisk", "SpeedNet", "TimeHours", "Disk", "Bandwidth", "Memory", "File")
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

    if (!($Value -is [int])) { $Result += "    <float>1</float>`n" }
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
    if ($DecimalMode) { $Result += "    <decimalmode>$DecimalMode</decimalmode>`n" }
    if ($Warning) { $Result += "    <warning>1</warning>`n" }
    if ($ValueLookup) { $Result += "    <ValueLookup>$ValueLookup</ValueLookup>`n" }
    if (!($ShowChart)) { $Result += "    <showchart>0</showchart>`n" }
    $Result += "  </result>`n"

    $Result
}
#endregion



#region Main script
# query data from Veeam
$VBRBackupRepository = Invoke-Command -Session $RemoteSession -ScriptBlock { (Get-VBRBackupRepository).Info } | Sort-Object Name

# output result to PRTG
"<prtg>"

# channel for freespace bytes
foreach ($item in $VBRBackupRepository) {
    Set-PrtgResult -Channel "$($item.Name) ($($item.Type)) Free" -Value $item.CachedFreeSpace -Unit BytesDisk -VolumeSize Giga -ShowChart -MinError ($MinErrorInGB * 1GB) -ErrorMsg "Diskspace is getting low on repo $($item.Name)" #-MaxWarn -MinWarn -MaxError -WarnMsg
    Set-PrtgResult -Channel "$($item.Name) ($($item.Type)) Total" -Value $item.CachedTotalSpace -Unit BytesDisk -VolumeSize Giga
}
# channel for freespace percent
foreach ($item in $VBRBackupRepository) {
    $percent = [math]::Round( ($item.CachedFreeSpace / $item.CachedTotalSpace * 100), 0)
    Set-PrtgResult -Channel "$($item.Name) ($($item.Type)) % free" -Value $percent -Unit Percent -ShowChart -MinError $MinFreePrct -ErrorMsg "Freespace % is getting low on repo $($item.Name)" #-MaxWarn -MinWarn -MaxError -WarnMsg
}

"</prtg>"

# kill remote sesssion
if ($RemoteSession) { Remove-PSSession -Session $RemoteSession }
#endregion


#region Debug output
if ($DebugConsoleOutput) {
    $VBRBackupRepository
}
#endregion