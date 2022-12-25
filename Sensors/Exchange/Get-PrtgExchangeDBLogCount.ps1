<#
    .SYNOPSIS
        PRTG Advanced Sensor - Exchange Server (Onpremises)

    .DESCRIPTION
        Advanced Sensor will report amount of logfiles existing for a mailbox database as a channel in the sensor

        Requirements:
        - HTTP (TCP Port 80) to exchange server specified in $ComputerName
        - PSRemoting (TCP Port 5985) or SMB (TCP port 445) to any exchange server with a database
        - priviledged (admin) account connecting to exchange backend and administrative shares/ PSRemoteEndpoint

    .PARAMETER ComputerName
        Name of Server

    .PARAMETER Filter
        String filter for mailbox database
        Can be none, one or many.

    .PARAMETER Credential
        Credential to connect to remote system and/or Veeam B&R Service

    .PARAMETER PSRemote
        Use PSRemoting for file operations instead of locally query files via SMB connection
        Default is "true"

        Use "Get-Help about_remote_requirements" for more information

    .EXAMPLE
        PS C:\> Get-PrtgExchangeDBLogCount.ps1 -ComputerName ex01.corp.customer.com

        Get all mailbox databases from server 'ex01.corp.customer.com' and report the number of existing logfiles

    .EXAMPLE
        PS C:\> Get-PrtgExchangeDBLogCount.ps1 -ComputerName ex01.corp.customer.com -Database "DB01"

        Get mailbox database "DB01" from server 'ex01.corp.customer.com' and report the number of existing logfiles

    .EXAMPLE
        PS C:\> Get-PrtgExchangeDBLogCount.ps1 -ComputerName ex01.corp.customer.com -Filter "DB*" Credential $Cred

        Get mailbox databases with name "DB*" from server 'ex01.corp.customer.com' and report the number of existing logfiles
        Connection to exchange will be done with credentials '$Cred'.

    .Notes
        Get-PrtgExchangeDBLogCount
        Author: Andreas Bellstedt
        LASTEDIT: 2022/12/25
        VERSION:  1.0.0
        KEYWORDS: PRTG, Exchange, OnPremise, database

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

    [Alias("Database", "DB")]
    [string[]]
    $Filter,

    [pscredential]
    $Credential = (.{ if ($env:prtg_windowsuser -and $env:prtg_windowspassword) { [pscredential]::new( "$(if($env:prtg_windowsdomain){ "$($env:prtg_windowsdomain)\"})$($env:prtg_windowsuser)", $("$($env:prtg_windowspassword)" | ConvertTo-SecureString -AsPlainText -Force)) } }),

    [ValidateSet("true", "false")]
    [string]
    $PSRemote = "true"
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
Import-PSSession -Session $exSession -CommandName "Set-AdServerSettings", "Get-MailboxDatabase" -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null

#endregion Variables and Prereqs



#region Main script

# Query jobs
Set-AdServerSettings -ViewEntireForest $true
[array]$mailboxDatabase = Get-MailboxDatabase #| Select-Object name, Servername, LogFolderpath, LogFilePrefix

# Filter Jobs
if ($Filter -and $mailboxDatabase) {
    $filterResult = ""
    $filterResult = foreach ($filterItem in $Filter) {
        $mailboxDatabase | Where-Object Name -like $filterItem
    }
    $mailboxDatabase = $filterResult | Sort-Object Name, id -Unique
}

# Build PRTG result
$result += "<prtg>"

foreach ($db in $mailboxDatabase) {
    if ($PSRemote) {
        $fileCount = Invoke-Command -ComputerName $db.Servername -ErrorAction Stop -ScriptBlock {
            $db = $using:db
            [string]$logpath = "\\$($db.Servername)\$($db.LogFolderpath.ToString().Replace(":", "$").Trim('\'))\$($db.LogFilePrefix)*.log"
            (Get-ChildItem -Path $logpath).count
        }
    } else {
        if (-not (Test-NetConnection -ComputerName $serverName -CommonTCPPort SMB -InformationLevel Quiet)) {
            [string]$logpath = "\\$($db.Servername)\$($db.LogFolderpath.ToString().Replace(":", "$").Trim('\'))\$($db.LogFilePrefix)*.log"
            $fileCount = (Get-ChildItem -Path $logpath).Count
        }
    }

    # Output PRTG job channel
    $result += Out-PrtgChannel -Channel $db.Name -Value $fileCount -Unit "Count" -ShowChart -ShowTable
}

$result += "</prtg>"

# Output PRTG result
$result

# kill remoting session
$exSession | Remove-PSSession

#endregion
