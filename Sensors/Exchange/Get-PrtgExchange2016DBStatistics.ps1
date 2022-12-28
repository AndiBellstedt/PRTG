<#
    .SYNOPSIS
        PRTG Advanced Sensor - Exchange Server (Onpremises) - Database statistics

    .DESCRIPTION
        Advanced Sensor will report extended mailbox database statistics into channels within the sensor

        Requirements:
        - HTTP (TCP Port 80) to exchange server specified in $ComputerName
        - priviledged (admin) account connecting to exchange backend

    .PARAMETER ComputerName
        Name of Server

    .PARAMETER Filter
        String filter for mailbox database
        Can be none, one or many.

    .PARAMETER ExchangeIsHA
        Boolean telling the sensor, to expect exchange database in a high availability setup.
        This means, database is in a DAG and at least on 2 servers replicated.
        Default is "true"

    .PARAMETER Credential
        Credential to connect to remote system and/or Veeam B&R Service

    .EXAMPLE
        PS C:\> Get-PrtgExchange2016DBStatistics.ps1 -ComputerName ex01.corp.customer.com

        Get all mailbox databases from server 'ex01.corp.customer.com' and report the number of existing logfiles

    .EXAMPLE
        PS C:\> Get-PrtgExchange2016DBStatistics.ps1 -ComputerName ex01.corp.customer.com -Database "DB01"

        Get mailbox database "DB01" from server 'ex01.corp.customer.com' and report the number of existing logfiles

    .EXAMPLE
        PS C:\> Get-PrtgExchange2016DBStatistics.ps1 -ComputerName ex01.corp.customer.com -Credential $Cred -Filter "DB*"

        Get mailbox databases with name "DB*" from server 'ex01.corp.customer.com' and report the number of existing logfiles
        Connection to exchange will be done with credentials '$Cred'.

    .Notes
        Get-PrtgExchange2016DBStatistics
        Author: Andreas Bellstedt
        LASTEDIT: 2022/12/28
        VERSION:  1.0.1
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

    [Alias("HA", "HighAvailability")]
    [bool]
    $ExchangeIsHA = $true,

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
Import-PSSession -Session $exSession -CommandName "Set-AdServerSettings", "Get-MailboxDatabase", "Get-MailboxDatabaseCopyStatus" -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null

#endregion Variables and Prereqs



#region Main script

# Query base info
Set-AdServerSettings -ViewEntireForest $true
[array]$mailboxDatabase = Get-MailboxDatabase -Server $ComputerName -Status -IncludeCorrupted

# Filter
if ($Filter -and $mailboxDatabase) {
    $filterResult = ""
    $filterResult = foreach ($filterItem in $Filter) {
        $mailboxDatabase | Where-Object Name -like $filterItem
    }
    $mailboxDatabase = $filterResult | Sort-Object Name, id -Unique
}

# query statistic information
$databaseWithStatistic = foreach ($db in $mailboxDatabase) {
    [PSCustomObject]@{
        Name       = $db.Name
        Status     = $db
        CopyStatus = (Get-MailboxDatabaseCopyStatus -Identity "$($db.Identity)\$($ComputerName)")
    }
}

# Build PRTG result
[array]$messages = @()
$result += "<prtg>"

foreach ($db in $databaseWithStatistic) {
    $contentIndexState = $null
    switch ($db.CopyStatus.ContentIndexState) {
        "Healthy" { $contentIndexState = 0 }
        "Crawling" { $contentIndexState = 1 }
        "Error" { $contentIndexState = 2 }
        Default {
            $contentIndexState = 2
            $messages += "Unknown ContentIndex status '$($db.CopyStatus.ContentIndexState)' in $($db.Name)"
        }
    }

    $dbCopyStatus = $null
    switch ($db.CopyStatus.Status) {
        "Healthy" { $dbCopyStatus = 0 }
        "Mounted" { $dbCopyStatus = 1 }
        "SeedingSource" { $dbCopyStatus = 2 }
        "Seeding" { $dbCopyStatus = 3 }
        "Initializing" { $dbCopyStatus = 4 }
        "Resynchronizing" { $dbCopyStatus = 5 }
        "Mounting" { $dbCopyStatus = 6 }
        "Dismounting" { $dbCopyStatus = 7 }
        "SinglePageRestore" { $dbCopyStatus = 8 }
        "Disconnected and Healthy" { $dbCopyStatus = 9 }
        "Disconnected and Resynchronizing" { $dbCopyStatus = 10 }
        "Suspended" { $dbCopyStatus = 11 }
        "Failed" { $dbCopyStatus = 12 }
        "Failed and Suspended" { $dbCopyStatus = 13 }
        "Dismounted" { $dbCopyStatus = 14 }
        "Service Down" { $dbCopyStatus = 15 }
        Default {
            $dbCopyStatus = 12
            $messages += "Unknown Copy status '$($db.CopyStatus.Status)' in $($db.Name)"
        }
    }


    if($ExchangeIsHA) {
        $result += Out-PrtgChannel -Channel "$($db.Name) Server count" -Value ($db.Status.Servers.Count) -Mode Absolute -Unit "Count" -MinError 1 -ShowTable -ErrorMsg "$($db.Name) lost high availability status"
    } else {
        $result += Out-PrtgChannel -Channel "$($db.Name) Server count" -Value ($db.Status.Servers.Count) -Mode Absolute -Unit "Count" -MaxError 1 -ShowTable -ErrorMsg "$($db.Name) expected in non HA setup"
        if($db.Status.Servers.Count -gt 1) { $messages += "$($db.Name) expected in non HA setup" }
    }
    $result += Out-PrtgChannel -Channel "$($db.Name) Status availability" -Value $dbCopyStatus -ValueLookup "prtg.standardlookups.exchangedag.status"
    $result += Out-PrtgChannel -Channel "$($db.Name) Status contentindex" -Value $contentIndexState -ValueLookup "prtg.standardlookups.exchangedag.contentindexstate"
    $result += Out-PrtgChannel -Channel "$($db.Name) TimeDiff last FullBackup" -Value ([math]::Round(((Get-Date) - $db.CopyStatus.LatestFullBackupTime).TotalHours, 0)) -Unit TimeHours -MaxWarn 24 -MaxError 48 -ShowChart -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Database version" -Value ([float]$db.Status.CurrentSchemaVersion) -Float $true -Mode Absolute -Unit "version" -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Database Whitespace" -Value ([math]::Round(($db.Status.AvailableNewMailboxSpace.ToString().Split('(')[1].Split(')')[0].split(' ')[0].replace(',', '').replace('.', '') / 1MB),0)) -Mode Absolute -VolumeSize MegaByte -ShowChart -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Database size" -Value ([math]::Round(($db.Status.DatabaseSize.ToString().Split('(')[1].Split(')')[0].split(' ')[0].replace(',', '').replace('.', '') / 1MB),0)) -Mode Absolute -VolumeSize MegaByte -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Log volume freespace" -Value ([math]::Round(($db.CopyStatus.DiskFreeSpace.ToString().Split('(')[1].Split(')')[0].split(' ')[0].replace(',', '').replace('.', '') / 1MB),0)) -Mode Absolute -VolumeSize MegaByte -ShowChart -ShowTable -MinWarn 8192 -MinError 2048
    $result += Out-PrtgChannel -Channel "$($db.Name) Log volume freespace total" -Value ([math]::Round(($db.CopyStatus.DiskTotalSpace.ToString().Split('(')[1].Split(')')[0].split(' ')[0].replace(',', '').replace('.', '') / 1MB),0)) -Mode Absolute -VolumeSize MegaByte
    $result += Out-PrtgChannel -Channel "$($db.Name) Log volume freespace Percent" -Value ($db.CopyStatus.DiskFreeSpacePercent) -Mode Absolute -Unit Percent -ShowChart -ShowTable -MinWarn 5 -MinError 2
    $result += Out-PrtgChannel -Channel "$($db.Name) Disk latency read" -Value ($db.CopyStatus.RecentDiskReadLatencyMs) -Mode Absolute -Unit TimeResponse -ShowChart -ShowTable -MaxWarn 20 -MaxError 100
    $result += Out-PrtgChannel -Channel "$($db.Name) Disk latency write" -Value ($db.CopyStatus.RecentDiskWriteLatencyMs) -Mode Absolute -Unit TimeResponse -ShowChart -ShowTable -MaxWarn 20 -MaxError 100
    $result += Out-PrtgChannel -Channel "$($db.Name) Disk read/s" -Value ($db.CopyStatus.RecentDiskReadsPerSec) -Mode Absolute -Unit "/s" -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Disk write/s" -Value ($db.CopyStatus.RecentDiskWritesPerSec) -Mode Absolute -Unit "/s" -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Usage CPU" -Value ($db.CopyStatus.RecentServerCpuPercentage) -Mode Absolute -Unit CPU -ShowChart -ShowTable -MaxWarn 70 -MaxError 90
    $result += Out-PrtgChannel -Channel "$($db.Name) Status mounted" -Value ([int]$db.Status.Mounted) -ValueLookup "prtg.standardlookups.boolean.statetrueok" -ShowChart -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Is MailboxDatabase" -Value ([int]$db.Status.IsMailboxDatabase) -ValueLookup "prtg.standardlookups.boolean.statetrueok" -ShowChart
    $result += Out-PrtgChannel -Channel "$($db.Name) Backup in progress" -Value ([int]$db.Status.BackupInProgress) -ValueLookup "prtg.standardlookups.boolean.statefalseok" -MaxError 2
    $result += Out-PrtgChannel -Channel "$($db.Name) Excluded from provisioning" -Value ([int]$db.Status.IsExcludedFromProvisioning) -ValueLookup "prtg.standardlookups.boolean.statefalseok" -ShowChart -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Status Index Enabled" -Value ([int]$db.Status.IndexEnabled) -ValueLookup "prtg.standardlookups.boolean.statefalseok" -MaxError 2
    $result += Out-PrtgChannel -Channel "$($db.Name) Status allow file restore" -Value ([int]$db.Status.AllowFileRestore) -ValueLookup "prtg.standardlookups.boolean.statefalseok" -ShowChart -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Retention for mailboxes" -Value (([timespan]$db.Status.MailboxRetention).TotalHours) -Mode Absolute -Unit "TimeHours" -MinError 2 -MinWarn 24 -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Retention for deleted items" -Value (([timespan]$db.Status.DeletedItemRetention).TotalHours) -Mode Absolute -Unit "TimeHours" -MinError 2 -MinWarn 24 -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Quota recoverable items" -Value ([math]::Round(($db.Status.RecoverableItemsQuota.ToString().Split('(')[1].Split(')')[0].split(' ')[0].replace(',', '').replace('.', '') / 1MB),0)) -Mode Absolute -VolumeSize MegaByte -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Quota CalendarLogging" -Value ([math]::Round(($db.Status.CalendarLoggingQuota.ToString().Split('(')[1].Split(')')[0].split(' ')[0].replace(',', '').replace('.', '') / 1MB),0)) -Mode Absolute -VolumeSize MegaByte -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Copy queue length" -Value ($db.CopyStatus.CopyQueueLength) -Mode Absolute -Unit "Count" -ShowChart -ShowTable -MaxWarn 1 -MaxError 10
    $result += Out-PrtgChannel -Channel "$($db.Name) Replay queue length" -Value ($db.CopyStatus.ReplayQueueLength) -Mode Absolute -Unit "Count" -ShowTable
    $result += Out-PrtgChannel -Channel "$($db.Name) Replay is suspended" -Value ([int]$db.CopyStatus.ReplaySuspended) -ValueLookup "prtg.standardlookups.boolean.statefalseok"
    $result += Out-PrtgChannel -Channel "$($db.Name) Resume is blocked" -Value ([int]$db.CopyStatus.ResumeBlocked) -ValueLookup "prtg.standardlookups.boolean.statefalseok"
    $result += Out-PrtgChannel -Channel "$($db.Name) Reseed id blocked" -Value ([int]$db.CopyStatus.ReseedBlocked) -ValueLookup "prtg.standardlookups.boolean.statefalseok"
    $result += Out-PrtgChannel -Channel "$($db.Name) Inplace reseed is blocked" -Value ([int]$db.CopyStatus.InPlaceReseedBlocked) -ValueLookup "prtg.standardlookups.boolean.statefalseok"
}
if($messages) {
    $result += "<text>$( [string]::Join(", ", $messages) )</text>"
}
$result += "</prtg>"

# Output PRTG result
$result

# kill remoting session
$exSession | Remove-PSSession

#endregion
