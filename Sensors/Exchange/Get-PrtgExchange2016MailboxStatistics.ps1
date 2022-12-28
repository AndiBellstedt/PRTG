<#
    .SYNOPSIS
        PRTG Advanced Sensor - Exchange Server (Onpremises) - Mailbox statistics

    .DESCRIPTION
        Advanced Sensor will report some mailbox statistics from exchange service

        Requirements:
        - HTTP (TCP Port 80) to exchange server specified in $ComputerName
        - priviledged (admin) account connecting to exchange backend and administrative shares/ PSRemoteEndpoint

    .PARAMETER ComputerName
        Name of Server

    .PARAMETER Filter
        String filter for excluding mailboxes
        Can be none, one or many.

    .PARAMETER Credential
        Credential to connect to remote system and/or Veeam B&R Service

    .EXAMPLE
        PS C:\> Get-PrtgExchange2016MailboxStatistics.ps1 -ComputerName ex01.corp.customer.com

        Get mailboxes from organization out of server 'ex01.corp.customer.com' and report statistcs

    .EXAMPLE
        PS C:\> Get-PrtgExchange2016MailboxStatistics.ps1 -ComputerName ex01.corp.customer.com -Filter service.*

        Get mailboxes from organization out of server 'ex01.corp.customer.com' and report statistcs
        Mailboxes with name *service.*" will be excluded from statistics

    .EXAMPLE
        PS C:\> Get-PrtgExchange2016MailboxStatistics.ps1 -ComputerName ex01.corp.customer.com -Credential $Cred

        Get mailboxes from organization out of server 'ex01.corp.customer.com' and report statistcs
        Connection to exchange will be done with credentials '$Cred'.

    .Notes
        Get-PrtgExchange2016MailboxStatistics
        Author: Andreas Bellstedt
        LASTEDIT: 2022/12/28
        VERSION:  1.0.0
        KEYWORDS: PRTG, Exchange, OnPremise, mailbox statistics

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

    [Alias("Exclude", "MailboxExcluded")]
    [string[]]
    $Filter,

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
[array]$STATISTICGrouping = @(1, 5, 10, 50)
$STATISTICGrouping = $STATISTICGrouping | Sort-Object

# Connection to Exchange service
$paramsExchange = @{
    "ConfigurationName" = "Microsoft.Exchange"
    "ConnectionUri"     = "http://$($ComputerName)/PowerShell"
    "ErrorAction"       = "Continue"
}
if ($Credential) { $paramsExchange.Add("Credential", $Credential) }

$exSession = New-PSSession @paramsExchange
if (-not $exSession) { throw "Cannot open remote session to '$($ComputerName)' with user '$($username)'" }
Import-PSSession -Session $exSession -CommandName "Set-AdServerSettings", "Get-Mailbox", "Get-MailboxStatistics", "Get-MailboxDatabase" -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null

#endregion Variables and Prereqs



#region Main script

# Query base info
Set-AdServerSettings -ViewEntireForest $true
[array]$mailboxes = Get-Mailbox -ResultSize unlimited
[array]$mailboxDatabases = Get-MailboxDatabase

# Filter
if ($Filter -and $mailboxes) {
    $filterResult = ""
    $filterResult = foreach ($filterItem in $Filter) {
        $mailboxes | Where-Object Name -notlike $filterItem
    }
    $mailboxes = $filterResult | Sort-Object Name, id -Unique
}

# build groups for channels
[array]$mailboxDbGroups = $mailboxes | Group-Object -Property Database
[array]$mailboxTypeGroups = $mailboxes | Group-Object -Property RecipientTypeDetails
[array]$mailboxHiddenGroups = $mailboxes | Group-Object -Property HiddenFromAddressListsEnabled
[array]$maildomainGroups = $mailboxes | ForEach-Object { ($_.primarysmtpaddress.split("@")[1]) } | Group-Object

# Get Mailbox statistics, calculate sizes on mailboxes and statistical groups
[array]$mailboxStatistics = $mailboxes | Get-MailboxStatistics
$mailboxStatistics = foreach ($item in $mailboxStatistics) {
    # convert string to byte
    $mailboxeSizeInBytes = $item.TotalItemSize.ToString().split("(")[1].split(" ")[0].replace(",", "").replace(".", "")

    # calculate rounded GB size (0,6 will be 0 /  0,7 will be 1)
    $sizeInGb = [math]::Round(($MailboxeSizeInBytes / 1GB), 1);
    $sizeInGbTrunced = [math]::Truncate($sizeInGb)
    if ( ($sizeInGb - $sizeInGbTrunced) -ge ((10 - 3) / 10)) {
        $mailboxeStatisticSizeInGB = $sizeInGbTrunced + 1
    } else {
        $mailboxeStatisticSizeInGB = $sizeInGbTrunced
    }

    # put most matching group value in place
    for ($i = 0; $i -lt $STATISTICGrouping.Count; $i++) {
        if ( $item.MailboxeStatisticSizeInGB -le $STATISTICGrouping[$i] ) {
            $mailboxeSizeStatisticGroup = $STATISTICGrouping[$i]
            $i = $STATISTICGrouping.Count + 1
        }
        if ($i -eq ($STATISTICGrouping.Count - 1)) {
            $mailboxeSizeStatisticGroup = $STATISTICGrouping[$i]
        }
    }

    # add infos into object
    Add-Member -InputObject $item -MemberType NoteProperty -Name "MailboxeSizeInBytes" -Value $mailboxeSizeInBytes -Force
    Add-Member -InputObject $item -MemberType NoteProperty -Name "MailboxeStatisticSizeInGB" -Value $mailboxeStatisticSizeInGB -Force
    Add-Member -InputObject $item -MemberType NoteProperty -Name "MailboxeSizeStatisticGroup" -Value $mailboxeSizeStatisticGroup -Force

    # output to pipeline
    $item
}
$MailboxeSizeStatisticGroups = $mailboxStatistics | Sort-Object MailboxeSizeStatisticGroup | Group-Object MailboxeSizeStatisticGroup


# Build PRTG result
[array]$messages = @()
$result += "<prtg>"

$result += Out-PrtgChannel -Channel "Mailboxes total" -Value ($mailboxes).count -Mode Absolute -Unit Count -ShowTable
$result += Out-PrtgChannel -Channel "Mailboxes visible" -Value ([Array](($mailboxHiddenGroups | Where-Object Name -like "false").group)).Count -Mode Absolute -Unit Count -ShowTable
$result += Out-PrtgChannel -Channel "Mailboxes hidden" -Value ([Array](($mailboxHiddenGroups | Where-Object Name -like "true").group)).Count -Mode Absolute -Unit Count -ShowTable

foreach ($data in $mailboxDatabases) {
    $result += Out-PrtgChannel -Channel "Mailboxes in $($data.Name)" -Value ([Array](($mailboxDbGroups | Where-Object name -like $data.Name).group)).Count -Mode Absolute -Unit Count -ShowTable -ShowChart -MinWarn 5 -MinError 0
}

foreach ($data in $mailboxTypeGroups) {
    $result += Out-PrtgChannel -Channel "Mailbox type: $($data.Name)" -Value ([Array]($data.group)).Count -Mode Absolute -Unit Count -ShowTable
}

foreach ($data in $maildomainGroups) {
    $result += Out-PrtgChannel -Channel "Maildomain: $($data.Name)" -Value ([Array]($data.group)).Count -Mode Absolute -Unit Count -ShowTable
}

$result += Out-PrtgChannel -Channel "Size 0-$($STATISTICGrouping[0])GB size" -Value ([Array](($MailboxeSizeStatisticGroups | Where-Object name -like $STATISTICGrouping[0]).group)).Count -Mode Absolute -Unit "mailboxes" -ShowTable
foreach ($statGroup in ($STATISTICGrouping[1 .. ($STATISTICGrouping.Count - 2)])) {
    $result += Out-PrtgChannel -Channel "Size up to $($statGroup)GB size" -Value ([Array](($MailboxeSizeStatisticGroups | Where-Object name -like $statGroup).group)).Count -Mode Absolute -Unit Count -ShowTable
}
$result += Out-PrtgChannel -Channel "Size $($STATISTICGrouping[-1])GB or more" -Value ([Array](($MailboxeSizeStatisticGroups | Where-Object name -like $STATISTICGrouping[-1]).group)).Count -Mode Absolute -Unit Count -ShowTable

if ($messages) {
    $result += "<text>$( [string]::Join(", ", $messages) )</text>"
}
$result += "</prtg>"

# Output PRTG result
$result

# kill remoting session
$exSession | Remove-PSSession

#endregion
