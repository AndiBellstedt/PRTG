﻿<#
    .SYNOPSIS
        PRTG Veeam Advanced Sensor - Veeam Backup & Recovery (Version 11)

    .DESCRIPTION
        Advanced Sensor will report repository information

        Attention. The Veeam PowerShell module is a 64Bit module!
        PRTG does (currently) not work with 64Bit PowerShell out of the box.
        You have to use a workarround with a batch or an exe file, as discribed in:
        https://kb.paessler.com/en/topic/32033-is-it-possible-to-use-the-64bit-version-of-powershell-with-prtg

        Recommendation is use "PSx64.cmd" as the script sensor and specify this scriptnname and it's parameters in the parameter box of PRTG

    .PARAMETER ComputerName
        Name of Backup & Replication Server

    .PARAMETER MinErrorInGB
        The minium value of freespace for the repository

        This matters only when the sensor is created, or for new repositories.
        The data is used by PRTG only, when the sensor is created. Later changes of the parameter will be ignored by PRTG

    .PARAMETER MinFreePrct
        The minium value of percentual freespace for the repository

        This matters only when the sensor is created, or for new repositories.
        The data is used by PRTG only, when the sensor is created. Later changes of the parameter will be ignored by PRTG

    .PARAMETER Include
        String filter to include explicit repositories
        Can be none, one or many

    .PARAMETER Exclude
        String filter to exclude repositories
        Can be none, one or many

    .PARAMETER Credential
        Credential to connect to remote system and/or Veeam B&R Service

    .PARAMETER PSRemote
        Text "true" or "false" to use PSRemoting instead of locally installed VeeamPSSnapin.
        Use "Get-Help about_remote_requirements" for more information

    .EXAMPLE
        PS C:\> Get-PrtgVBR11RepositoryStatus.ps1 -ComputerName VBR01.corp.customer.com

        Get all repositories from server 'VBR01.corp.customer.com'
        This methods require Veeam Management console / PowerShell module installed locally on the probe system

    .EXAMPLE
        PS C:\> Get-PrtgVBR11RepositoryStatus.ps1 -ComputerName VBR01.corp.customer.com -PSRemote

        Get all repositories from server 'VBR01.corp.customer.com' with the use of PSRemoting. This one query Veeam information "locally".
        This one can execute, without installed Veeam Management console / PowerShell module on the probe system

    .EXAMPLE
        PS C:\> Get-PrtgVBR11RepositoryStatus.ps1 -ComputerName VBR01.corp.customer.com -Filter *Local* -PSRemote

        Get only repositories where 'Local' is in the RepoName. Infomation will be queried from server 'VBR01.corp.customer.com' through PSRemoting.
        This one can execute, without installed Veeam Management console / PowerShell module on the probe system

    .Notes
        Get-PrtgVBR11RepositoryStatus
        Author: Andreas Bellstedt
        LASTEDIT: 2022/11/26
        VERSION: 1.2.2
        KEYWORDS: PRTG, Veeam, VBR

    .LINK
        https://github.com/AndiBellstedt/PRTG
#>
#Requires -Version 3
[cmdletbinding(
    ConfirmImpact = "Low",
    PositionalBinding = $false
)]
param(
    [Alias("BRHost")]
    [string]
    $ComputerName = (.{ if ($env:prtg_host) { $env:prtg_host } else { $env:COMPUTERNAME } }),

    [Alias("Filter", "RepoName", "Repository", "RepositoryName")]
    [string[]]
    $Include,

    [string[]]
    $Exclude,

    [int]
    $MinErrorInGB = 50,

    [int]
    $MinFreePrct = 10,

    [pscredential]
    $Credential = (.{ if ($env:prtg_windowsuser -and $env:prtg_windowspassword) { [pscredential]::new( "$(if($env:prtg_windowsdomain){ "$($env:prtg_windowsdomain)\"})$($env:prtg_windowsuser)", $("$($env:prtg_windowspassword)" | ConvertTo-SecureString -AsPlainText -Force)) } }),

    [ValidateSet("true", "false")]
    [string]
    $PSRemote = "true" #(.{ if ($env:COMPUTERNAME -like $env:prtg_host -or $env:prtg_host -like "localhost" -or $env:prtg_host -like "127.0.0.1" -or $ComputerName -like $env:COMPUTERNAME -or $ComputerName -like "localhost" -or $ComputerName -like "127.0.0.1") { "false" } else { "true" } })
)



#region Variables and Prereqs
# Disable output of warning to prevent Veeam PS quirks
$WarningPreference = "SilentlyContinue"

# Set error handling
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

# Start loading VEEAM module (in local or remote session)
[bool]$usePSRemote = [bool]::Parse($PSRemote)
if ($usePSRemote) {
    $paramsRemote = @{
        "ComputerName" = $ComputerName
        "ErrorAction"  = "Continue"
    }
    if ($Credential) {
        $paramsRemote.Add("Credential", $Credential)
        $username = $Credential.UserName
    } else {
        $username = $env:USERNAME
    }

    # Remoting on VBR server
    $RemoteSession = New-PSSession @paramsRemote
    if (-not $RemoteSession) { throw "Cannot open remote session to '$($ComputerName)' with user '$($username)'" }

    # Loading PSSnapin then retrieve commands
    Invoke-Command -Session $RemoteSession -ErrorAction Stop -Verbose:$false -ScriptBlock {
        $WarningPreference = "SilentlyContinue"
        Import-Module Veeam.Backup.PowerShell -Verbose:$false -ErrorAction Stop
    }
    Import-PSSession -Session $RemoteSession -Module Veeam.Backup.PowerShell -CommandName "Disconnect-VBRServer", "Connect-VBRServer", "Get-VBRBackupRepository", "Get-VBRRepositoryExtent" -ErrorAction Stop -Verbose:$false -AllowClobber  | Out-Null
} else {
    try {
        Import-Module Veeam.Backup.PowerShell -Verbose:$false -ErrorAction Stop
    } catch {
        throw "Failed to load Veeam.Backup.PowerShell module"
    }
}

# Initiate B&R Service Connection
Write-Verbose "Start processing connection to '$($ComputerName)'"

Disconnect-VBRServer -Verbose:$false -ErrorAction Ignore

$paramConnectVBR = @{
    "Verbose"     = $false
    "ErrorAction" = "Stop"
}
if ($usePSRemote -eq $false) { $paramConnectVBR.Add("Server", $ComputerName) }
if (($usePSRemote -eq $false) -and $Credential) {
    $paramConnectVBR.Add("Credential", $Credential)
    $username = $Credential.UserName
} else {
    $username = $env:USERNAME
}

try {
    Write-Verbose "Connecting new Veeam B&R Service '$($ComputerName)' with user '$($username)'"
    Connect-VBRServer @paramConnectVBR
} catch {
    Throw "Failed to connect to Veeam B&R Service '$($ComputerName)' with user '$($username)'"
}
#endregion Variables and Prereqs



#region Functions
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
#endregion



#region Main script
# Query data from Veeam
[array]$repos = @()
if ($usePSRemote) {
    $repos += Invoke-Command -Session $RemoteSession -ErrorAction Stop -Verbose:$false -ScriptBlock {
        [array]$vbrBackupRepository = Get-VBRBackupRepository | Sort-Object Name

        foreach ($repo in $vbrBackupRepository) {
            $container = $repo.GetContainer()
            $repo | Select-Object Name, Id, @{n = "Type"; e = { $_.Type.ToString() } }, @{n = "CachedFreeSpace"; e = { $container.CachedFreeSpace.InBytes } }, @{n = "CachedTotalSpace"; e = { $container.CachedTotalSpace.InBytes } }
            Clear-Variable container -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Confirm:$false -WhatIf:$false
        }
    }

    $repos += Invoke-Command -Session $RemoteSession -ErrorAction Stop -Verbose:$false -ScriptBlock {
        [array]$vbrBackupRepositoryScaleOut = Get-VBRBackupRepository -ScaleOut

        foreach ($scaleOut in $vbrBackupRepositoryScaleOut) {
            foreach ($extend in (Get-VBRRepositoryExtent -Repository $scaleOut.Name)) {
                $container = $extend.repository.GetContainer()
                $extend | Select-Object Name, Id, @{n = "Type"; e = { $extend.repository.Type.ToString() } }, @{n = "CachedFreeSpace"; e = { $container.CachedFreeSpace.InBytes } }, @{n = "CachedTotalSpace"; e = { $container.CachedTotalSpace.InBytes } }
                Clear-Variable container -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Confirm:$false -WhatIf:$false
            }
        }
    }
} else {
    [array]$vbrBackupRepository = Get-VBRBackupRepository | Sort-Object Name
    $repos += foreach ($repo in $vbrBackupRepository) {
        $container = $repo.GetContainer()
        $repo | Select-Object Name, Id, @{n = "Type"; e = { $_.Type.ToString() } }, @{n = "CachedFreeSpace"; e = { $container.CachedFreeSpace.InBytes } }, @{n = "CachedTotalSpace"; e = { $container.CachedTotalSpace.InBytes } }
        Clear-Variable container -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Confirm:$false -WhatIf:$false
    }

    [array]$vbrBackupRepositoryScaleOut = Get-VBRBackupRepository -ScaleOut
    $repos += foreach ($scaleOut in $vbrBackupRepositoryScaleOut) {
        foreach ($extend in (Get-VBRRepositoryExtent -Repository $scaleOut.Name)) {
            $container = $extend.repository.GetContainer()
            $extend | Select-Object Name, Id, @{n = "Type"; e = { $extend.repository.Type.ToString() } }, @{n = "CachedFreeSpace"; e = { $container.CachedFreeSpace.InBytes } }, @{n = "CachedTotalSpace"; e = { $container.CachedTotalSpace.InBytes } }
            Clear-Variable container -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -Confirm:$false -WhatIf:$false
        }
    }
}
$repos = $repos | Sort-Object Name -Unique


# Filter
if ($Include -and $repos) {
    $filterResult = ""
    $filterResult = foreach ($filterItem in $Include) {
        $repos | Where-Object Name -like $filterItem
    }
    $repos = $filterResult | Sort-Object Name, id -Unique
}

if ($Exclude -and $repos) {
    [Array]$toRemove = @()
    $toRemove = foreach ($filterItem in $Exclude) {
        $repos | Where-Object Name -Like $filterItem
    }
    $toRemove = $toRemove | Sort-Object id -Unique

    $repos = $repos | Where-Object id -NotIn $toRemove.id | Sort-Object Name, id -Unique
}


# Output result to PRTG
"<prtg>"
# channel for freespace bytes - usual backup repository
foreach ($item in $repos) {
    Out-PrtgChannel -Channel "$($item.Name) ($($item.Type)) Free" -Value ([math]::round(($item.CachedFreeSpace / 1GB), 1)) -Unit GB -Float $true -ShowChart -ShowTable -MinError $MinErrorInGB -ErrorMsg "Diskspace is getting low on repo $($item.Name)" #-MaxWarn -MinWarn -MaxError -WarnMsg
    Out-PrtgChannel -Channel "$($item.Name) ($($item.Type)) Used" -Value ([math]::round((($item.CachedTotalSpace - $item.CachedFreeSpace) / 1GB), 1)) -Unit GB -Float $true -ShowTable
    Out-PrtgChannel -Channel "$($item.Name) ($($item.Type)) Total" -Value ([math]::round(($item.CachedTotalSpace / 1GB), 1)) -Unit GB -Float $true
}

# channel for freespace percent
foreach ($item in $repos) {
    $percent = [math]::Round( ($item.CachedFreeSpace / $item.CachedTotalSpace * 100), 0)
    Out-PrtgChannel -Channel "$($item.Name) ($($item.Type)) % free" -Value $percent -Unit Percent -ShowChart -ShowTable -MinError $MinFreePrct -ErrorMsg "Freespace % is getting low on repo $($item.Name)" #-MaxWarn -MinWarn -MaxError -WarnMsg
}
"</prtg>"

# kill remote sesssion
Disconnect-VBRServer -Verbose:$false -ErrorAction Ignore
if ($RemoteSession) { Remove-PSSession -Session $RemoteSession }
#endregion

