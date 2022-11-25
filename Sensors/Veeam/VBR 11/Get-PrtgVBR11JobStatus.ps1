<#
    .SYNOPSIS
        PRTG Veeam Advanced Sensor - Veeam Backup & Recovery (Version 11)

    .DESCRIPTION
        Advanced Sensor will Report status of any Veeam Backpu Backup & Replication Job as a channel in the sensor

        Attention. The Veeam PowerShell module is a 64Bit module!
        PRTG does (currently) not work with 64Bit PowerShell out of the box.
        You have to use a workarround with a batch or an exe file, as discribed in:
        https://kb.paessler.com/en/topic/32033-is-it-possible-to-use-the-64bit-version-of-powershell-with-prtg

        Recommendation is use "PSx64.cmd" as the script sensor and specify this scriptnname and it's parameters in the parameter box of PRTG

    .PARAMETER ComputerName
        Name of Backup & Replication Server

    .PARAMETER Filter
        String filter for Jobs.
        Can be none, one or many.

    .PARAMETER ValueLookup
        Name of prtg internal lookup value to translate "job status Id" in channel

    .PARAMETER Credential
        Credential to connect to remote system and/or Veeam B&R Service

    .PARAMETER PSRemote
        Switch to use PSRemoting instead of locally installed VeeamPSSnapin.
        Use "Get-Help about_remote_requirements" for more information

    .EXAMPLE
        PS C:\> Get-VeeamJobStatus.ps1 -ComputerName VBR01.corp.customer.com

        Get all Jobs from server 'VBR01.corp.customer.com'
        This methods require Veeam Management console / PowerShell module installed locally on the probe system

    .EXAMPLE
        PS C:\> Get-VeeamJobStatus.ps1 -ComputerName VBR01.corp.customer.com -PSRemote

        Get all Jobs from server 'VBR01.corp.customer.com' with the use of PSRemoting to server VBR01 and query Veeam information "locally".
        This one can execute, without installed Veeam Management console / PowerShell module on the probe system

    .EXAMPLE
        PS C:\> Get-VeeamJobStatus.ps1 -ComputerName VBR01.corp.customer.com -Filter *Backup* -PSRemote

        Get only Jobs where 'backup' is in the JobName from server 'VBR01.corp.customer.com' through PSRemoting.
        This one can execute, without installed Veeam Management console / PowerShell module on the probe system

    .Notes
        Get-VeeamJobStatus
        Author: Andreas Bellstedt
        LASTEDIT: 2022/11/20
        VERSION: 1.1.2
        KEYWORDS: Veeam, PRTG


        Derived from:
            NAME:  PRTG-VeeamBRStats.ps1
            CREDITS:
            Thanks to Shawn, for creating an awsome Reporting Script:
            http://blog.smasterson.com/2016/02/16/veeam-v9-my-veeam-report-v9-0-1/

            Thanks to Bernd Leinfelder for the Scalout Repository part!
            https://github.com/berndleinfelder

            Thanks to Guy Zuercher for the Endpoint Backup part and a lot of other enhancmeents!
            https://github.com/gzuercher

    .LINK
        https://github.com/AndiBellstedt
#>
#Requires -Version 3
[cmdletbinding()]
param(
    [Alias("BRHost")]
    [string]
    $ComputerName = (.{ if ($env:prtg_host) { $env:prtg_host } else { $env:COMPUTERNAME } }),

    [Alias("JobName", "Job")]
    [string[]]
    $Filter,

    [string]
    $ValueLookup = "veeam.job.status",

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

    #Write-Error $_.ToString()
    #Write-Error $_.ScriptStackTrace

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
    Import-PSSession -Session $RemoteSession -Module Veeam.Backup.PowerShell -CommandName "Disconnect-VBRServer", "Connect-VBRServer", "Get-VBRJob", "Get-VBRTapeJob" -ErrorAction Stop -Verbose:$false | Out-Null
} else {
    try {
        Import-Module Veeam.Backup.PowerShell -Verbose:$false -ErrorAction Stop
    } catch {
        throw "Failed to load VeeamPSSnapIn"
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
# Query jobs
[array]$jobs = @()
if ($usePSRemote) {
    $jobs += Invoke-Command -Session $RemoteSession -ErrorAction Stop -Verbose:$false -ScriptBlock {
        Get-VBRJob -WarningAction SilentlyContinue | Sort-Object Name | Select-Object Name, Id, @{n = "LatestStatus"; e = { $_.Info.LatestStatus.ToString() } }
    }
    $jobs = Invoke-Command -Session $RemoteSession -ErrorAction Stop -Verbose:$false -ScriptBlock {
        Get-VBRJob -WarningAction SilentlyContinue | Sort-Object Name | Select-Object Name, Id, @{n = "LatestStatus"; e = { $_.Info.LatestStatus.ToString() } }
    }

} else {
    $jobs += Get-VBRJob -WarningAction SilentlyContinue | Sort-Object Name | Select-Object Name, Id, @{n = "LatestStatus"; e = { $_.Info.LatestStatus.ToString() } }
    $jobs += Get-VBRTapeJob -WarningAction SilentlyContinue | Sort-Object Name | Select-Object Name, Id, @{n = "LatestStatus"; e = { $_.LastResult.ToString() } }
}


# Filter Jobs
if ($Filter -and $jobs) {
    $filterResult = ""
    $filterResult = foreach ($filterItem in $Filter) {
        $jobs | Where-Object Name -like $filterItem
    }
    $jobs = $filterResult | Sort-Object Name, id -Unique
}

# Build PRTG result
"<prtg>"

foreach ($job in $jobs) {
    switch ($job.LatestStatus) {
        'Success' { $jobStatus = 4 }
        'None' { $jobStatus = 3 }    # aka "running" or "never runs"
        'Warning' { $jobStatus = 2 }
        'Failed' { $jobStatus = 1 }
        Default { $jobStatus = 0 }
    }

    # Output PRTG job channel
    Out-PrtgChannel -Channel $job.Name -Value $jobStatus -ValueLookup $valueLookup -ShowChart -ShowTable
}

"</prtg>"

# kill remoting session
Disconnect-VBRServer -Verbose:$false -ErrorAction Ignore
if ($RemoteSession) { Remove-PSSession -Session $RemoteSession }
#endregion
