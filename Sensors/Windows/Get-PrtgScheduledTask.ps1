<#
    .SYNOPSIS
        PRTG Advanced Sensor - Get-PRTGScheduledTask

    .DESCRIPTION
        Advanced Sensor will report all scheduled tasks. Filter out the system-tasks created by the OS,
        report back if all tasks run successfully, or which task fails.

    .PARAMETER Computername
        Machine to query
        Local machine is deault

    .PARAMETER IgnoreTask
        Filtered out tasks

    .PARAMETER IgnoreStatus
        task status to be ignored
        There are some default-task-status-replys which will always be ignored

    .PARAMETER PSRemote
        Text bool if PowerShell remoting is used (="true"), or RPC remoting with COM objects (="false") is used
        Value has to be a TEXT, not a $true/$false

        Default is "true"

    .PARAMETER Credential
        Credential object to connect to remote computer

        Only applies if PSRemote is "TRUE"

    .EXAMPLE
        PS C:\> Get-PRTGScheduledTask.ps1

        Query all tasks of the local system

    .EXAMPLE
        PS C:\> Get-PRTGScheduledTask.ps1 -ComputerName srv.corp.customer.com

        Query all tasks from server 'srv.corp.customer.com'

    .EXAMPLE
        PS C:\> Get-PRTGScheduledTask.ps1 -ComputerName srv.corp.customer.com -IgnoreTask "MyUpdate*"

        Query all tasks except 'MyUpdate*' from remote server

    .EXAMPLE
        PS C:\> Get-PRTGScheduledTask.ps1 -ComputerName srv.corp.customer.com -IgnoreStatus "0x555"

        Query all tasks except 'MyUpdate*' from remote server

    .NOTES
        Author       : Andreas Bellstedt
        Last Modified: 21.01.2023
        Version      : 4.0.0

    .LINK
        https://github.com/AndiBellstedt

#>
#Requires -Version 5.0
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
[CmdletBinding(
    ConfirmImpact = "Low",
    PositionalBinding = $true
)]
Param (
    [parameter(
        ValueFromPipelineByPropertyName = $true,
        ValueFromPipeline = $true
    )]
    [ValidateNotNullOrEmpty()]
    [Alias("Server", "Machine", "Hostname", "Host")]
    [string]
    $ComputerName = $env:prtg_host,

    [string[]]
    $IgnoreTask = "CreateExplorerShellUnelevatedTask",

    [string[]]
    $IgnoreStatus,

    [pscredential]
    $Credential = (.{ if ($env:prtg_windowsuser -and $env:prtg_windowspassword) { [pscredential]::new( "$(if($env:prtg_windowsdomain){ "$($env:prtg_windowsdomain)\"})$($env:prtg_windowsuser)", $("$($env:prtg_windowspassword)" | ConvertTo-SecureString -AsPlainText -Force)) } }),

    [ValidateSet("true", "false")]
    [string]
    $PSRemote = "true"
)



#region helper functions

# Set error handling
trap {
    # Catch all unhadled errors and close Pssession to avoid this issue:
    # Thanks for https://github.com/klmj for the idea
    # http://www.checkyourlogs.net/?p=54583

    #Write-Error $_.ToString()
    #Write-Error $_.ScriptStackTrace

    Write-Output "<prtg>"
    Write-Output " <error>1</error>"
    Write-Output " <text>$($_.ToString())</text>"
    Write-Output "</prtg>"

    exit 2
}


function Out-PrtgChannel {
    [CmdletBinding()]
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

function Get-OLEDate($date) {
    # Returns a date if greater than 12/30/1899 00:00; otherwise, returns nothing
    if ($date -gt [DateTime] "12/30/1899") { $date }
}


function ConvertTo-VersionStr([Int] $version) {
    # Returns a version number as a string (x.y); e.g. 65537 (10001 hex) returns "1.1"
    $major = [Math]::Truncate($version / [Math]::Pow(2, 0x10)) -band 0xFFFF
    $minor = $version -band 0xFFFF
    "$($major).$($minor)"
}


function ConvertTo-VersionInt([String] $version) {
    # Returns a string "x.y" as a version number; e.g., "1.3" returns 65539 (10003 hex)
    $parts = $version.Split(".")
    $major = [Int] $parts[0] * [Math]::Pow(2, 0x10)
    $major -bor [Int] $parts[1]
}

function ConvertFrom-TaskCOMObject {
    [CmdletBinding(
        PositionalBinding = $true
    )]
    param (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        $Tasks,

        [bool]
        $OlderVersion
    )

    begin{}

    process {

        foreach ($task in $Tasks) {
            # Assume root tasks folder (\) if task folders supported
            $taskDefinition = $task.Definition

            $actionCount = 0

            foreach ($action in $taskDefinition.Actions) {

                $actionCount += 1

                if ($OlderVersion) {
                    $taskName = $task.Path
                } else {
                    $taskName = $task.Name
                }

                # Old platforms return null for the Type property
                if ((-not $action.Type) -or ($action.Type -eq 0)) {
                    $actionType = $ACTION_TYPE[0]
                    $action = "$($action.Path) $($action.Arguments)"
                } else {
                    $actionType = $ACTION_TYPE[$action.Type]
                    $action = $NULL
                }

                if ($task.LastTaskResult) {
                    # If negative, convert to DWORD (UInt32)
                    if ($task.LastTaskResult -lt 0) {
                        $lastTaskResult = "0x{0:X}" -f [UInt32] ($task.LastTaskResult + [Math]::Pow(2, 32))
                    } else {
                        $lastTaskResult = "0x{0:X}" -f $task.LastTaskResult
                    }
                } else {
                    $lastTaskResult = $NULL
                }

                if ($task.State) { $taskState = $TASK_STATE[$task.State] }

                $regInfo = $taskDefinition.RegistrationInfo
                if ($regInfo.Date) { $creationDate = [DateTime]::Parse($regInfo.Date) }
                $principal = $taskDefinition.Principal
                if ($OlderVersion) { if ($principal.RunLevel -eq 1) { $elevated = $TRUE } else { $elevated = $FALSE } }

                $output = [PSCustomObject]@{
                    "ComputerName"   = $computerName
                    "ServiceVersion" = $serviceVersion
                    "TaskName"       = $taskName
                    "Enabled"        = ([Boolean] $task.Enabled)
                    "ActionNumber"   = $actionCount
                    "ActionType"     = $actionType
                    "Action"         = $action
                    "LastRunTime"    = (Get-OLEDate $task.LastRunTime)
                    "LastResult"     = $lastTaskResult
                    "NextRunTime"    = (Get-OLEDate $task.NextRunTime)
                    "State"          = $taskState
                    "Author"         = $regInfo.Author
                    "Created"        = $creationDate
                    "RunAs"          = $principal.UserId
                    "Elevated"       = $elevated
                }

                $output
            }
        }
    }

    end{}
}


$scriptblockGetTasks = [System.Management.Automation.ScriptBlock]::Create(@'
    param(
        $ComputerName = $args[0]
    )

    function Get-Task {
        [CmdletBinding()]
        param(
            $TaskFolder
        )

        if ($TaskFolder) {
            $tasks = $TaskFolder.GetTasks(1)

            # Output tasks
            $tasks | foreach-object { $_ }

            # Get subfolders
            $taskFolders = $TaskFolder.GetFolders(0)
            $taskFolders | foreach-object { Get-Task -TaskFolder $_ }
        }
    }

    $taskService = New-Object -com("Schedule.Service")
    try { $taskService.connect($ComputerName) } catch { throw "unable to connect to $ComputerName. $($_)" }
    Get-Task $taskService.GetFolder("\")
'@)


$scriptblockGetVersion = [System.Management.Automation.ScriptBlock]::Create(@'
    param(
        $ComputerName = $args[0]
    )

    $taskService = New-Object -com("Schedule.Service")
    $taskService.HighestVersion
'@)

#endregion helper functions



#region VARIABLES
$MIN_SCHEDULER_VERSION = "1.2"
$TASK_STATE = @{0 = "Unknown"; 1 = "Disabled"; 2 = "Queued"; 3 = "Ready"; 4 = "Running" }
$ACTION_TYPE = @{0 = "Execute"; 5 = "COMhandler"; 6 = "Email"; 7 = "ShowMessage" }

$msgText = ""
$failcountCount = 0
#endregion VARIABLES



#region Script
# create temporary console and set set output encoding - https://kb.paessler.com/en/topic/64817-how-can-i-show-special-characters-with-exe-script-sensors
ping localhost -n 1 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

if (-not $ComputerName) { throw "No computer specified. Not going to return local tasks of $($env:COMPUTERNAME)" }

# Connect to system and get all scheduled tasks in all folders
Write-Verbose "Connect to server $($ComputerName)"
if ($PSRemote) {
    $invokeParam = @{
        "ComputerName" = $ComputerName
        "ScriptBlock"  = $scriptblockGetVersion
        "ErrorAction"  = Stop
    }
    if ($Credential) { $invokeParam.Add("Credential", $Credential) }
    $taskServiceVersion = Invoke-Command @invokeParam

    $serviceVersion = ConvertTo-VersionStr $taskServiceVersion
    $isVistaOrNewer = (ConvertTo-VersionInt $serviceVersion) -ge (ConvertTo-VersionInt $MIN_SCHEDULER_VERSION)

    $invokeParam['ScriptBlock'] = $scriptblockGetTasks
    $allScheduledTasks= Invoke-Command @invokeParam | ConvertFrom-TaskCOMObject -OlderVersion $isVistaOrNewer

} else {
    $taskServiceVersion = $taskService.HighestVersion
    $serviceVersion = ConvertTo-VersionStr $taskServiceVersion
    $isVistaOrNewer = (ConvertTo-VersionInt $serviceVersion) -ge (ConvertTo-VersionInt $MIN_SCHEDULER_VERSION)

    $allScheduledTasks = . $scriptblock -ComputerName $ComputerName | ConvertFrom-TaskCOMObject -OlderVersion $isVistaOrNewer
}


if ($allScheduledTasks) {

    Write-Verbose "Filtering out operatingsystem default tasks"
    [array]$filterScheduledTasks = $allScheduledTasks | Where-Object {
        $_.Author -ne "Microsoft" -and
        $_.Author -ne "Microsoft Corporation" -and
        $_.taskname -notlike '\Microsoft\Windows\Time Zone\SynchronizeTimeZone' -and
        $_.taskname -notlike '\CreateExplorerShellUnelevatedTask' -and
        $_.taskname -notlike '\User_Feed_Synchronization-*' -and
        $_.ActionType -notlike "COMhandler" -and
        $_.Author -notlike "" -and
        $_.Enabled -eq $true -and
        $_.LastRunTime -notlike "" -and
        $_.LastResult -notlike "0x41301" -and # Task is currently running.
        $_.LastResult -notlike "0x41303" -and # Task has not yet run.
        $_.LastResult -notlike "0x41325" -and # Task is queued
        #$_.LastResult -notlike "0x80070420" -and
        #$_.LastResult -notlike "0x800710E0" -and # The operator or administrator has refused the request
        $_.LastResult -notlike "0x420" # An instance of the service is already running ( http://msdn.microsoft.com/en-us/library/windows/desktop/ms681383(v=vs.85).aspx )
    }
    <#
        Filter out Microsoft-System-Tasks
        0 or 0x0: The operation completed successfully.
        1 or 0x1: Incorrect function called or unknown function called.
        2 or 0x2: File not found.
        10 or 0xa: The environment is incorrect.
        0x41300: Task is ready to run at its next scheduled time.
        0x41302: Task is disabled.
        0x41304: There are no more runs scheduled for this task.
        0x41306: Task is terminated.
        0x8004130F: Credentials became corrupted (*)  ( http://msdn.microsoft.com/en-us/library/aa383604%28VS.85%29.aspx )
        0x8004131F: An instance of this task is already running.
        0x800704DD: The service is not available (is 'Run only when an user is logged on' checked?)
        0xC000013A: The application terminated as a result of a CTRL+C.
        0xC06D007E: Unknown software exception.
    #>


    if ($IgnoreTask) {
        Write-Verbose "Filtering out ignored tasks"
        foreach ($IgnoredTask in $IgnoreTask) {
            [array]$filterScheduledTasks = $filterScheduledTasks | Where-Object { $_.TaskName -notlike $IgnoredTask }
            [array]$filterScheduledTasks = $filterScheduledTasks | Where-Object { $_.TaskName -notlike $('\' + $IgnoredTask) } #assuring when people do not recognize the starting backslash for the Taskname
        }
    }


    if ($IgnoreStatus) {
        Write-Verbose "Filtering out ignored status"
        foreach ($IgnoredStatus in $IgnoreStatus) {
            [array]$filterScheduledTasks = $filterScheduledTasks | Where-Object { $_.LastResult -notlike $IgnoredStatus }
        }
    }


    if ($filterScheduledTasks.Count -gt 0) {
        Write-Verbose "Parsing $($filterScheduledTasks.Count) tasks"

        foreach ($task in $filterScheduledTasks) {
            if ([string]$task.LastResult -ne "") {
                Write-Verbose "Working on failed task: $($task.TaskName.tostring()) with status $($task.LastResult) and last runtime $($task.LastRunTime)"

                if ($failcountCount -ge 1) { $msgText += " & " }
                $msgText += "$( $task.TaskName.tostring() ) (Status:$($task.LastResult))"

                $failcountCount++
            }
        }
        if ($failcountCount -gt 0) {
            Write-Verbose "Building message text for error output"

            if ($msgText.EndsWith(" & ")) { $msgText = $msgText.Substring(0, $msgText.Length - 3) }
            $msgText = "$failcountCount Task(s) failed: $msgText"

            Write-Verbose "$msgText"
        }
    } else {
        $msgText = "OK, all tasks completed successfull"
        Write-Verbose "$msgText"
    }


    #region Create output object
    Write-Verbose "Preparing PRTG channel output data"

    $XMLOutput = '<?xml version="1.0" encoding="UTF-8" ?>'
    $XMLOutput += '<prtg>'

    # First Channel
    $ChannelName = "Number of tasks in system"
    Write-Verbose "$($ChannelName): $($allScheduledTasks.count)"
    $XMLOutput += Out-PrtgChannel -Channel $ChannelName -Value $allScheduledTasks.count -Unit Count -ShowChart

    # Second Channel
    $ChannelName = "Gathered tasks by sensor"
    If ($NULL -eq $filterScheduledTasks) {
        Write-Verbose "$($ChannelName): 0"
        $XMLOutput += Out-PrtgChannel -Channel $ChannelName -Value 0 -Unit Count -ShowChart
    } else {
        Write-Verbose "$($ChannelName): $($filterScheduledTasks.count)"
        $XMLOutput += Out-PrtgChannel -Channel $ChannelName -Value $filterScheduledTasks.count -Unit Count -ShowChart
    }

    # Third Channel
    $ChannelName = "Failed tasks"
    Write-Verbose "$($ChannelName): $($failcountCount)"
    $XMLOutput += Out-PrtgChannel -Channel $ChannelName -Value $failcountCount -Unit Count -ShowChart -MaxError 0.5 -ErrorMsg "Error occured. There are failing scheduled tasks on the machine"

    $XMLOutput += "<text>" + $msgText + "</text>`n"
    $XMLOutput += "</prtg>"

    #endregion Create output object
} else {
    throw "No tasks found"
}

# Final output
$XMLOutput


#endregion
