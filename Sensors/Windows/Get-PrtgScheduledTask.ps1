<#
    .SYNOPSIS
        PRTG Advanced Sensor - Get-PRTGScheduledTask

    .DESCRIPTION
        Advanced Sensor will report all scheduled tasks. Filter out the system-tasks created by the OS,
        report back if all tasks run successfully, or which task fails.

    .NOTES
        Author       : Andreas Bellstedt
        Last Modified: 06.11.2022
        Version      : 3.0.0

    .LINK
        https://github.com/AndiBellstedt

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

    .PARAMETER Computername
        Machine to query
        Local machine is deault

    .PARAMETER IgnoreTask
        Filtered out tasks

    .PARAMETER IgnoreStatus
        task status to be ignored
        There are some default-task-status-replys which will always be ignored

#>
#Requires -Version 3.0
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
    [Alias("Machine", "Hostname", "host")]
    [string]
    $ComputerName = "svw-hq1-task01",

    [string[]]
    $IgnoreTask = "CreateExplorerShellUnelevatedTask",

    [string[]]
    $IgnoreStatus
)


#region Prepare
$logScope = "[PREPARE                ]"



#region Constants
$logScopeMaxlength = 23
$logScope = "[PREP_CONSTANTS         ]"
$StatWarning = "[WARNING]"
$StatInfo = "[INFO   ]"
$StatQuery = "[QUERY  ]"
$StatSet = "[SET    ]"
$StatError = "[ERROR  ]"

$MIN_SCHEDULER_VERSION = "1.2"
$TASK_STATE = @{0 = "Unknown"; 1 = "Disabled"; 2 = "Queued"; 3 = "Ready"; 4 = "Running" }
$ACTION_TYPE = @{0 = "Execute"; 5 = "COMhandler"; 6 = "Email"; 7 = "ShowMessage" }

#endregion Vorbereitung - Constanten setzen


#region helper functions
$logScope = "[PREP_HELPER               ]"

function Out-PrtgChannel {
    Param (
        [Parameter(mandatory = $True, Position = 0)]
        [string]$Channel,

        [Parameter(mandatory = $True, Position = 1)]
        $Value,

        [Parameter(mandatory = $True, Position = 2)]
        [string]$Unit,

        [Parameter(mandatory = $False)]
        [alias('mw')]
        [string]$MaxWarn,

        [Parameter(mandatory = $False)]
        [alias('minw')]
        [string]$MinWarn,

        [Parameter(mandatory = $False)]
        [alias('me')]
        [string]$MaxError,

        [Parameter(mandatory = $False)]
        [alias('wm')]
        [string]$WarnMsg,

        [Parameter(mandatory = $False)]
        [alias('em')]
        [string]$ErrorMsg,

        [Parameter(mandatory = $False)]
        [alias('mo')]
        [string]$Mode,

        [Parameter(mandatory = $False)]
        [alias('sc')]
        [switch]$ShowChart,

        [Parameter(mandatory = $False)]
        [alias('ss')]
        [ValidateSet("One", "Kilo", "Mega", "Giga", "Tera", "Byte", "KiloByte", "MegaByte", "GigaByte", "TeraByte", "Bit", "KiloBit", "MegaBit", "GigaBit", "TeraBit")]
        [string]$SpeedSize,

        [Parameter(mandatory = $False)]
        [ValidateSet("One", "Kilo", "Mega", "Giga", "Tera", "Byte", "KiloByte", "MegaByte", "GigaByte", "TeraByte", "Bit", "KiloBit", "MegaBit", "GigaBit", "TeraBit")]
        [string]$VolumeSize,

        [Parameter(mandatory = $False)]
        [alias('dm')]
        [ValidateSet("Auto", "All")]
        [string]$DecimalMode,

        [Parameter(mandatory = $False)]
        [alias('w')]
        [switch]$Warning,

        [Parameter(mandatory = $False)]
        [string]$ValueLookup
    )
    $logScope = Set-LogScope "F_Out-PrtgChannel"

    $StandardUnits = @("BytesBandwidth", "BytesMemory", "BytesDisk", "Temperature", "Percent", "TimeResponse", "TimeSeconds", "Custom", "Count", "CPU", "BytesFile", "SpeedDisk", "SpeedNet", "TimeHours")
    $LimitMode = $false

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
    if ($MaxError) { $Result += "    <limitminwarning>$MinWarn</limitminwarning>`n"; $LimitMode = $true }
    if ($MaxError) { $Result += "    <limitmaxerror>$MaxError</limitmaxerror>`n"; $LimitMode = $true }
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

    return $Result
}


function Set-LogScope {
    <#
    .Synopsis
        Set-LogScope / LogScope

    .DESCRIPTION
        Put a Name in string with square brackets with a defined length. Intended for structural logging.

    .EXAMPLE
        Set-LogScope -Name "BEGIN" -Length 10
        Set-LogScope -Name "BEGIN"
    .EXAMPLE
        Set-LogScope "BEGIN" 10
        Set-LogScope "BEGIN"

    #>
    [CmdletBinding(DefaultParameterSetName = '', ConfirmImpact = "Low")]
    [Alias('LogScope')]
    [OutputType([String])]
    Param(
        [parameter( Mandatory = $true,
            Position = 0)]
        [string]$Name,

        [parameter( Mandatory = $false,
            Position = 1)]
        [int]$Length = (.{ if ($logScopeMaxlength) { $logScopeMaxlength }else { 10 } })
    )
    $logScope = "[FUNCTION_SET-LOGSCOPE]"

    if ($Name.Length -gt $Length) {
        Write-Warning "$logScope $($Name) is to long ($($Name.Length)) for maximum logscopelength ($($Length))!"
        $Name = $Name.Substring(0, $Length)
    }

    $return = "[$($Name)$()"
    for ($i = 1; $i -le ($Length - $Name.Length); $i++) {
        $return += " "
    }
    $return += "]"
    Write-Output $return
}


function Write-Log {
    <#
    .Synopsis
        Write-Log / Log
        Logs text to the console and/or to a file.

    .DESCRIPTION
        A comprehensive helper function for structured logging.
        Writes one or more messages to the different available outputchannels of the powershell and to one or more logfiles.

    .NOTES
        Version: 2.1
        Author:  Andreas Bellstedt
    #>
    [CmdletBinding(DefaultParameterSetName = 'VerboseOutput', ConfirmImpact = "Low")]
    [Alias('Log')]
    Param(
        #The Textmessage to be logged
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true
        )]
        [string]
        $LogText,

        #The name of the logfile(s) where the message should be logged
        [string[]]
        $LogFile,

        #Suppress the timestamp in the logged output
        [switch]
        $NoTimeStamp,

        #Suppress the info, wether the logged output is written to file or only displayed in the outputchannel
        [switch]
        $NoFileStatus,

        #Specifies that LogText is displayed as text in the debug-channel, not in the verbose-channel
        [Parameter(ParameterSetName = 'DebugOutput' )]
        [switch]
        $DebugOutput,

        #Specifies that LogText is displayed as text in the console window, not in the verbose-channel
        [Parameter(ParameterSetName = 'ConsoleOutput' )]
        [Alias('Visible')]
        [switch]
        $Console,

        #Specifies that LogText is displayed as (red) error message in the console window, not in the verbose-channel
        [Parameter(ParameterSetName = 'ErrorOutput' )]
        [switch]
        $ErrorOutput,

        #Logs the LogText as warrning message to the console
        [parameter(ParameterSetName = 'VerboseOutput' )]
        [parameter(ParameterSetName = 'DebugOutput' )]
        [parameter(ParameterSetName = 'ConsoleOutput' )]
        [switch]
        $Warning
    )
    Begin {
        if ($NoFileStatus) { $status = '' } else { $status = "[NOFILE] " }
        #turn of confimation for debug actions
        If ($PSBoundParameters['Debug'] -or ($PsCmdlet.ParameterSetName -eq 'DebugOutput')) { $DebugPreference = 'Continue' }
    }
    Process {
        if ($NoTimeStamp) { $logDate = '' } else { $logDate = "[$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")] " }

        if ($LogFile) {
            if ($NoFileStatus) { $status = '' } else { $status = "[FILE  ] " }
            foreach ($File in $LogFile) {
                Write-Output "$($logDate)$($LogText)" | Out-File -FilePath $File -Append
            }
        }

        $message = "$($logDate)$($status)$($LogText)"
        switch ($PsCmdlet.ParameterSetName) {
            'VerboseOutput' { if ($Warning) { write-warning $message } else { write-verbose $message } }
            'DebugOutput' { if ($Warning) { Write-Debug   "WARNING: $message" } else { Write-Debug   $message } }
            'ConsoleOutput' { if ($Warning) { Write-Host    "WARNING: $message" -ForegroundColor $Host.PrivateData.WarningForegroundColor -BackgroundColor $Host.PrivateData.WarningBackgroundColor }else { Write-Host $message } }
            'ErrorOutput' { Write-error   "$logDate $status $LogText" }
        }
    }
    End {
        Remove-Variable message, logDate, status
    }
}


#endregion Vorbereitung


#region script functions
$logScope = Set-LogScope "PREP_SCRIPTFUNCTIONS"


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

function get-task($taskFolder) {
    #Abfrage, um Endlosschleifen zu verhindern
    if ($taskFolder -ne $Null) {
        $tasks = $taskFolder.GetTasks(1)
        $tasks | foreach-object { $_ }
        $taskFolders = $taskFolder.GetFolders(0)
        $taskFolders | foreach-object { get-task $_ $TRUE }
    }
}


function get-OLEdate($date) {
    # Returns a date if greater than 12/30/1899 00:00; otherwise, returns nothing
    if ($date -gt [DateTime] "12/30/1899") { $date }
}


function convertto-versionstr([Int] $version) {
    # Returns a version number as a string (x.y); e.g. 65537 (10001 hex) returns "1.1"
    $major = [Math]::Truncate($version / [Math]::Pow(2, 0x10)) -band 0xFFFF
    $minor = $version -band 0xFFFF
    "$($major).$($minor)"
}


function convertto-versionint([String] $version) {
    # Returns a string "x.y" as a version number; e.g., "1.3" returns 65539 (10003 hex)
    $parts = $version.Split(".")
    $major = [Int] $parts[0] * [Math]::Pow(2, 0x10)
    $major -bor [Int] $parts[1]
}


function get-ComputerScheduledTasks($computerName) {

    try {
        Write-Log -LogText "$logScope $StatInfo Trying to Connect to Server $ComputerName ." -NoFileStatus
        $TaskService.connect($ComputerName)
    } catch {
        $Global:ErrorMessage = $_.Exception.Message
        Write-Log -LogText "$logScope $StatInfo Connection failed: $Global:ErrorMessage " -NoFileStatus
        $Global:ConnectionSuccessfull = $FALSE
    }

    # Execute if Connection was successful
    if ($Global:ConnectionSuccessfull) {
        Write-Log -LogText "$logScope $StatInfo Connection successfully established" -NoFileStatus

        $serviceVersion = convertto-versionstr $TaskService.HighestVersion
        $vistaOrNewer = (convertto-versionint $serviceVersion) -ge (convertto-versionint $MIN_SCHEDULER_VERSION)
        $rootFolder = $TaskService.GetFolder("\")

        # Get all scheduled Tasks in all Folders
        $taskList = get-task $rootFolder

        if ($taskList.count -gt 0 ) {
            foreach ($task in $taskList) {
                # Assume root tasks folder (\) if task folders supported
                $taskDefinition = $task.Definition
                $actionCount = 0
                foreach ($action in $taskDefinition.Actions) {
                    $actionCount += 1
                    $output = new-object PSObject
                    # PROPERTY: ComputerName
                    $output | add-member NoteProperty ComputerName $computerName
                    # PROPERTY: ServiceVersion
                    $output | add-member NoteProperty ServiceVersion $serviceVersion
                    # PROPERTY: TaskName
                    if ($vistaOrNewer) {
                        $output | add-member NoteProperty TaskName $task.Path
                    } else {
                        $output | add-member NoteProperty TaskName $task.Name
                    }
                    #PROPERTY: Enabled
                    $output | add-member NoteProperty Enabled ([Boolean] $task.Enabled)
                    # PROPERTY: ActionNumber
                    $output | add-member NoteProperty ActionNumber $actionCount
                    # PROPERTIES: ActionType and Action
                    # Old platforms return null for the Type property
                    if ((-not $action.Type) -or ($action.Type -eq 0)) {
                        $output | add-member NoteProperty ActionType $ACTION_TYPE[0]
                        $output | add-member NoteProperty Action "$($action.Path) $($action.Arguments)"
                    } else {
                        $output | add-member NoteProperty ActionType $ACTION_TYPE[$action.Type]
                        $output | add-member NoteProperty Action $NULL
                    }
                    # PROPERTY: LastRunTime
                    $output | add-member NoteProperty LastRunTime (get-OLEdate $task.LastRunTime)
                    # PROPERTY: LastResult
                    if ($task.LastTaskResult) {
                        # If negative, convert to DWORD (UInt32)
                        if ($task.LastTaskResult -lt 0) {
                            $lastTaskResult = "0x{0:X}" -f [UInt32] ($task.LastTaskResult + [Math]::Pow(2, 32))
                        } else {
                            $lastTaskResult = "0x{0:X}" -f $task.LastTaskResult
                        }
                    } else {
                        $lastTaskResult = $NULL  # fix bug in v1.0-1.1 (should output $NULL)
                    }
                    $output | add-member NoteProperty LastResult $lastTaskResult
                    # PROPERTY: NextRunTime
                    $output | add-member NoteProperty NextRunTime (get-OLEdate $task.NextRunTime)
                    # PROPERTY: State
                    if ($task.State) {
                        $taskState = $TASK_STATE[$task.State]
                    }
                    $output | add-member NoteProperty State $taskState
                    $regInfo = $taskDefinition.RegistrationInfo
                    # PROPERTY: Author
                    $output | add-member NoteProperty Author $regInfo.Author
                    # The RegistrationInfo object's Date property, if set, is a string
                    if ($regInfo.Date) {
                        $creationDate = [DateTime]::Parse($regInfo.Date)
                    }
                    $output | add-member NoteProperty Created $creationDate
                    # PROPERTY: RunAs
                    $principal = $taskDefinition.Principal
                    $output | add-member NoteProperty RunAs $principal.UserId
                    # PROPERTY: Elevated
                    if ($vistaOrNewer) {
                        if ($principal.RunLevel -eq 1) { $elevated = $TRUE } else { $elevated = $FALSE }
                    }
                    $output | add-member NoteProperty Elevated $elevated
                    # Output the object
                    $output
                }
            }
        }
    } else {
        # Output the object in case of Connection Error
        $null
    }
}


#endregion script functions


#region VARIABLES
$logScope = "[VARIABLES]"

$MsgText = ""
$FailcountCount = 0
$TaskService = new-object -com("Schedule.Service")

# create temporary console and set set output encoding - https://kb.paessler.com/en/topic/64817-how-can-i-show-special-characters-with-exe-script-sensors
ping localhost -n 1 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$XMLOutput = '<?xml version="1.0" encoding="UTF-8" ?>'
$XMLOutput += '<prtg>'
$Global:ConnectionSuccessfull = $true
$Global:ErrorMessage = ""

#endregion VARIABLES
#endregion Prepare



#region Script
$logScope = Set-LogScope "SCRIPT"

Write-Log -LogText "$logScope $StatQuery Getting Tasks from $ComputerName" -NoFileStatus
$AllScheduledTasks = get-ComputerScheduledTasks($ComputerName)

# Execute if Connection was successful
if ($Global:ConnectionSuccessfull) {
    Write-Log -LogText "$logScope $StatInfo Filtering out operatingsystem default tasks" -NoFileStatus
    [array]$FilterScheduledTasks = $AllScheduledTasks | Where-Object { $_.Author -ne "Microsoft" -and $_.Author -ne "Microsoft Corporation" -and $_.taskname -notlike '\Microsoft\Windows\Time Zone\SynchronizeTimeZone' -and $_.taskname -notlike '\CreateExplorerShellUnelevatedTask' -and $_.taskname -notlike '\User_Feed_Synchronization-*' -and $_.Author -notlike "" -and $_.Enabled -eq $true -and $_.LastRunTime -notlike "" -and $_.LastResult -notlike "0x41301" -and $_.LastResult -notlike "0x41303" -and $_.LastResult -notlike "0x41325" -and $_.LastResult -notlike "0x80070420" -and $_.LastResult -notlike "0x420" -and $_.ActionType -notlike "COMhandler"}
    <#
        Filter out Microsoft-System-Tasks
        0 or 0x0: The operation completed successfully.
        1 or 0x1: Incorrect function called or unknown function called.
        2 or 0x2: File not found.
        10 or 0xa: The environment is incorrect.
        0x420 - 1056 - An instance of the service is already running ( http://msdn.microsoft.com/en-us/library/windows/desktop/ms681383(v=vs.85).aspx )
        0x41300: Task is ready to run at its next scheduled time.
        0x41301: Task is currently running.
        0x41325: Task is queued
        0x41302: Task is disabled.
        0x41303: Task has not yet run.
        0x41304: There are no more runs scheduled for this task.
        0x41306: Task is terminated.
        0x8004130F: Credentials became corrupted (*)  ( http://msdn.microsoft.com/en-us/library/aa383604%28VS.85%29.aspx )
        0x8004131F: An instance of this task is already running.
        0x800704DD: The service is not available (is 'Run only when an user is logged on' checked?)
        0xC000013A: The application terminated as a result of a CTRL+C.
        0xC06D007E: Unknown software exception.
    #>

    if ($IgnoreTask) {
        Write-Log -LogText "$logScope $StatInfo Filtering out ignored tasks" -NoFileStatus
        foreach ($IgnoredTask in $IgnoreTask) {
            [array]$FilterScheduledTasks = $FilterScheduledTasks | Where-Object { $_.TaskName -notlike $IgnoredTask }
            [array]$FilterScheduledTasks = $FilterScheduledTasks | Where-Object { $_.TaskName -notlike $('\' + $IgnoredTask) } #assuring when people do not recognize the starting backslash for the Taskname
        }
    }

    if ($IgnoreStatus) {
        Write-Log -LogText "$logScope $StatInfo Filtering out ignored status" -NoFileStatus
        foreach ($IgnoredStatus in $IgnoreStatus) {
            [array]$FilterScheduledTasks = $FilterScheduledTasks | Where-Object { $_.LastResult -notlike $IgnoredStatus }
        }
    }


    if ($FilterScheduledTasks.Count -gt 0) {
        Write-Log -LogText "$logScope $StatInfo Parsing $($FilterScheduledTasks.Count) tasks" -NoFileStatus

        foreach ($Task in $FilterScheduledTasks) {
            if ([string]$Task.LastResult -ne "") {
                Write-Log -LogText "$logScope $StatWarning Working on failed task: $($Task.TaskName.tostring()) with status $($Task.LastResult) and last runtime $($task.LastRunTime)" -NoFileStatus

                if ($FailcountCount -ge 1) { $MsgText += " & " }
                $MsgText += "$( $Task.TaskName.tostring() ) (Status:$($Task.LastResult))"

                $FailcountCount++
            }
        }
        if ($FailcountCount -gt 0) {
            Write-Log -LogText "$logScope $StatInfo Building message text for error output" -NoFileStatus

            if ($MsgText.EndsWith(" & ")) { $MsgText = $MsgText.Substring(0, $MsgText.Length - 3) }
            $MsgText = "$FailcountCount Task(s) failed: $MsgText"

            Write-Log -LogText "$logScope $StatInfo $MsgText" -NoFileStatus
        }
    } else {
        $MsgText = "OK, all tasks completed successfull"
        Write-Log -LogText "$logScope $StatInfo $MsgText" -NoFileStatus
    }

    Write-Log -LogText "$logScope $StatInfo Preparing PRTG channel output data" -NoFileStatus
    if ($AllScheduledTasks) {
        $ChannelName = "Number of tasks in system"
        Write-Log -LogText "$logScope $StatInfo $($ChannelName): $($AllScheduledTasks.count)" -NoFileStatus
        $XMLOutput += Out-PrtgChannel -Channel $ChannelName -Value $AllScheduledTasks.count -Unit Count -ShowChart

        $ChannelName = "Gathered tasks by sensor"
        If ($Null -eq $FilterScheduledTasks) {
            Write-Log -LogText "$logScope $StatInfo $($ChannelName): 0" -NoFileStatus
            $XMLOutput += Out-PrtgChannel -Channel $ChannelName -Value 0 -Unit Count -ShowChart
        } else {
            Write-Log -LogText "$logScope $StatInfo $($ChannelName): $($FilterScheduledTasks.count)" -NoFileStatus
            $XMLOutput += Out-PrtgChannel -Channel $ChannelName -Value $FilterScheduledTasks.count -Unit Count -ShowChart
        }

        $ChannelName = "Failed tasks"
        Write-Log -LogText "$logScope $StatInfo $($ChannelName): $($FailcountCount)" -NoFileStatus
        $XMLOutput += Out-PrtgChannel -Channel $ChannelName -Value $FailcountCount -Unit Count -ShowChart -MaxError 0.5 -ErrorMsg "Error occured. There are failing scheduled tasks on the machine"

    } else {
        Throw "Error, no tasks found!"
    }
} else {
    Throw "Connection to server failed with error message: $Global:ErrorMessage "
}
$XMLOutput += "<text>" + $MsgText + "</text>`n"
$XMLOutput += "</prtg>"

[Console]::WriteLine($XMLOutput)
Exit 0

#endregion