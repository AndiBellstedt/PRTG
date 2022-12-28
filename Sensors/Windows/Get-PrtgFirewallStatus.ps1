<#
    .SYNOPSIS
        PRTG Advanced Sensor - Windows - Status of Windows Firewall

    .DESCRIPTION
        Advanced Sensor will report status on Windows Firewall

    .PARAMETER ComputerName
        Name of Computer to query

    .PARAMETER FWProfile
        What profile is going to be queried
        Default is "All"
        Possible values "All", "Private", "Domain", "Public"

    .PARAMETER Credential
        Credential to connect to remote system

    .EXAMPLE
        PS C:\> Get-PrtgFirewallStatus.ps1 -ComputerName srv01.corp.customer.com

        Get windows firewall status from server 'srv01.corp.customer.com' and report all profiles as channels

    .EXAMPLE
        PS C:\> Get-PrtgFirewallStatus.ps1 -ComputerName srv01.corp.customer.com -FWProfile "Domain", "Public"

        Get windows firewall status from server 'srv01.corp.customer.com' and report "Domain" and "Public" profiles as channel

    .EXAMPLE
        PS C:\> Get-PrtgFirewallStatus.ps1 -ComputerName srv01.corp.customer.com -Credential $Cred

        Get windows firewall status from server 'srv01.corp.customer.com' and report all profiles as channels
        Connection to exchange will be done with credentials '$Cred'.

    .Notes
        Get-PrtgFirewallStatus
        Author: Andreas Bellstedt
        LASTEDIT: 2022/12/28
        VERSION:  1.0.0
        KEYWORDS: PRTG, Windows, Firewall

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

    [ValidateSet("Private", "Domain", "Public", "All")]
    [string[]]
    $FWProfile = "All",

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

Function Get-RemoteFirewallStatus {
    <#
        .SYNOPSIS
            Retrieves firewall status from remote systems via the registry.

        .DESCRIPTION
            Retrieves firewall status from remote systems via the registry.

        .PARAMETER ComputerName
            Specifies the target computer for data query.

        .PARAMETER ThrottleLimit
            Specifies the maximum number of systems to inventory simultaneously

        .PARAMETER Timeout
            Specifies the maximum time in second command can run in background before terminating this thread.

        .PARAMETER ShowProgress
            Show progress bar information

        .EXAMPLE
            PS > (Get-RemoteFirewallStatus).Rules | where {$_.Active -eq 'TRUE'} | Select Name,Dir

            Description
            -----------
            Displays the name and direction of all active firewall rules defined in the registry of the
            local system.
        .EXAMPLE
            PS > (Get-RemoteFirewallStatus).FirewallEnabled

            Description
            -----------
            Displays the status of the local firewall.
        .NOTES
            Author: Zachary Loeber
            Site: http://www.the-little-things.net/
            Requires: Powershell 2.0

            Version History
            1.0.0 - 10/02/2013 - Initial release
    #>
    [CmdletBinding(PositionalBinding=$true)]
    Param(
        [Parameter(
            HelpMessage = "Computer or computers to gather information from",
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true
        )]
        [ValidateNotNullOrEmpty()]
        [Alias('DNSHostName', 'PSComputerName')]
        [string[]]
        $ComputerName = $env:computername,

        [Parameter(HelpMessage = "Maximum number of concurrent runspaces.")]
        [ValidateRange(1, 65535)]
        [int32]
        $ThrottleLimit = 32,

        [Parameter(HelpMessage = "Timeout before a runspaces stops trying to gather the information.")]
        [ValidateRange(1, 65535)]
        [int32]
        $Timeout = 120,

        [Parameter(HelpMessage = "Display progress of function.")]
        [switch]
        $ShowProgress,

        [Parameter(HelpMessage = "Set this if you want the function to prompt for alternate credentials.")]
        [switch]
        $PromptForCredential,

        [Parameter(HelpMessage = "Set this if you want to provide your own alternate credentials.")]
        [PSCredential]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    Begin {
        # Gather possible local host names and IPs to prevent credential utilization in some cases
        Write-Verbose -Message 'Firewall Information: Creating local hostname list'
        $IPAddresses = [net.dns]::GetHostAddresses($env:COMPUTERNAME) | Select-Object -ExpandProperty IpAddressToString
        $HostNames = $IPAddresses | ForEach-Object {
            try {
                [net.dns]::GetHostByAddress($_)
            } catch {
                # We do not care about errors here...
            }
        } | Select-Object -ExpandProperty HostName -Unique
        $LocalHost = @('', '.', 'localhost', $env:COMPUTERNAME, '::1', '127.0.0.1') + $IPAddresses + $HostNames

        Write-Verbose -Message 'Firewall Information: Creating initial variables'
        $runspacetimers = [HashTable]::Synchronized(@{})
        $runspaces = New-Object -TypeName System.Collections.ArrayList
        $bgRunspaceCounter = 0

        if ($PromptForCredential) {
            $Credential = Get-Credential
        }

        Write-Verbose -Message 'Firewall Information: Creating Initial Session State'
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($ExternalVariable in ('runspacetimers', 'Credential', 'LocalHost')) {
            Write-Verbose -Message "Firewall Information: Adding variable $ExternalVariable to initial session state"
            $iss.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $ExternalVariable, (Get-Variable -Name $ExternalVariable -ValueOnly), ''))
        }

        Write-Verbose -Message 'Firewall Information: Creating runspace pool'
        $rp = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $ThrottleLimit, $iss, $Host)
        $rp.ApartmentState = 'STA'
        $rp.Open()

        # This is the actual code called for each computer
        Write-Verbose -Message 'Firewall Information: Defining background runspaces scriptblock'
        $ScriptBlock = {
            [CmdletBinding()]
            Param
            (
                [Parameter(Position = 0)]
                [string]
                $ComputerName,

                [Parameter()]
                [int]
                $bgRunspaceID
            )
            $runspacetimers.$bgRunspaceID = Get-Date

            try {
                Write-Verbose -Message ('Firewall Information: Runspace {0}: Start' -f $ComputerName)
                $WMIHast = @{
                    ComputerName = $ComputerName
                    ErrorAction  = 'Stop'
                }
                if (($LocalHost -notcontains $ComputerName) -and ($null -ne $Credential)) {
                    $WMIHast.Credential = $Credential
                }
                $FwProtocols = @{
                    1   = "ICMPv4"
                    2   = "IGMP"
                    6   = "TCP"
                    17  = "UDP"
                    41  = "IPv6"
                    43  = "IPv6Route"
                    44  = "IPv6Frag"
                    47  = "GRE"
                    58  = "ICMPv6"
                    59  = "IPv6NoNxt"
                    60  = "IPv6Opts"
                    112 = "VRRP"
                    113 = "PGM"
                    115 = "L2TP"
                }

                #region Firewall Settings
                Write-Verbose -Message ('Firewall Information: Runspace {0}: Gathering registry information' -f $ComputerName)
                $defaultProperties = @('ComputerName', 'FirewallEnabled')
                $HKLM = '2147483650'
                $BasePath = 'System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
                $FW_DomainProfile = "$BasePath\DomainProfile"
                $FW_PublicProfile = "$BasePath\PublicProfile"
                $FW_StandardProfile = "$BasePath\StandardProfile"
                $FW_DomainLogPath = "$($FW_DomainProfile)\Logging"
                $FW_PublicLogPath = "$($FW_PublicProfile)\Logging"
                $FW_StandardLogPath = "$($FW_StandardProfile)\Logging"

                $reg = Get-WmiObject @WMIHast -Class StdRegProv -Namespace 'root\default' -List:$true
                $DomainEnabled = [bool]($reg.GetDwordValue($HKLM, $FW_DomainProfile, "EnableFirewall")).uValue
                $PublicEnabled = [bool]($reg.GetDwordValue($HKLM, $FW_PublicProfile, "EnableFirewall")).uValue
                $StandardEnabled = [bool]($reg.GetDwordValue($HKLM, $FW_StandardProfile, "EnableFirewall")).uValue
                $FirewallEnabled = $false
                $FirewallKeys = @()
                $FirewallKeys += 'System\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules'
                $FirewallKeys += 'Software\Policies\Microsoft\WindowsFirewall\FirewallRules'
                $RuleList = @()

                foreach ($Key in $FirewallKeys) {
                    $FirewallRules = $reg.EnumValues($HKLM, $Key)
                    for ($i = 0; $i -lt $FirewallRules.Types.Count; $i++) {
                        $Rule = ($reg.GetStringValue($HKLM, $Key, $FirewallRules.sNames[$i])).sValue

                        # Prepare hashtable
                        $HashProps = @{
                            NameOfRule  = ($FirewallRules.sNames[$i])
                            RuleVersion = ($Rule -split '\|')[0]
                            Action      = $null
                            Active      = $null
                            Dir         = $null
                            Proto       = $null
                            LPort       = $null
                            App         = $null
                            Name        = $null
                            Desc        = $null
                            EmbedCtxt   = $null
                            Profile     = 'All'
                            RA4         = $null
                            RA6         = $null
                            Svc         = $null
                            RPort       = $null
                            ICMP6       = $null
                            Edge        = $null
                            LA4         = $null
                            LA6         = $null
                            ICMP4       = $null
                            LPort2_10   = $null
                            RPort2_10   = $null
                        }

                        # Determine if this is a local or a group policy rule and display this in the hashtable
                        if ($Key -match 'System\\CurrentControlSet') {
                            $HashProps.RuleType = 'Local'
                        } else {
                            $HashProps.RuleType = 'GPO'
                        }

                        # Iterate through the value of the registry key and fill PSObject with the relevant data
                        foreach ($FireWallRule in ($Rule -split '\|')) {
                            switch (($FireWallRule -split '=')[0]) {
                                'Action' { $HashProps.Action = ($FireWallRule -split '=')[1] }
                                'Active' { $HashProps.Active = ($FireWallRule -split '=')[1] }
                                'Dir' { $HashProps.Dir = ($FireWallRule -split '=')[1] }
                                'Protocol' { $HashProps.Proto = $FwProtocols[[int](($FireWallRule -split '=')[1])] }
                                'LPort' { $HashProps.LPort = ($FireWallRule -split '=')[1] }
                                'App' { $HashProps.App = ($FireWallRule -split '=')[1] }
                                'Name' { $HashProps.Name = ($FireWallRule -split '=')[1] }
                                'Desc' { $HashProps.Desc = ($FireWallRule -split '=')[1] }
                                'EmbedCtxt' { $HashProps.EmbedCtxt = ($FireWallRule -split '=')[1] }
                                'Profile' { $HashProps.Profile = ($FireWallRule -split '=')[1] }
                                'RA4' { [array]$HashProps.RA4 += ($FireWallRule -split '=')[1] }
                                'RA6' { [array]$HashProps.RA6 += ($FireWallRule -split '=')[1] }
                                'Svc' { $HashProps.Svc = ($FireWallRule -split '=')[1] }
                                'RPort' { $HashProps.RPort = ($FireWallRule -split '=')[1] }
                                'ICMP6' { $HashProps.ICMP6 = ($FireWallRule -split '=')[1] }
                                'Edge' { $HashProps.Edge = ($FireWallRule -split '=')[1] }
                                'LA4' { [array]$HashProps.LA4 += ($FireWallRule -split '=')[1] }
                                'LA6' { [array]$HashProps.LA6 += ($FireWallRule -split '=')[1] }
                                'ICMP4' { $HashProps.ICMP4 = ($FireWallRule -split '=')[1] }
                                'LPort2_10' { $HashProps.LPort2_10 = ($FireWallRule -split '=')[1] }
                                'RPort2_10' { $HashProps.RPort2_10 = ($FireWallRule -split '=')[1] }
                                Default {}
                            }
                            if ($HashProps.Name -match '\@') {
                                $HashProps.Name = $HashProps.NameOfRule
                            }
                        }

                        # Create and output object using the properties defined in the hashtable
                        $RuleList += New-Object -TypeName 'PSCustomObject' -Property $HashProps
                    }
                }

                if ($DomainEnabled -or $PublicEnabled -or $StandardEnabled) {
                    $FirewallEnabled = $true
                }
                $ResultProperty = @{
                    'PSComputerName'      = $ComputerName
                    'PSDateTime'          = $PSDateTime
                    'ComputerName'        = $ComputerName
                    'FirewallEnabled'     = $FirewallEnabled
                    'DomainZoneEnabled'   = $DomainEnabled
                    'DomainZoneLogPath'   = [string]($reg.GetStringValue($HKLM, $FW_DomainLogPath, "LogFilePath").sValue)
                    'DomainZoneLogSize'   = [int]($reg.GetDWORDValue($HKLM, $FW_DomainLogPath, "LogFileSize").uValue)
                    'PublicZoneEnabled'   = $PublicEnabled
                    'PublicZoneLogPath'   = [string]($reg.GetStringValue($HKLM, $FW_PublicLogPath, "LogFilePath").sValue)
                    'PublicZoneLogSize'   = [int]($reg.GetDWORDValue($HKLM, $FW_PublicLogPath, "LogFileSize").uValue)
                    'StandardZoneEnabled' = $StandardEnabled
                    'StandardZoneLogPath' = [string]($reg.GetStringValue($HKLM, $FW_StandardLogPath, "LogFilePath").sValue)
                    'StandardZoneLogSize' = [int]($reg.GetDWORDValue($HKLM, $FW_StandardLogPath, "LogFileSize").uValue)
                    'Rules'               = $RuleList
                }

                $ResultObject = New-Object PSObject -Property $ResultProperty

                # Setup the default properties for output
                $ResultObject.PSObject.TypeNames.Insert(0, 'My.RemoteFirewall.Info')
                $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet', [string[]]$defaultProperties)
                $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)
                $ResultObject | Add-Member MemberSet PSStandardMembers $PSStandardMembers

                Write-Output -InputObject $ResultObject
            } catch {
                Write-Warning -Message ('Firewall Information: {0}: {1}' -f $ComputerName, $_.Exception.Message)
            }
            Write-Verbose -Message ('Firewall Information: Runspace {0}: End' -f $ComputerName)
        }

        function Get-Result {
            [CmdletBinding()]
            Param
            (
                [switch]$Wait
            )
            do {
                $More = $false
                foreach ($runspace in $runspaces) {
                    $StartTime = $runspacetimers[$runspace.ID]
                    if ($runspace.Handle.isCompleted) {
                        Write-Verbose -Message ('Firewall Information: Thread done for {0}' -f $runspace.IObject)
                        $runspace.PowerShell.EndInvoke($runspace.Handle)
                        $runspace.PowerShell.Dispose()
                        $runspace.PowerShell = $null
                        $runspace.Handle = $null
                    } elseif ($null -ne $runspace.Handle) {
                        $More = $true
                    }
                    if ($Timeout -and $StartTime) {
                        if ((New-TimeSpan -Start $StartTime).TotalSeconds -ge $Timeout -and $runspace.PowerShell) {
                            Write-Warning -Message ('Firewall Information: Timeout {0}' -f $runspace.IObject)
                            $runspace.PowerShell.Dispose()
                            $runspace.PowerShell = $null
                            $runspace.Handle = $null
                        }
                    }
                }
                if ($More -and $PSBoundParameters['Wait']) {
                    Start-Sleep -Milliseconds 100
                }
                foreach ($threat in $runspaces.Clone()) {
                    if ( -not $threat.handle) {
                        Write-Verbose -Message ('Firewall Information: Removing {0} from runspaces' -f $threat.IObject)
                        $runspaces.Remove($threat)
                    }
                }
                if ($ShowProgress) {
                    $ProgressSplatting = @{
                        Activity        = 'Getting installed programs'
                        Status          = 'Firewall Information: {0} of {1} total threads done' -f ($bgRunspaceCounter - $runspaces.Count), $bgRunspaceCounter
                        PercentComplete = ($bgRunspaceCounter - $runspaces.Count) / $bgRunspaceCounter * 100
                    }
                    Write-Progress @ProgressSplatting
                }
            }
            while ($More -and $PSBoundParameters['Wait'])
        }
    }

    Process {
        foreach ($Computer in $ComputerName) {
            $bgRunspaceCounter++
            $psCMD = [System.Management.Automation.PowerShell]::Create().AddScript($ScriptBlock)
            $null = $psCMD.AddParameter('bgRunspaceID', $bgRunspaceCounter)
            $null = $psCMD.AddParameter('ComputerName', $Computer)
            $null = $psCMD.AddParameter('Verbose', $VerbosePreference)
            $psCMD.RunspacePool = $rp

            Write-Verbose -Message ('Firewall Information: Starting {0}' -f $Computer)
            [void]$runspaces.Add(@{
                    Handle     = $psCMD.BeginInvoke()
                    PowerShell = $psCMD
                    IObject    = $Computer
                    ID         = $bgRunspaceCounter
                })
            Get-Result
        }
    }

    End {
        Get-Result -Wait
        if ($ShowProgress) {
            Write-Progress -Activity 'Firewall Information: Getting program listing' -Status 'Done' -Completed
        }
        Write-Verbose -Message "Firewall Information: Closing runspace pool"
        $rp.Close()
        $rp.Dispose()
    }
}

#endregion Helper functions



#region Variables and Prereqs
[array]$result = ""

if($FWProfile -contains "All") {
    $FWProfile = @("Domain", "Private", "Public")
}
#endregion Variables and Prereqs



#region Main script

# Query base info
$fwParam = @{
    "Name" = $FWProfile
    "ErrorAction" = "Stop"
}

if($ComputerName -eq $env:COMPUTERNAME) {
    $fwParam.Add("CimSession", $ComputerName)
} else {
    $cimParam = @{
        "ComputerName" = $ComputerName
        "ErrorAction" = "Stop"
    }
    if($Credential) { $cimParam.Add("Credential", $Credential) }

    $cimSession = New-CimSession @cimParam
    $fwParam.Add("CimSession", $cimSession)
}

$status = Get-NetFirewallProfile @fwParam

# Build PRTG result
[array]$messages = @()
$result += "<prtg>"

foreach ($item in $status) {

    $result += Out-PrtgChannel -Channel "$($item.Name) enabled" -Value ([int]($item.Enabled)) -ValueLookup "prtg.standardlookups.boolean.statetrueok" -ShowChart -ShowTable
    $result += Out-PrtgChannel -Channel "$($item.Name) Log Allowed traffic" -Value ([int]($item.LogAllowed)) -ValueLookup "prtg.standardlookups.exchangedag.yesno.allstatesok" -ShowTable
    $result += Out-PrtgChannel -Channel "$($item.Name) Log Blocked traffic" -Value ([int]($item.LogBlocked)) -ValueLookup "prtg.standardlookups.exchangedag.yesno.allstatesok" -ShowTable

    if($item.LogAllowed -or $item.LogBlocked) {
        $messages += "$($item.Name) logfile: $($item.LogFileName)"
    }
}
if($messages) {
    $result += "<text>$( [string]::Join(", ", $messages) )</text>"
}
$result += "</prtg>"

# Output PRTG result
$result | clip

# kill remoting session
$exSession | Remove-PSSession

#endregion
