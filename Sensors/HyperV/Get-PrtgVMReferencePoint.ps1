<#
    .SYNOPSIS
        PRTG HyperV Advanced Sensor

    .DESCRIPTION
        Advanced Sensor will Report information about amount of HyperV VM reference points
        High amount of reference points leeds into slow starting VMs an management overhead on the hypervisor

    .PARAMETER ComputerName
        The HyperV host to query for virtual machines.

    .PARAMETER VMName
        The virtual machine name to query. Basicly this is a filter, so wildcards are supportet.
        Defaul value is "*"

    .PARAMETER MaxWarning
        Limit when PRTG report a channel in warning state. (yellow message)

    .PARAMETER MaxError
        Limit when PRTG report a channel in error state. (red alert)

    .EXAMPLE
        PS C:\> .\Get-VMReferencePoint.ps1 -ComputerName "HV01" -VMName *

        Reports amount of reference poitns for all VMs on host "HV01" with defaul warning and error values

    .EXAMPLE
        PS C:\> .\Get-VMReferencePoint.ps1 -ComputerName "HV01" -VMName "VM01" -MaxWarning "30" -MaxError "100"

        Reports amount of reference poitns for all VMs on host "HV01" with customized warn and error limits

    .NOTES
        Get-PrtgVMReferencePoint
        Author: Andreas Bellstedt
        LASTEDIT: 2022/11/25
        VERSION: 1.0.1
        KEYWORDS: PRTG, HyperV, HV

        Derived from microsoft script found in Veeam Knowledgebase
        https://forums.veeam.com/microsoft-hyper-v-f25/guest-os-starting-up-is-very-slow-on-hyper-v-2016-t50984.html

        additional references:
        https://docs.microsoft.com/de-de/archive/blogs/taylorb/teched-europe-windows-vnext-hyper-v-backup-and-restore-powershell-scripts
        https://community.spiceworks.com/topic/2215842-hyper-v-live-migration-fails

    .LINK
        https://github.com/AndiBellstedt/PRTG
#>
#Requires -Version 3
[CmdletBinding(
    ConfirmImpact = "Low",
    PositionalBinding = $true
)]
param(
    [string]
    [Alias("Hostname", "Server", "Computer", "ServerName", "Host")]
    $ComputerName = (.{ if ($env:prtg_host) { $env:prtg_host } else { $env:COMPUTERNAME } }),

    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]
    [Alias("VM", "Name", "Filter")]
    $VMName = "*",

    [int]
    $MaxWarning,

    [int]
    $MaxError = 30
)



#region helper functions
filter ProcessWMIJob {
    param(
        [WMI]$WmiClass = $null,
        [string]$MethodName = $null
    )
    $errorCode = 0
    $returnObject = $_
    if ($_.ReturnValue -eq 4096) {
        $Job = [WMI]$_.Job
        $returnObject = $Job
        while ($Job.JobState -eq 4) {
            Write-Progress -Activity $Job.Caption -Status ($Job.JobStatus + " - " + $Job.PercentComplete + "%") -PercentComplete $Job.PercentComplete
            Start-Sleep -seconds 1
            $Job.PSBase.Get()
        }
        if ($Job.JobState -ne 7) {
            if ($Job.ErrorDescription -ne "") {
                Write-Error $Job.ErrorDescription
                Throw $Job.ErrorDescription
            } else {
                $errorCode = $Job.ErrorCode
            }
        }
        Write-Progress -Activity $Job.Caption -Status $Job.JobStatus -PercentComplete 100 -Completed:$true

    } elseif ($_.ReturnValue -ne 0) {
        $errorCode = $_.ReturnValue
    }

    if ($errorCode -ne 0) {
        Write-Error "Hyper-V WMI Job Failed!"
        if ($WmiClass -and $MethodName) {
            $psWmiClass = [WmiClass]("\\" + $WmiClass.__SERVER + "\" + $WmiClass.__NAMESPACE + ":" + $WmiClass.__CLASS)
            $psWmiClass.PSBase.Options.UseAmendedQualifiers = $TRUE
            $MethodQualifierValues = ($psWmiClass.PSBase.Methods[$MethodName].Qualifiers)["Values"]
            $indexOfError = [System.Array]::IndexOf(($psWmiClass.PSBase.Methods[$MethodName].Qualifiers)["ValueMap"].Value, [string]$errorCode)
            if (($indexOfError -ne "-1") -and $MethodQualifierValues) {
                Throw "ReturnCode: ", $errorCode, " ErrorMessage: '", $MethodQualifierValues.Value[$indexOfError], "' - when calling $MethodName"
            } else {
                Throw "ReturnCode: ", $errorCode, " ErrorMessage: 'MessageNotFound' - when calling $MethodName"
            }
        } else {
            Throw "ReturnCode: ", $errorCode, "When calling $MethodName - for rich error messages provide classpath and method name."
        }
    }
    return $returnObject
}

# error handling for PRTG
trap {
    # Catch all unhadled errors and close Pssession to avoid this issue:
    # Thanks for https://github.com/klmj for the idea
    # http://www.checkyourlogs.net/?p=54583

    # build PRTG result object with error output
    "<prtg>"
    " <error>1</error>"
    " <text>$($_.ToString())</text>"
    "</prtg>"

    exit 1
}

# XML channel output for PRTG
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
#endregion helper functions



#region main script
# query VMs from HyperV host
$vmCollection = Get-VM -ComputerName $ComputerName -Name $VMName | Sort-Object -Property Name
Write-Verbose "$($vmCollection.count) VMs found on '$($ComputerName)'"

# Start with output to PRTG as a xml result object
$output = "<prtg>"

# loop trough VMs and build data channels
foreach ($vmItem in $vmCollection) {
    $vmName = $vmItem.Name
    Write-Verbose "$(Get-Date -Format s) Query VM '$($vmName)'"

    # Retrieve an instance of the virtual machine computer system that contains reference points
    $msvm_ComputerSystem = Get-WmiObject -ComputerName $ComputerName -Namespace "root\virtualization\v2" -Class "Msvm_ComputerSystem" -Filter "ElementName='$($vmName)'"

    # Retrieve all refrence associations of the virtual machine
    $allrefPoints = $msvm_ComputerSystem.GetRelationships("Msvm_ReferencePointOfVirtualSystem")

    # Enumerate across all of the instances and add all recovery points to an array
    $enum = $allrefPoints.GetEnumerator()
    $enum.Reset()

    $virtualSystemRefPoint = @()
    while ($enum.MoveNext()) {
        $virtualSystemRefPoint += ([WMI] $enum.Current.Dependent)
    }

    # Return channel for per VM with amount of ReferencePoints
    $param = @{
        "Channel" = $vmName.toUpper()
        "Value"   = $virtualSystemRefPoint.Count
        "Unit"    = "Count"
    }
    if ($MaxWarning) { $parm.add("MaxWarn", $MaxWarning) }
    if ($MaxError) {
        $param.add("MaxError", $MaxError)
        $param.add("ErrorMsg", "Potential slow VM start and problems livemigrate VMs. Check and cleanup reference points")
    }

    $output += Set-PrtgResult @param
    Write-Verbose "$(Get-Date -Format s) Found $($virtualSystemRefPoint.Count) reference points for '$($vmName)'"
}

# close and finish prtg result object
$output += "</prtg>"

# output result to shell
$output

#endregion main script
