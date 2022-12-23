<#
    .SYNOPSIS
        PRTG Advanced Sensor - Check license status for citrix license server

    .DESCRIPTION
        PRTG citrix licensing server monitor
        Script for checking license status for citrix license server

    .PARAMETER ComputerName
        String Parameter - optional
        Specifies Computer to be queried

    .EXAMPLE
        PS C:\> .\Get-PrtgCtxLicenseStatus.ps1 -ComputerName Server1

        Check license status of Server1

    .NOTES
        Get-PrtgCtxLicenseStatus
        Author: Andreas Bellstedt
        LASTEDIT: 2022/12/13
        VERSION: 1.0.2
        KEYWORDS: PRTG, Citrix, LicenseMonitoring

        derived from https://github.com/LockstepGroup/citrix-prtg/blob/master/Lockstep%20-%20Citrix%20Licensing%20Monitor.ps1

    .LINK
        https://github.com/AndiBellstedt/PRTG

#>
#Requires –Version 3
Param (
    [Parameter(Position = 0)]
    [Alias("Hostname", "Server", "Computer", "ServerName", "Host")]
    [string]
    $ComputerName = (.{ if ($env:prtg_host) { $env:prtg_host } else { $env:COMPUTERNAME } })
)



#region helper functions
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

function Get-TargetStatus {
    Param (
        [Parameter(mandatory = $True, Position = 0)]
        [string]$ComputerName,
        [Parameter(Position = 1)]
        [string]$ServiceName = "SamSs"
    )

    $wmi = [WMISearcher]""
    $wmi.options.timeout = '0:0:5' # 5-second timeout
    $wmi.scope.path = ("\\" + $ComputerName + "\Root\CIMV2")
    $wmi.query = 'Select Status from Win32_Service where Name= "' + $ServiceName + '"'

    try {
        $ServiceStatus = ($wmi.Get() | Select-Object Status).Status
    } catch {
        if ($_.Exception.InnerException) {
            return ("Error: " + $ComputerName + ": " + $_.Exception.InnerException.Message)
        } else {
            return ("Error: " + $ComputerName + ": " + $_.Exception.Message)
        }
    }

    if ($ServiceStatus -eq "OK") {
        return $true
    } else {
        return ("Error: " + $ComputerName + ": $ServiceName not running.")
    }
}


function ConvertFrom-PLD($MyPLD) {
    $rawcsv = @"
        "pld","name"
        "XDTTP_STD_UD","XenDesktop VDI|User/Device"
        "XDTTP_PLT_UD","XenDesktop Platinum|User/Device"
        "XDTTP_ENT_UD","XenDesktop Enterprise|User/Device"
        "XDTTP_ADV_UD","XenDesktop Advanced|User/Device"
        "XDTTP_STD_CCS","XenDesktop VDI|Concurrent System"
        "XDTTP_PLT_CCS","XenDesktop Platinum|Concurrent System"
        "XDTTP_ENT_CCS","XenDesktop Enterprise|Concurrent System"
        "XDT_STD_UD","XenDesktop VDI|User/Device"
        "XDT_PLT_UD","XenDesktop Platinum|User/Device"
        "XDT_ENT_UD","XenDesktop Enterprise|User/Device"
        "XDT_ADV_UD","XenDesktop Advanced|User/Device"
        "XDT_STD_CCS","XenDesktop VDI|Concurrent System"
        "XDT_PLT_CCS","XenDesktop Platinum|Concurrent System"
        "XDT_ENT_CCS","XenDesktop Enterprise|Concurrent System"
        "XDSTP_STD_CCS","XenDesktop VDI|Concurrent System"
        "XDSTP_PLT_CCS","XenDesktop Platinum|Concurrent System"
        "XDSTP_ENT_CCS","XenDesktop Enterprise|Concurrent System"
        "XDSTP_ADV_CCS","XenDesktop Advanced|Concurrent System"
        "XDS_STD_CCS","XenDesktop VDI|Concurrent System"
        "XDS_PLT_CCS","XenDesktop Platinum|Concurrent System"
        "XDS_ENT_CCS","XenDesktop Enterprise|Concurrent System"
        "XDS_ADV_CCS","XenDesktop Advanced|Concurrent System"
        "PVSDTP_STD_CCS","Provisioning Server for Desktops|Concurrent System"
        "PVSD_STD_CCS","Provisioning Server for Desktops|Concurrent System"
        "PVS_STD_CCS","Provisioning Services|Concurrent"
        "MPSTP_VDS_RN","Desktop Server|Named User"
        "MPSTP_STD_CCU","XenApp (Presentation Server) Standard|Concurrent User"
        "MPSTP_PLT_CCU","XenApp (Presentation Server) Platinum|Concurrent User"
        "MPSTP_ENT_CCU","XenApp (Presentation Server) Enterprise|Concurrent User"
        "MPSTP_ADV_CCU","XenApp (Presentation Server) Advanced|Concurrent User"
        "MPS_VDS_RN","Desktop Server|Named User"
        "MPS_STD_CCU","XenApp (Presentation Server) Standard|Concurrent User"
        "MPS_SMB_RN","XenApp Fundamentals|Named User"
        "MPS_PLT_CCU","XenApp Platinum|Concurrent"
        "MPS_ENT_ENABLER","SmartAuditor|Enabler"
        "MPS_ENT_CCU","XenApp Enterprise|Concurrent"
        "MPS_ADV_CCU","XenApp Advanced|Concurrent"
        "MPMTP_ADV_RN","Password Manager (max of 5X SSPR named users allowed per license)|Named User"
        "MPM_ADV_RN","Password Manager (max of 5X SSPR named users allowed per license)|Named User"
        "MPMTP_ADV_RC","Password Manager (max of 10X SSPR named users allowed per license)|Concurrent User"
        "MPM_ADV_RC","Password Manager (max of 10X SSPR named users allowed per license)|Concurrent User"
        "MCM_STD_CCU","Conferencing Manager|Concurrent User"
        "CXSTP_PLT_CCS","XenServer Platinum|Concurrent System"
        "CXSTP_ENT_CCS","XenServer Enterprise|Concurrent System"
        "CXSTP_ADV_CCS","XenServer Advanced|Concurrent System"
        "CXS_PLT_CCS","XenServer Platinum|Concurrent System"
        "CXS_ENT_CCS","XenServer Enterprise|Concurrent"
        "CXS_ADV_CCS","XenServer Advanced|Concurrent System"
        "CXC_XT_UD","XenClient XT|Device"
        "CWSDE_5M_SSERVER","WANScaler Defense Edition 5Mbps|Server"
        "CWSDE_45M_SSERVER","WANScaler Defense Edition 45Mbps|Server"
        "CWSDE_20M_SSERVER","WANScaler Defense Edition 20Mbps|Server"
        "CWSDE_10M_SSERVER","WANScaler Defense Edition 10Mbps|Server"
        "CWSDE_100M_SSERVER","WANScaler Defense Edition 100Mbps|Server"
        "CWS_STD_SCCU","Repeater Plug-in|Concurrent User"
        "CWS_ENCRYPT_ENABLER","Branch Repeater Crypto|Enabler"
        "CWS_8820_SSERVER","Repeater 8820|Server"
        "CWS_8810_SSERVER","Repeater 8810|Server"
        "CWS_8540_SSERVER","Repeater 8540|Server"
        "CWS_8530_SSERVER","Repeater 8530|Server"
        "CWS_8520_SSERVER","Repeater 8520|Server"
        "CWS_8510_SSERVER","Repeater 8510|Server"
        "CWS_8320_SSERVER","Repeater 8320|Server"
        "CWS_8310_SSERVER","Repeater 8310|Server"
        "CSSTP_ENT_CCU","Application Streaming for Desktops|Concurrent User"
        "CSS_ENT_CCU","Application Streaming for Desktops|Concurrent User"
        "CPMTP_STD_RN","Password Manager Standard|Named User"
        "CPMTP_STD_RC","Password Manager Standard|Concurrent User"
        "CPMTP_ENT_RN","Password Manager Enterprise (max of 5X SSPR named users allowed per license)|Named User"
        "CPMTP_ENT_RC","Password Manager Enterprise (max of 10X SSPR named users allowed per license)|Concurrent User"
        "CPMTP_ADV_RN","Password Manager Advanced|Named User"
        "CPMTP_ADV_RC","Password Manager Advanced|Concurrent User"
        "CPM_STD_RN","Password Manager Standard|Named User"
        "CPM_STD_RC","Password Manager Standard|Concurrent User"
        "CPM_ENT_RN","Password Manager Enterprise (max of 5X SSPR named users allowed per license)|Named User"
        "CPM_ENT_RC","Password Manager Enterprise (max of 10X SSPR named users allowed per license)|Concurrent User"
        "CPM_ADV_RN","Password Manager Advanced|Named User"
        "CPM_ADV_RC","Password Manager Advanced|Concurrent User"
        "CNS_V500_SERVER","NetScaler VPX 500|Server"
        "CNS_V200_SERVER","NetScaler VPX 200|Server"
        "CNS_V3000_SERVER","NetScaler VPX 3000|Server"
        "CNS_V1000_SERVER","NetScaler VPX 1000|Server"
        "CNS_V100_SERVER","NetScaler VPX 100|Server"
        "CNS_V10_SERVER","NetScaler VPX 10|Server"
        "CNS_V1_SERVER","NetScaler VPX 1|Server"
        "CNS_SSLVPN_CCU","Access Gateway - Enterprise Edition|Concurrent User"
        "CNS_SSE_SERVER","NetScaler Application Switch - Standard Edition|Server"
        "CNS_SPE_SERVER","NetScaler Application Switch - Platinum Edition|Server"
        "CNS_SEE_SERVER","NetScaler Application Switch - Enterprise Edition|Server"
        "CNS_PROXGSLB_SERVER","NetScaler Global Server Load Balancer (Proximity) - Option|Server"
        "CNS_OCLOUD_SERVER","NetScaler OpenCloud Access Option|Server"
        "CNS_IPV6_SERVER","NetScaler IPv6 - Option|Server"
        "CNS_HTMLINJ_SERVER","NetScaler HTML Injection - Option|Server"
        "CNS_GSLB_SERVER","NetScaler Global Server Load Balancer (Basic) - Option|Server"
        "CNS_CLOUDG_RN","NetScaler Cloud Gateway|Per User"
        "CNS_CLOUDG_CCS","NetScaler Cloud Gateway|Concurrent User"
        "CNS_CLOUDG_SERVER","NetScaler Cloud Gateway|Server"
        "CNS_CLOUDB_SERVER","NetScaler Cloud Bridge|Server"
        "CNS_CACHE_SERVER","NetScaler AppCache - Option|Server"
        "CNS_APPFSA_SERVER","NetScaler Application Firewall|Server"
        "CNS_APPF_SERVER","NetScaler Application Firewall - Option |Server"
        "CNS_APPCON_CCU","NetScaler AppConnector Option|Concurrent Application"
        "CNS_APPCE_SERVER","NetScaler AppCompress Extreme - Option|Server"
        "CNS_APPC_SERVER","NetScaler AppCompress - Option|Server"
        "CNS_AGEE_SERVER","Access Gateway - Enterprise Edition|Server"
        "CNS_ADVGSLB_SERVER","NetScaler Advanced Global Server Load Balancer - Option|Server"
        "CNS_AAC_SERVER","NetScaler Application Accelerator|Server"
        "CNS_21500_SERVER","NetScaler MPX 21500|Server"
        "CNS_19500_SERVER","NetScaler MPX 19500|Server"
        "CNS_17500_SERVER","NetScaler MPX 17500|Server"
        "CNS_17000_SERVER","NetScaler MPX 17000|Server"
        "CNS_15500_SERVER","NetScaler MPX 15500|Server"
        "CNS_15000_SERVER","NetScaler MPX 15000|Server"
        "CNS_12500_SERVER","NetScaler MPX 12500|Server"
        "CNS_10500_SERVER","NetScaler MPX 10500|Server"
        "CNS_9700_SERVER","NetScaler MPX 9700|Server"
        "CNS_9500_SERVER","NetScaler MPX 9500|Server"
        "CNS_7500_SERVER","NetScaler MPX 7500|Server"
        "CNS_5500_SERVER","NetScaler MPX 5500|Server"
        "CESPSTP_ENT_CCU","EdgeSight for XenApp|Concurrent User"
        "CESPS_ENT_CCU","EdgeSight for XenApp|Concurrent User"
        "CESLTTP_STD_SSERVER","EdgeSight for Load Testing - Controller|Server"
        "CESLTTP_STD_SCCU","EdgeSight for Load Testing|Concurrent User"
        "CESLT_STD_SSERVER","EdgeSight for Load Testing - Controller|Server"
        "CESLT_STD_SCCU","EdgeSight for Load Testing|Concurrent User"
        "CESEPTP_ENT_CCU","EdgeSight for Endpoints|Concurrent User"
        "CESEP_ENT_CCU","EdgeSight for Endpoints|Concurrent User"
        "CEHVTP_PLT_CCS","StorageLink Platinum|Concurrent System"
        "CEHVTP_ENT_CCS","StorageLink Enterprise|Concurrent System"
        "CEHV_PLT_CCS","StorageLink Platinum|Concurrent System"
        "CEHV_ENT_CCS","StorageLink Enterprise|Concurrent"
        "CCGW_STD_CCU","EasyCall Unlimited License|Concurrent User"
        "CCG_STD_CCU","EasyCall|Concurrent User"
        "CBRWS_300_SSERVER","Branch Repeater with Windows Server 300|Server"
        "CBRWS_200_SSERVER","Branch Repeater with Windows Server 200|Server"
        "CBRWS_100_SSERVER","Branch Repeater with Windows Server 100|Server"
        "CBRW2K8_300_SSERVER","Branch Repeater with Windows Server 2008 300|Server"
        "CBRW2K8_200_SSERVER","Branch Repeater with Windows Server 2008 200|Server"
        "CBRW2K8_100_SSERVER","Branch Repeater with Windows Server 2008 100|Server"
        "CBR_V45_SSERVER","Branch Repeater VPX 45 Mbps|Server"
        "CBR_V10_SSERVER","Branch Repeater VPX 10 Mbps|Server"
        "CBR_V2_SSERVER","Branch Repeater VPX 2 Mbps|Server"
        "CBR_V1_SSERVER","Branch Repeater VPX 1 Mbps|Server"
        "CBR_VEXP_SSERVER","Branch Repeater VPX Express|Server"
        "CBR_300_SSERVER","Branch Repeater 300|Server"
        "CBR_200_SSERVER","Branch Repeater 200|Server"
        "CBR_100_SSERVER","Branch Repeater 100|Server"
        "CASTP_ENT_CCU","Application Streaming for Desktops|Concurrent User"
        "CAS_ENT_CCU","Application Streaming for Desktops|Concurrent User"
        "CAG_SSLVPN_CCU","Access Gateway - Standard Edition|Concurrent User"
        "CAG_ICA_CCU","Access Gateway - Basic Connection|Concurrent User"
        "CAG_EXPRESS_SERVER","Access Gateway VPX - Express Edition|Server"
        "CAG_BASE_SERVER","Access Gateway - Basic Connection|Server"
        "CAG_AAC_CCU","Access Gateway - Advanced Edition|Concurrent User"
        "DE.LICTYPE","Developer Edition"
        "TP.LICTYPE","Technology Preview"
        "Eval.LICTYPE","Evaluation"
        "RetailS.LICTYPE","Expiring Retail"
        "Retail.LICTYPE","Retail"
        "NFR.LICTYPE","Not For Resale"
        "SYS.LICTYPE","System"
        "CITRIX","Start-up License|Server"
"@
    $LicenseList = ConvertFrom-Csv $rawcsv
    $LicenseList | Where-Object { $_.pld -eq $MyPLD } | Select-Object -ExpandProperty name
}


function Set-PrtgResult {
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
#endregion helper functions



#region work part of the script
# defining variables
$ReturnText = "OK" #default value
$ServiceNames = @("Citrix Licensing", "Citrix_GTLicensingProv", "CitrixLicensingConfigService", "CtxLSPortSvc")


# prereqs - this widens the buffer to prevent "chopping" long lines caused by long product names and set encoding to german compatible output
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size (2000, 25)
ping localhost -n 1 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8


# check for computer to connect
if (-not $ComputerName) {
    return @"
<prtg>
  <error>1</error>
  <text>Required parameter not specified: please provide target hostname (or %host)</text>
</prtg>
"@
}


# initial wmi connection tests (fail-fast)
$CheckServer = Get-TargetStatus $ComputerName
if ($CheckServer -ne $true) {
    return @"
<prtg>
  <error>1</error>
  <text>$CheckServer</text>
</prtg>
"@
}


# query license status
$LicensingData = Get-WmiObject -class "Citrix_GT_License_Pool" -Namespace "ROOT\CitrixLicensing" -ComputerName $ComputerName
$LicensingData = $LicensingData | Select-Object Count, InUseCount, PooledAvailable, Overdraft, PLD, LicenseType, @{
    n = 'PercentAvailable';
    e = { [math]::round( (( $_.PooledAvailable / $_.Count ) * 100), 0) }
}, @{
    n = 'PercentInUse';
    e = { [math]::round( (($_.InUseCount / $_.Count) * 100), 0) }
}, @{
    n = 'ProductName';
    e = { ConvertFrom-PLD $_.PLD }
}
#$LicensingData = $LicensingData | Where-Object PLD -like "XDT_ENT_CCS"

# query service state
$Services = Get-Service $ServiceNames -ComputerName $ComputerName -ErrorAction SilentlyContinue


# creating PRTG result info
$XMLOutput = '<?xml version="1.0" encoding="UTF-8" ?>'
$XMLOutput += '<prtg>'

foreach ($Service in $Services) {
    if ($Service.Status -ne "Running") { $State = 2 } else { $State = 1 }
    $XmlOutput += Set-PrtgResult $("Service: " + $Service.DisplayName) $State state -me 1 -em "Service is not running" -ValueLookup "prtg.standardlookups.yesno.stateyesok"
}

foreach ($License in $LicensingData) {
    $XMLOutput += Set-PrtgResult ("License: " + $License.ProductName + ": Percent In Use") $License.PercentInUse "Percent" -MaxWarn 90 -MaxError 100 -WarnMsg (($License.PercentInUse).toString() + "% of licenses allocated.") -ErrorMsg "No more licenses available." -ShowChart
    $XMLOutput += Set-PrtgResult ("License: " + $License.ProductName + ": Percent Available") $License.PercentAvailable "Percent" #-MaxWarn 10 -MaxError 0 -WarnMsg (($License.PercentAvailable).toString() + "% of licenses available.") -ErrorMsg "No more licenses available." -ShowChart
    $XMLOutput += Set-PrtgResult ("License: " + $License.ProductName + ": Available") $License.PooledAvailable "#"
    $XMLOutput += Set-PrtgResult ("License: " + $License.ProductName + ": Total Installed") $License.Count "#"
}

$XMLOutput += "  <text>$ReturnText</text>"
$XMLOutput += "</prtg>"


# output result to the console
$XMLOutput


#endregion work part of the script
