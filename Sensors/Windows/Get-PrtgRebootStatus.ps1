<#
    .SYNOPSIS
        PRTG Veeam EXE Sensor - Get-PRTGRebootStatus.ps1

    .DESCRIPTION
        EXE sensor will report if a machine needs a reboot

    .NOTES
        Author        : Andreas Bellstedt
        Last Modified : 06.11.2022
        Version       : 1.0.0

    .LINK
        https://github.com/AndiBellstedt

    .EXAMPLE
        Get-PRTGRebootStatus.ps1 -ComputerName SRV01.corp.customer.com

        Check all reboot information

    .EXAMPLE
        Get-PRTGRebootStatus.ps1 -ComputerName SRV01.corp.customer.com -NoCBServicing -NoWindowsUpdate -NoSCCM -NoPendFileRename

        Skip CBSServices, Windows Updates, SCCM and Pending file renames

    .PARAMETER Computername
        Specifies the machine name.
        If not specified, the local machine will queried

    .PARAMETER NoCBServicing
        "Component Based Servicing" status will be ignored

    .PARAMETER NoWindowsUpdate
        Ignores "Windows Update Service" status for pending reboots

    .PARAMETER NoSCCM
        Ignores "SCCM Client" reboot status

    .PARAMETER NoPendFileRename
        Ignores FileRenameOperations status
#>
[CmdletBinding()]
Param (
    [string]
    $ComputerName,

    [pscredential]
    $Credential,

    [switch]
    $NoCBServicing,

    [switch]
    $NoWindowsUpdate,

    [switch]
    $NoSCCM,

    [switch]
    $NoPendFileRename
)


#Region VARIABLES
[bool]$RebootNeeded = $false
[String]$RebootText = ""
#EndRegion VARIABLES


#Region ScriptBlock
$scriptBlock = {
    <#
    .DESCRIPTION
        This function will query the registry on a local or remote computer and determine if the
        system is pending a reboot, from either Microsoft Patching or a Software Installation.
        For Windows 2008+ the function will query the CBS registry key as another factor in determining
        pending reboot state.  "PendingFileRenameOperations" and "Auto Update\RebootRequired" are observed
        as being consistant across Windows Server 2003 & 2008.

        CBServicing = Component Based Servicing (Windows 2008)
        WindowsUpdate = Windows Update / Auto Update (Windows 2003 / 2008)
        CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
        PendFileRename = PendingFileRenameOperations (Windows 2003 / 2008)
    .LINK
        Component-Based Servicing:
        http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx

        PendingFileRename/Auto Update:
        http://support.microsoft.com/kb/2723674
        http://technet.microsoft.com/en-us/library/cc960241.aspx
        http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx

        SCCM 2012/CCM_ClientSDK:
        http://msdn.microsoft.com/en-us/library/jj902723.aspx

    .NOTES
        Author:  Brian Wilhite
        Email:   bwilhite1@carolina.rr.com
        Date:    08/29/2012
        PSVer:   2.0/3.0
        Updated: 05/30/2013
        UpdNote: Added CCMClient property - Used with SCCM 2012 Clients only
                Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
                Removed $Data variable from the PSObject - it is not needed
                Bug with the way CCMClientSDK returned null value if it was false
                Removed unneeded variables
                Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
    #>

    #Setting pending values to false to cut down on the number of else statements
    $PendFileRename, $Pending, $SCCM = $false, $false, $false

    #Setting CBSRebootPend to null since not all versions of Windows has this value
    $CBSRebootPend = $null

    #Querying WMI for build version
    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName

    # If Vista/2008 & Above query the CBS Reg Key
    If ($WMI_OS.BuildNumber -ge 6001) {
        $RegSubKeysCBS = Get-ChildItem "HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction:SilentlyContinue
        if ($RegSubKeysCBS -ne $null) { $CBSRebootPend = $true }
    }

    # Query WUAU from the registry
    $RegWUAU = Get-Item "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction:SilentlyContinue
    if ($RegWUAU -ne $null) { $WUAURebootReq = $true }

    # Query PendingFileRenameOperations from the registry
    $RegSubKeySM = Get-Item "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager\"
    $RegValuePFRO = ($RegSubKeySM |  Get-ItemProperty -Name PendingFileRenameOperations -ErrorAction:SilentlyContinue).PendingFileRenameOperations

    # If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
    If ($RegValuePFRO) { $PendFileRename = $true }

    # Determine SCCM 2012 Client Reboot Pending Status. To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
    $CCMClientSDK = $null
    $CCMSplat = @{
        NameSpace    = 'ROOT\ccm\ClientSDK'
        Class        = 'CCM_ClientUtilities'
        Name         = 'DetermineIfRebootPending'
        ComputerName = "."
        ErrorAction  = 'SilentlyContinue'
    }
    $CCMClientSDK = Invoke-WmiMethod @CCMSplat
    If ($CCMClientSDK) {
        If ($CCMClientSDK.ReturnValue -ne 0) { Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)" }
        If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) { $SCCM = $true }
    } Else {
        $SCCM = $null
    }

    # If any of the variables are true, set $Pending variable to $true
    If ($CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename) { $Pending = $true }

    # Creating Custom PSObject and Select-Object Splat
    $SelectSplat = @{Property = ('Computer', 'CBServicing', 'WindowsUpdate', 'CCMClientSDK', 'PendFileRename', 'PendFileRenVal', 'RebootPending') }
    New-Object -TypeName PSObject -Property @{
        Computer       = $WMI_OS.CSName
        CBServicing    = $CBSRebootPend
        WindowsUpdate  = $WUAURebootReq
        CCMClientSDK   = $SCCM
        PendFileRename = $PendFileRename
        PendFileRenVal = $RegValuePFRO
        RebootPending  = $Pending
    } | Select-Object @SelectSplat
}
#EndRegion ScriptBlock


#Region Script

# Invoke Check on local or remote computer
if ($ComputerName -and ($ComputerName -notlike "localhost" -or $ComputerName -notlike "127.0.0.1")) {
    $paramInvokeCommand = @{
        "ComputerName" = $ComputerName
        "ScriptBlock"  = $ScriptBlock
    }
    if ($Credential) { $paramInvokeCommand.Add("Credential", $Credential) }
    $RebootStatus = Invoke-Command @paramInvokeCommand
} else {
    $RebootStatus = . $ScriptBlock
}


if ($RebootStatus.CBServicing -and (-not $NoCBServicing)) {
    if ($RebootNeeded) { $RebootText += " and " }
    $RebootNeeded = $true
    $RebootText += "Component Based Servicing"
}

if ($RebootStatus.WindowsUpdate -and (-not $NoWindowsUpdate)) {
    if ($RebootNeeded) { $RebootText += " and " }
    $RebootNeeded = $true; $RebootText += "installed Windows Updates"
}

if ($RebootStatus.CCMClientSDK -and (-not $NoSCCM)) {
    if ($RebootNeeded) { $RebootText += " and " }
    $RebootNeeded = $true
    $RebootText += "SCCM activities "
}

if ($RebootStatus.PendFileRename -and (-not $NoPendFileRename)) {
    $PendFileRenVal = [string]::Join(", ", ($RebootStatus.PendFileRenVal.Replace('\??\', '') | Where-Object { $_ -ne "" } | Sort-Object -Unique))
    if ($RebootNeeded) { $RebootText += " and " }
    $RebootNeeded = $true
    $RebootText += "Pending FileRenameOperations: $($PendFileRenVal)"
}

if ($RebootStatus.RebootPending -and $RebootNeeded) {
    "1:Reboot required because of $($RebootText)"
    Exit 4
} else {
    "0:No reboot required"
    Exit 0
}
#EndRegion Script