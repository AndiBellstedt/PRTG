<#
        .SYNOPSIS
        PRTG Veeam Advanced Sensor
 
        .DESCRIPTION
        Advanced Sensor will Report Statistics about Backups during last 24 Hours and Actual Repository usage.
 
        .PARAMETER PSRemote
        Switch to use PSRemoting instead of locally installed VeeamPSSnapin.
        Use "Get-Help about_remote_requirements" for more information
 
        .EXAMPLE
        PRTG-VeeamBRStats.ps1 -BRHost veeam01.lan.local
 
        .EXAMPLE
        PRTG-VeeamBRStats.ps1 -BRHost veeam01.lan.local -reportmode "Monthly" -repoCritical 80 -repoWarn 70 -Debug
 
        .EXAMPLE
        PRTG-VeeamBRStats.ps1 -BRHost veeam01.lan.local -reportmode "Monthly" -repoCritical 80 -repoWarn 70 -selChann "BR"
 

        .Notes
        NAME:  PRTG-VeeamBRStats.ps1
        LASTEDIT: 02/08/2018

        VERSION: 1.8

        KEYWORDS: Veeam, PRTG

        CREDITS:

        Thanks to Shawn, for creating an awsome Reporting Script:

        http://blog.smasterson.com/2016/02/16/veeam-v9-my-veeam-report-v9-0-1/

 

        Thanks to Bernd Leinfelder for the Scalout Repository part!

        https://github.com/berndleinfelder

 

        Thanks to Guy Zuercher for the Endpoint Backup part and a lot of other enhancmeents!

        https://github.com/gzuercher

 #>
#Requires -Version 3
[cmdletbinding()]
param(
    [string]
    $BRHost = "localhost",

    [string]
    $valueLookup = "",

    [switch]
    $PSRemote
)

 

#region Variables and Prereqs


# Disable output of warning to prevent Veeam PS quirks
#$WarningPreference = "SilentlyContinue"

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

    Exit
}

 

# Start Load VEEAM Snapin (in local or remote session)
if ($PSRemote) {
    # Remoting on VBR server
    $RemoteSession = New-PSSession -Authentication Kerberos -ComputerName $BRHost
    if (-not $RemoteSession) { throw "Cannot open remote session on '$BRHost' with user '$env:USERNAME'" }

    # Loading PSSnapin then retrieve commands
    Invoke-Command -Session $RemoteSession -ScriptBlock { Add-PSSnapin VeeamPSSnapin -Verbose:$false; $WarningPreference = "SilentlyContinue" } -ErrorAction Stop -Verbose:$false # muting warning about powershell version
    Import-PSSession -Session $RemoteSession -Module VeeamPSSnapin -ErrorAction Stop -Verbose:$false | Out-Null
} else {
    if (-not (Get-PSSnapin -Name VeeamPSSnapIn -ErrorAction SilentlyContinue)) {
        try {
            Add-PSSnapin -PassThru VeeamPSSnapIn -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to load VeeamPSSnapIn"
        }
    }
}

# Start BRHost Connection
Write-Verbose "Starting to Process Connection to '$BRHost' with user '$env:USERNAME' ..."
$OpenConnection = (Get-VBRServerSession).Server
if ($OpenConnection -eq $BRHost) {
    Write-Verbose "BRHost '$BRHost' is Already Connected..."
} elseif ($null -eq $OpenConnection) {
    Write-Verbose "Connecting BRHost '$BRHost' with user '$env:USERNAME'..."
    try {
        Connect-VBRServer -Server $BRHost -Verbose:$false
    } catch {
        Throw "Failed to connect to Veeam BR Host '$BRHost' with user '$env:USERNAME'"
    }
} else {
    Write-Verbose "Disconnection current BRHost..."
    Disconnect-VBRServer -Verbose:$false
    Write-Verbose "Connecting new BRHost '$BRHost' with user '$env:USERNAME'..."
    try {
        Connect-VBRServer -Server $BRHost -Verbose:$false
    } catch {
        Throw "Failed to connect to Veeam BR Host '$BRHost' with user '$env:USERNAME'"
    }
}
$NewConnection = (Get-VBRServerSession).Server
if ($null -eq $NewConnection) {
    Throw "Failed to connect to Veeam BR Host '$BRHost' with user '$env:USERNAME'"
}


#endregion Variables and Prereqs

 

#region Functions

#endregion

 

#region Main script

# query jobs
$VBRJobs = Invoke-Command -Session $RemoteSession -ScriptBlock { Get-VBRJob | select-object *, @{n="JobStatus"; e={ $_.GetLastResult()}} }
$VBRTapeJobs = Get-VBRTapeJob

# build PRTG result
"<prtg>"
foreach ($VBRJob in $VBRJobs) {
    switch ($VBRJob.JobStatus.Value) {
        'Success' { $JobStatusValue = 4 }
        'None' { $JobStatusValue = 3 }    # aka "running" or "never runs"
        'Warning' { $JobStatusValue = 2 }
        'Failed' { $JobStatusValue = 1 }
        Default { $JobStatusValue = 0 }
    }
    "<result>"
    "  <channel>$($VBRJob.Name)</channel>"
    "  <value>$JobStatusValue</value>"
    "  <ValueLookup>$valueLookup</ValueLookup>"
    "  <showChart>1</showChart>"
    "  <showTable>1</showTable>"
    "</result>"
}

foreach ($VBRTapeJob in $VBRTapeJobs) {
    switch ($VBRTapeJob.LastResult){
        'Success' { $JobStatusValue = 4 }
        'None' { $JobStatusValue = 3 }    # aka "running" or "never runs"
        'Warning' { $JobStatusValue = 2 }
        'Failed' { $JobStatusValue = 1 }
        Default { $JobStatusValue = 0 }
    }
    "<result>"
    "  <channel>$($VBRTapeJob.Name)</channel>"
    "  <value>$JobStatusValue</value>"
    "  <ValueLookup>$valueLookup</ValueLookup>"
    "  <showChart>1</showChart>"
    "  <showTable>1</showTable>"
    "</result>"
}
"</prtg>"

# kill remoting session
if ($RemoteSession) { Remove-PSSession -Session $RemoteSession }

#endregion



#region Debug output
if ($DebugOutput) {
}

#endregion
