<#
    .SYNOPSIS
        PRTG Advanced Sensor - (Custom) Sensor deployment

    .DESCRIPTION
        This custom sensor will download a folder structure with files from Azure Storage Account into the local probe directory.
        Depending on the enabled features in monitoring contract, the local folder will forced to be the exact same as
        the conotent in the Storage Account.

        The sensor is designed to run in the probe-device of prtg remote probe.
        Script is designed to run in context of the probe (no windows login/service account needed)
        Script is designed to run with prtg system variables, that provide linuxuser and linuxpassword credentials as environmentvariables.

        WebProxy settings currently not supported in sensor. Script expects HTTPS WAN access to Azure Storage Accounts

    .PARAMETER SASURI
        URL and SAS Token as a full URL

        Expected as specified linux password within PRTG

    .PARAMETER FeatureString
        The contract features as a comma separed list for the prtg remote probe

        Expected values are:
        - EnableSensorSync = Files from Azure Storage Account are provided for the probe
        - EnableCustomerSensors = Probe can have own, inividual/additional sensors/scripts

    .PARAMETER ExcludeFromSync
        Name of files to exclude from sync
        Names can be specified as a "like-filter". So wildcards and partitial names are possible

    .PARAMETER ProtectedFile
        filenames not to be touched by sensor deployment
        By default, ths sensordepyloyment script is a protected file.

    .PARAMETER Destination
        The folder where to sync the files
        By default, this should be the "custom sensor" directory within the probe

    .PARAMETER LogFile
        Fullname of the (optional) logfile.

    .EXAMPLE
        PS C:\> Invoke-PrtgSensorDeployment.ps1

        Necessary values will be queried from the environment variables, as long as the sensor/script executes with prtg environment variables.

    .Notes
        Invoke-PrtgSensorDeployment
        Author: Andreas Bellstedt
        LASTEDIT: 2022/11/25
        VERSION: 1.0.0
        KEYWORDS: PRTG, ManagedServices

    .LINK
        https://github.com/AndiBellstedt/PRTG
#>
#Requires -Version 3
[CmdletBinding(
    ConfirmImpact = "Medium",
    PositionalBinding = $true
)]
param(
    [String]
    $SASURI = (.{ if ($env:prtg_linuxpassword) { $env:prtg_linuxpassword } }),

    [String]
    $FeatureString = (.{ if ($env:prtg_linuxuser) { $env:prtg_linuxuser } }),

    [Alias("Exclude", "Filter")]
    [string[]]
    $ExcludeFromSync,

    [string[]]
    $ProtectedFile = "Invoke-PRTGSensorDeployment.ps1",

    [String]
    $Destination = "$(Get-Process -Name "PRTG Probe" | Select-Object -ExpandProperty Path | Split-Path)\Custom Sensors",

    [string]
    $LogFile #= "C:\Administration\Logs\PRTGSensorDeployment_$(Get-Date -Format "yyyy-MM-dd").log"
)



#region helper functions
# PRTG error handling
trap {
    Write-Output "<prtg>"
    Write-Output " <error>1</error>"
    Write-Output " <text>$($_.ToString())</text>"
    Write-Output "</prtg>"

    exit 1
}

function Get-BlobChildItem {
    <#
    .Synopsis
        Get-BlobChildItem

    .DESCRIPTION
        List content of an Azure blob storage container

    .PARAMETER StorageUrl
        The url of the azure storage account with the blob to query

        Only the URL without query parameter or SAS token is needed.
        Query parameter or SAS token will be ignored in this url.

    .PARAMETER SASToken
        The access token string to authenticate the connection request

    .EXAMPLE
        PS C:\> Get-BlobChildItem -StorageUrl "https://mystorageaccount.blob.core.windows.net/myblob" -SASToken $token

        Query the content from the blob 'myblob' within the storageaccount "mystorageaccount"

        Authenticatin is done via SAS token, which has to be given as a SecureString:
        $token = Read-Host -AsSecureString -Prompt "SAS Token please"

    .NOTES
        Author: Andreas Bellstedt

    .LINK
        https://github.com/AndiBellstedt/
    #>
    [CmdletBinding(
        ConfirmImpact = "Low",
        PositionalBinding = $true
    )]
    param (
        [Parameter(Mandatory = $true)]
        [Alias("URL")]
        [uri]
        $StorageUrl,

        [Parameter(Mandatory = $true)]
        [Alias("SAS", "Token")]
        [securestring]
        $SASToken
    )


    $sasTokenCredential = [pscredential]::new('token', $SASToken)
    $_url = $StorageUrl.Scheme + "://" + $StorageUrl.Host + $StorageUrl.AbsolutePath + "?restype=container&comp=list&" + $($sasTokenCredential.GetNetworkCredential().Password)
    $response = Invoke-RestMethod -Uri $_url -Method Get

    #cleanup answer and convert body to XML
    $xml = [xml]$response.Substring($response.IndexOf('<'))

    foreach ($file in $xml.ChildNodes.Blobs.Blob) {
        $_folderPath = "/" + $file.Name.Replace($file.Name.Split("/")[-1], "")
        $hash = [ordered]@{
            PSTypeName         = 'Azure.BlobItem'
            "FolderPath"       = $_folderPath
            "Name"             = $file.Name.Split("/")[-1]
            "FullName"         = $file.Name
            "VersionId"        = $file.VersionId
            "IsCurrentVersion" = $file.IsCurrentVersion
        }
        foreach ($property in ($file.Properties | Get-Member -MemberType Property).Name) {
            $hash.Add($property, $file.Properties.$property)
        }

        $hash.Add("URI", "$($StorageUrl.Scheme)://$($StorageUrl.Host)$($StorageUrl.AbsolutePath)/$($file.Name)")

        [PSCustomObject]$hash
    }
}

function Save-BlobItem {
    <#
    .Synopsis
        Save-BlobItem

    .DESCRIPTION
        Save/download a file from an Azure blob storage account

    .PARAMETER StorageUrl
        The url of the azure storage account with the blob to query

        Only the URL without query parameter or SAS token is needed.
        Query parameter or SAS token will be ignored in this url.

    .PARAMETER SASToken
        The access token string to authenticate the connection request

    .PARAMETER Path
        The path to save the file into

    .PARAMETER Force
        Overwrite the file, if it exists

    .PARAMETER PassThru
        Output the saved file to the console

    .EXAMPLE
        PS C:\> Save-BlobItem -StorageUrl "https://mystorageaccount.blob.core.windows.net/myblob/folder/file.txt" -SASToken $token

        Save the file 'file.txt' from the blob 'myblob' within the storageaccount "mystorageaccount"

        Authenticatin is done via SAS token, which has to be given as a SecureString:
        $token = Read-Host -AsSecureString -Prompt "SAS Token please"

    .EXAMPLE
        PS C:\> Get-BlobChildItem -StorageUrl "https://mystorageaccount.blob.core.windows.net/myblob/" -SASToken $token | Save-BlobItem -Path C:\AZDownload -SASToken $token

        Save all files with folder structure from the blob 'myblob' within the storageaccount "mystorageaccount" to the current directory

        Authenticatin is done via SAS token, which has to be given as a SecureString:
        $token = Read-Host -AsSecureString -Prompt "SAS Token please"

    .NOTES
        Author: Andreas Bellstedt

    .LINK
        https://github.com/AndiBellstedt
    #>
    [CmdletBinding(
        ConfirmImpact = "Medium",
        PositionalBinding = $true
    )]
    param (

        [Parameter(
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = "true",
            Mandatory = $true
        )]
        [Alias("URL", "URI")]
        [uri[]]
        $StorageUrl,

        [Parameter(Mandatory = $true)]
        [Alias("SAS", "Token")]
        [securestring]
        $SASToken,

        [ValidateNotNullOrEmpty()]
        [Alias("OutPath", "FilePath")]
        [string]
        $Path = (Get-Location),

        [switch]
        $Force,

        [switch]
        $PassThru
    )

    begin {
        $sasTokenCredential = [pscredential]::new('token', $SASToken)
    }

    process {
        foreach ($url in $StorageUrl) {
            [uri]$_url = $url.Scheme + "://" + $url.Host + $url.AbsolutePath + "?" + $($sasTokenCredential.GetNetworkCredential().Password)
            #$filePath = [string]::Join("", $_url.Segments[2 .. ($_url.Segments.Count - 1)])
            $filePath = $_url.LocalPath.Trim("/").Substring( $_url.LocalPath.Trim("/").IndexOf("/")).Trim("/")
            Write-Verbose "Working on file $($filePath)"

            # Create folder structure if there is one
            if (Split-Path $filePath) {
                $_path = Join-Path $Path (Split-Path $filePath)
                if (-not (Test-Path -Path $_path)) {
                    Write-Verbose "Creating directory $($_path)"
                    $folder = New-Item -Path $_path -ItemType Directory -Force
                } else {
                    $folder = Get-Item -Path $_path
                }
            } else {
                $folder = Get-Item -Path $Path
            }

            # Download the file
            $destFile = Join-Path -Path $folder.FullName -ChildPath $_url.Segments[-1]
            if (Get-Item -Path $destFile -ErrorAction Ignore) {
                if ($Force) {
                    Remove-Item -Path $destFile -Force -Confirm:$false
                } else {
                    Write-Warning "File '$($_url.Segments[-1])' already present in '$($folder.FullName)'! Skipping download"
                    continue
                }
            }

            $webclient = New-Object System.Net.WebClient
            $webclient.DownloadFile($_url, $destFile)

            if ($PassThru) { Get-Item -Path $destFile }
        }
    }

    end {
    }
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

function Invoke-Filtering {
    [CmdletBinding(
        ConfirmImpact = "Low",
        PositionalBinding = $true
    )]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $List,

        $Exclude = $ExcludeFromSync,

        $PropertyName = "Name"
    )

    [Array]$toRemove = @()
    $toRemove = foreach ($filterItem in $Exclude) {
        $List | Where-Object $PropertyName -Like $filterItem
    }
    $toRemove = $toRemove | Select-Object * -Unique

    $List | Where-Object $PropertyName -NotIn $toRemove.$PropertyName
}
#endregion helper functions



#region Init & Variables
if ($LogFile) {
    $PSDefaultParameterValues = @{
        "Out-File:FilePath" = $LogFile
        "Out-File:Encoding" = "default"
        "Out-File:Append"   = $true
        "Out-File:Force"    = $true
    }
}

if ($SASURI) {
    [uri]$StorageUrl = $SASURI.Split("?")[0]
    [System.Security.SecureString]$SASToken = $SASURI.Split("?")[1] | ConvertTo-SecureString -AsPlainText -Force
}

if ($FeatureString) {
    $features = $FeatureString.Split(",").Trim(" ")
}

[array]$filesToDownload = @()

if (-not (Test-Path $Destination)) { throw "Path $($Destination) not found" }
#endregion Init & Variables



#region main script
$msg = "$(Get-Date -Format s), ***** Starting script $($MyInvocation.MyCommand.Name)"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

# Query content
$filesLocalAll = Get-ChildItem -Path $Destination -Recurse -File | Select-Object *, @{n = "Compare"; e = { $_.FullName.replace($Destination, '').trim("\") } }, @{n = "Hash"; e = { Get-FileHash -Path $_.FullName -Algorithm MD5 | Select-Object -ExpandProperty hash } }
$filesLocal = Invoke-Filtering -List $filesLocalAll -Exclude $ExcludeFromSync -PropertyName "Name"
$msg = "$(Get-Date -Format s), Files in $($Destination): $($filesLocal.Count) effective / $($filesLocalAll.Count) all"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

if ($StorageUrl) {
    $filesInBlobAll = Get-BlobChildItem -StorageUrl $StorageUrl -SASToken $SASToken | Select-Object *, @{n = "Compare"; e = { $_.FullName.replace("/", "\").trim("\") } }, @{n = "Hash"; e = { [string]::Join("", ([System.Convert]::FromBase64String($_.'Content-MD5') | ForEach-Object { '{0:X2}' -f [int]$_ })) } }
    $filesInBlob = Invoke-Filtering -List $filesInBlobAll -Exclude $ExcludeFromSync -PropertyName "Name"
    $msg = "$(Get-Date -Format s), Files blob ($StorageUrl): $($filesInBlob.Count) effective / $($filesInBlobAll.Count) all"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

    $fileCompare = Compare-Object -ReferenceObject $filesInBlob -DifferenceObject $filesLocal -Property Compare -PassThru -IncludeEqual
    $msg = "$(Get-Date -Format s), Compare result: $(($fileCompare | Where-Object SideIndicator -like "==").Count) both sides / $(($fileCompare | Where-Object SideIndicator -like "<=").Count) locally missing / $(($fileCompare | Where-Object SideIndicator -like "<=").Count) not in blob"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }
}


# Enforce contract compliance
if ("EnableCustomerSensors" -NotIn $features) {
    if ($fileCompare) {
        # select uncompliant files
        [array]$filesLocalToDelete = $fileCompare | Where-Object SideIndicator -like "=>"
        $msg = "$(Get-Date -Format s), Found $($filesLocalToDelete.Count) files locally to remove"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }
        $filesLocalToDelete | Remove-Item -Force -Confirm:$false

        # query local files again
        $filesLocalAll = Get-ChildItem -Path $Destination -Recurse -File | Select-Object *, @{n = "Compare"; e = { $_.FullName.replace($Destination, '').trim("\") } }, @{n = "Hash"; e = { Get-FileHash -Path $_.FullName -Algorithm MD5 | Select-Object -ExpandProperty hash } }
        $filesLocal = Invoke-Filtering -List $filesLocalAll -Exclude $ExcludeFromSync -PropertyName "Name"
        $msg = "$(Get-Date -Format s), Again, files in $($Destination): $($filesLocal.Count) effective / $($filesLocalAll.Count) all"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

        # build compare again
        $fileCompare = Compare-Object -ReferenceObject $filesInBlob -DifferenceObject $filesLocal -Property Compare -PassThru -IncludeEqual
        $msg = "$(Get-Date -Format s), Again, compare result: $(($fileCompare | Where-Object SideIndicator -like "==").Count) both sides / $(($fileCompare | Where-Object SideIndicator -like "<=").Count) locally missing / $(($fileCompare | Where-Object SideIndicator -like "<=").Count) not in blob"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }
    } else {
        # select uncompliant files
        $filesLocalToDelete = Invoke-Filtering -List $filesLocal -Exclude $ProtectedFile -PropertyName "Name"
        $msg = "$(Get-Date -Format s), $($filesLocalToDelete.Count) files locally to cleanup"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }
        $filesLocalToDelete | Remove-Item  -Force -Confirm:$false
    }
}


# Check SensorSync
if ("EnableSensorSync" -in $features) {
    if ($filesInBlob) {
        # Sync changes
        $filesBothSides = $fileCompare | Where-Object SideIndicator -like "=="
        $msg = "$(Get-Date -Format s), $($filesBothSides.Count) files already synced"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

        # Detect modified files
        [array]$filesToDownload += Compare-Object -ReferenceObject $filesBothSides -DifferenceObject ($filesLocal | Where-Object compare -in $filesBothSides.compare) -Property Hash -PassThru | Where-Object SideIndicator -like "<="
        $msg = "$(Get-Date -Format s), $($filesToDownload.Count) Locally modified files: $([string]::Join(", ", $filesToDownload.name))"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

        # new files to download
        [array]$filesToDownload += $fileCompare | Where-Object SideIndicator -like "<="
        $msg = "$(Get-Date -Format s), $($fileCompare | Where-Object SideIndicator -like "<=" | Measure-Object | Select-Object -ExpandProperty count) new files in blob: $([string]::Join('', ($fileCompare | Where-Object SideIndicator -like "<=" | Select-Object -ExpandProperty Name)))"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

        # download files
        $msg = "$(Get-Date -Format s), Going to download $($filesToDownload.count) files"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }
        $filesDownloaded = $filesToDownload | Save-BlobItem -Path $Destination -SASToken $SASToken -Force -PassThru -Verbose
        $msg = "$(Get-Date -Format s), $($filesDownloaded.count) files: $([string]::Join(", ", $filesDownloaded.Name))"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

        # Output PRTG object
        $fileDiff = $filesInBlob.Count - $filesLocal.Count
        if ($fileDiff -lt 0) { $fileDiff = $fileDiff * -1 }
        $msg = "$(Get-Date -Format s), Files in blob $($filesInBlob.Count)"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }
        $msg = "$(Get-Date -Format s), Files locallly $($filesLocal.Count)"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }
        $msg = "$(Get-Date -Format s), Deviation $($fileDiff)"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

        "<prtg>"
        Out-PrtgChannel -Channel "Files in blob" -Value $filesInBlob.Count -Float $false -ShowTable
        Out-PrtgChannel -Channel "Files locallly" -Value $filesLocal.Count -Float $false -ShowTable
        Out-PrtgChannel -Channel "Deviation" -Value $fileDiff -Float $false -ShowTable -ShowChart
        Out-PrtgChannel -Channel "Synced files" -Value $filesDownloaded.count -Float $false -ShowTable
        "<text>Sensor sync in palce. Current featureset: $($features)</text>"
        "</prtg>"
    } else {
        throw "SensorSync endabled, but now no files in blob"
    }
} else {
    # Output PRTG object
    $msg = "$(Get-Date -Format s), Sensor sync not enabled (Current featureset: $([String]::Join(", ", $features)))"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }

    "<prtg>"
    Out-PrtgChannel -Channel "Files locallly" -Value $filesLocal.Count -Float $false -ShowTable
    Out-PrtgChannel -Channel "Synced files" -Value 0 -Float $false -ShowTable
    "<text>$($msg)</text>"
    "</prtg>"
}

$msg = "$(Get-Date -Format s), ***** Finish script"; Write-Verbose $msg; if ($LogFile) { $msg | Out-File }
#endregion main script
