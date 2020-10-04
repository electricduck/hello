#  _   _      _ _         ____  
# | | | | ___| | | ___   / /\ \ 
# | |_| |/ _ \ | |/ _ \ / /  \ \
# |  _  |  __/ | | (_) / /   / /
# |_| |_|\___|_|_|\___/_/   /_/
# ======================= 20.7 =
# #[Box:~]###########################################################[-][o][x]#
# #                                                                           #
# #        ###############                                                    #
# #       ##   ##########  $ PowerShell 7.0.0                                 #
# #      ####   ########   # 12345 (00000000-0000-0000-0000-000000000000)     #
# #     ######   ######    ~ Windows 10 2009 (October 2020)                   #
# #    ####   ########     @ Box\Me                                           #
# #   ##   ###     ##      + 123 hours (5 days)                               #
# #  ###############                                                          #
# #                                                                           #
# # ~ > How-ToInstall                                                         #
# #                                                                           #
# #     1) Download this file, and save it as 'Install-Hello.ps1'             #
# #     2) Run './Install-Profile.ps1'                                        #
# #     3) Watch the magic happen                                             #
# #     4) Restart your shell                                                 #
# #                                                                           #
# #############################################################################

#region Global variables

enum PSCompat {
    UnknownCompat
    Core
    Legacy
}

enum OS {
    UnknownOS
    Linux
    MacOS
    Windows
}

$HelloVersion = "20.7"
$HostName = [net.dns]::GetHostName()
[OS]$HostOS = [OS]::UnknownOS
$HostUnicode = (([Console]::OutputEncoding).CodePage) -in 65001, 1208, 4110
$HostUsername = [System.Environment]::UserName
[PSCompat]$PSCompat = [PSCompat]::UnknownCompat
$PSVersion = $PSVersionTable.PSVersion

if ($PSVersion.Major -lt 6) {
    $PSCompat = [PSCompat]::Legacy
    $HostOS = [OS]::Windows
}
else {
    $PSCompat = [PSCompat]::Core

    if ($IsWindows) {
        $HostOS = [OS]::Windows
    }
    elseif ($IsMacOS) {
        $HostOS = [OS]::MacOS
    }
    elseif ($IsLinux) {
        $HostOS = [OS]::Linux
    }
}

#endregion

#region Settings

function Set-HelloDefaultSetting {
    Param(
        [ValidateSet("AllowUnsupported", "Caret", "ColorAccent", "ColorHigh", "ColorLow", "UseBuiltInPrompt")]
        [string]$Key,
        [object]$DefaultValue
    )
    
    if (!([Environment]::GetEnvironmentVariable("HELLO_$Key", "Process"))) {
        [Environment]::SetEnvironmentVariable("HELLO_$Key", $DefaultValue, "Process")
    }
}

if ($HostUnicode) {
    Set-HelloDefaultSetting -Key "Caret" -DefaultValue "➜"
}
else {
    Set-HelloDefaultSetting -Key "Caret" -DefaultValue ">"
}

Set-HelloDefaultSetting -Key "AllowUnsupported" -DefaultValue $false
Set-HelloDefaultSetting -Key "ColorAccent" -DefaultValue "Cyan"
Set-HelloDefaultSetting -Key "ColorHigh" -DefaultValue "White"
Set-HelloDefaultSetting -Key "ColorLow" -DefaultValue "Gray"
Set-HelloDefaultSetting -Key "UseBuiltInPrompt" -DefaultValue $false

#endregion

#region Functions

function Assert-HelloSupportedPowershell {
    if (
        ($PSCompat -eq [PSCompat]::Core) -or
        ($PSVersion.Major -eq 5 -and $PSVersion.Minor -ge 1)
    ) {
        $true
    }
    else {
        $false
    }
}

function Assert-HelloUseBuiltInPrompt {
    if ($env:HELLO_UseBuiltInPrompt -eq $true) {
        $true
    }
    else {
        if (Get-Command "starship" -ErrorAction SilentlyContinue) {
            Invoke-Expression (&starship init powershell)
            $false
        }
        else {
            $true
        }
    }
}

function Get-HelloLogoPart {
    Param(
        [int]$Line,
        [int]$Padding = 1
    )

    if ($Padding -gt 0) {
        0..($Padding - 1) | ForEach-Object { "" }
    }

    switch ($Line) {
        0 { "      ############### " }
        1 { "     ##   ##########  " }
        2 { "    ####   ########   " }
        3 { "   ######   ######    " }
        4 { "  ####   ########     " }
        5 { " ##   ###     ##      " }
        6 { "###############       " }
    }
}

function Get-HelloOSDetails {
    $HelloOSDetailsReturn = New-Object -TypeName PSObject

    $HostOSName = ""
    $HostOSRelease = ""
    $HostOSVersion = [Environment]::OSVersion.Version

    switch ($HostOS) {
        Linux {
            $LinuxOSRelease = if (Test-Path /etc/os-release) {
                (Get-Content /etc/os-release)
            }

            if ($LinuxOSRelease) {
                $HostOSName = (($LinuxOSRelease | select-string "NAME")[0].ToString().Replace("NAME=", "").Replace("`"", "")).
                Replace("elementary OS", "elementaryOS").
                Replace("Debian GNU/Linux", "Debian")

                $HostOSRelease = ($LinuxOSRelease | select-string "VERSION")[0].ToString().Replace("VERSION=", "").Replace("`"", "")
            }
            else {
                $HostOSName = "Linux"
                $HostOSRelease = "$($HostOSVersion.Major).$($HostOSVersion.Minor).$($HostOSVersion.Build)"
            }
        }
        MacOS {
            $HostOSName = if ($HostOSVersion.Build -lt 16) {
                "OSX"
            }
            elseif ($HostOSVersion.Build -le 16) {
                "macOS"
            }

            $HostOSRelease = "$($HostOSVersion.Major).$($HostOSVersion.Minor)"
        }
        Windows {
            $WindowsCurrentVersion = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"

            $HostOSName = if ($WindowsCurrentVersion.ProductName) {
                $WindowsCurrentVersion.ProductName.
                Replace("Microsoft Windows", "Windows")
            }
            else {
                "Windows"
            }

            $HostOSRelease = if ($WindowsCurrentVersion.CSDVersion) {
                $WindowsCurrentVersion.CSDVersion
            }
            elseif ($WindowsCurrentVersion.ReleaseId) {
                $WindowsCurrentVersion.ReleaseId
            }
            elseif ($HostOSVersion.Build -ge 9841) {
                "Build $($HostOSVersion.Build)"
            }
            elseif (
                # TODO: Better way of picking up official builds that don't have a ReleaseId/CSDVersion
                $HostOSVersion.Build -in 7600, 9200, 9600, 10240 # 7600: 7 / 2008 R2; 9200: 8 / 2012; 9600: 8.1 / 2012 R2; 10240: 10 1507
            ) {
                ""
            }
            else {
                "$($HostOSVersion.Major).$($HostOSVersion.Minor).$($HostOSVersion.Build)"
            }
        }
    }

    $HelloOSDetailsReturn | Add-Member -MemberType NoteProperty -Name Name -Value $HostOSName
    $HelloOSDetailsReturn | Add-Member -MemberType NoteProperty -Name Release -Value $HostOSRelease
    $HelloOSDetailsReturn | Add-Member -MemberType NoteProperty -Name Version -Value $HostOSVersion

    $HelloOSDetailsReturn
}

function Get-HelloProcess {
    $HelloProcessReturn = New-Object -TypeName PSObject

    $HelloProcessReturn | Add-Member -MemberType NoteProperty -Name InstanceId -Value $Host.InstanceId
    $HelloProcessReturn | Add-Member -MemberType NoteProperty -Name PID -Value $PID

    $HelloProcessReturn
}

function Get-HelloUptime {
    function Get-Suffix {
        Param(
            [int]$Amount,
            [string]$SingularPrefix = "day",
            [string]$PluralPrefix = "days"
        )

        if ($Amount -eq 1) {
            $SingularPrefix
        }
        else {
            $PluralPrefix
        }
    }

    $HelloUptimeReturn = New-Object -TypeName PSObject
    $UptimeOutput = $null

    if ($PSCompat -eq [PSCompat]::Legacy) {
        $Win32OSObject = Get-WmiObject win32_operatingsystem
        $UptimeOutput = (Get-Date) - ($Win32OSObject.ConvertToDateTime($Win32OSObject.lastbootuptime))
    }
    else {
        $UptimeOutput = Get-Uptime
    }

    $HelloUptimeReturn | Add-Member -MemberType NoteProperty -Name Days -Value $UptimeOutput.Days
    $HelloUptimeReturn | Add-Member -MemberType NoteProperty -Name Hours -Value $UptimeOutput.TotalHours
    $HelloUptimeReturn | Add-Member -MemberType NoteProperty -Name HoursRounded -Value ([Math]::Round($UptimeOutput.TotalHours))
    $HelloUptimeReturn | Add-Member -MemberType NoteProperty -Name DaySuffix -Value (Get-Suffix -Amount $HelloUptimeReturn.Days -SingularPrefix "day" -PluralPrefix "days")
    $HelloUptimeReturn | Add-Member -MemberType NoteProperty -Name HourSuffix -Value (Get-Suffix -Amount $HelloUptimeReturn.HoursRounded -SingularPrefix "hour" -PluralPrefix "hours")

    $HelloUptimeReturn
}

function Write-HelloPrompt {
    $Path = (Get-Location).Path
    $ShortPath = Split-Path -leaf -path $Path

    if ($Path -eq "/") {
        $ShortPath = "/"
    }

    if ($Path -eq $HOME) {
        $ShortPath = "~"
    }

    $Host.UI.RawUI.WindowTitle = "$($HostName):$Path"

    Write-Host " "
    Write-Host $ShortPath -f $env:HELLO_ColorLow -n
    Write-Host " $env:HELLO_Caret" -f $env:HELLO_ColorAccent -n
}

function Write-Hello {
    function Write-LinePrefix {
        Param(
            [int]$Line,
            [string]$Icon,
            [ConsoleColor]$IconColor = [ConsoleColor]::White
        )

        Write-Host (Get-HelloLogoPart -Line $Line) -ForegroundColor $env:HELLO_ColorAccent -n
    
        if ($Icon) {
            Write-Host "$Icon " -f $IconColor -n
        }
        else {
            Write-Host " "
        }
    }

    $HostOSDetails = Get-HelloOSDetails
    $Process = Get-HelloProcess
    $Uptime = Get-HelloUptime

    Write-Host " "
    Write-LinePrefix -Line 0

    Write-LinePrefix -Line 1 -Icon "$" -IconColor Red
    Write-Host "PowerShell " -ForegroundColor $env:HELLO_ColorHigh -n
    Write-Host $PSVersion -ForegroundColor $env:HELLO_ColorLow

    Write-LinePrefix -Line 2 -Icon "#" -IconColor Yellow
    Write-Host $Process.PID -ForegroundColor $env:HELLO_ColorHigh -n
    Write-Host " ($($Process.InstanceId))" -ForegroundColor $env:HELLO_ColorLow

    Write-LinePrefix -Line 3 -Icon "~" -IconColor Green
    Write-Host $HostOSDetails.Name -ForegroundColor $env:HELLO_ColorHigh -n
    Write-Host " $($HostOSDetails.Release)" -ForegroundColor $env:HELLO_ColorLow

    Write-LinePrefix -Line 4 -Icon "@" -IconColor Cyan
    Write-Host $HostName -ForegroundColor $env:HELLO_ColorHigh -n
    Write-Host "/" -ForegroundColor $env:HELLO_ColorLow -n
    Write-Host $HostUsername -ForegroundColor $env:HELLO_ColorHigh

    Write-LinePrefix -Line 5 -Icon "+" -IconColor Magenta
    Write-Host "$($Uptime.HoursRounded) $($Uptime.HourSuffix)" -ForegroundColor $env:HELLO_ColorHigh -n
    if ($Uptime.Days -ne 0) {
        Write-Host " ($($Uptime.Days) $($Uptime.DaySuffix))" -ForegroundColor $env:HELLO_ColorLow
    }
    else {
        Write-Host ""
    }

    Write-LinePrefix -Line 6
}

function Update-Hello {
    Param(
        [bool]$Online = $true,
        [string]$Path = "",
        [bool]$DevBranch = $false
    )

    function Write-StatusMessage {
        Param(
            [string]$Message,
            [string[]]$Messages,
            [ValidateSet("Debug", "Doing", "Error", "Message", "Success")]
            [string]$Type = "Doing",
            [bool]$Timestamp = $false
        )

        $MessageColor = switch ($Type) {
            "Debug" { [ConsoleColor]::DarkGray }
            "Doing" { [ConsoleColor]::Cyan }
            "Error" { [ConsoleColor]::Red }
            "Message" { [ConsoleColor]::White }
            "Success" { [ConsoleColor]::Green }
        }
        $MessagePrefix = ""
        
        if ($Type -ne "Message") {
            $MessagePrefix = "[$(Get-Date -Format 'HH:mm:ss.ffff')]"
        }
        else {
            $MessagePrefix = "               "
        }

        if (!$Messages) {
            $Messages = @($Message)
        }

        foreach ($Message in $Messages) {
            Write-Host $MessagePrefix -n -ForegroundColor $env:HELLO_ColorLow
            Write-Host " $Message" -ForegroundColor $MessageColor
        }
    }

    if ((Assert-HelloSupportedPowershell) -eq $false) {
        Write-StatusMessage "Unsupported PowerShell version ($($PSVersion.Major).$($PSVersion.Minor))" -Type "Error"
        Write-StatusMessage "Set `$env:HELLO_AllowUnsupported to `$true to continue with installation" -Type "Debug"

        if ($env:HELLO_AllowUnsupported -eq $false) {
            Exit 0
        }
    }

    if (!(Test-Path $PROFILE)) {
        Write-StatusMessage "Creating PowerShell profile..."
        Write-StatusMessage $PROFILE -Type "Debug"
        New-Item $PROFILE -ItemType File -Force | Out-Null
    }
    else {
        if ((Select-String -Path $PROFILE -Pattern "#  ____  _                           ___")) {
            Write-StatusMessage "Deleting old Plunge install..." -Type "Doing"
            Clear-Content $PROFILE -Force | Out-Null
        }
    }

    $InstallLocation = "$(((Get-Item $PROFILE).Directory).FullName)/hello.ps1".Replace("\", "/")
    $InstallSource = $Path
    $OnlineInstallLocation = ($InstallLocation + "_tmp")
    $OnlineInstallUrl = "https://raw.githubusercontent.com/electricduck/hello/" + (@( { release }, { develop })[$DevBranch]).ToString().Trim() + "/Install-Hello.ps1"
    $IsInstalled = (Test-Path $InstallLocation)
    $NewVersion = $HelloVersion
    $DotSource = ". $InstallLocation"
    $InstallMessagePrefix = (@( { Installing }, { Updating })[$IsInstalled]).ToString().Trim()

    if ($Online) {
        $InstallSource = $OnlineInstallLocation
        Write-StatusMessage "Downloading from Github..."
        Invoke-WebRequest $OnlineInstallUrl -out $InstallSource | Out-Null
    }

    Write-StatusMessage "$InstallMessagePrefix..."
    Write-StatusMessage $InstallLocation -Type "Debug"
    Copy-Item $InstallSource $InstallLocation -Force

    if (!(Select-String -Path $PROFILE -Pattern $DotSource)) {
        Write-StatusMessage "Appending to profile..."
        Add-Content $PROFILE $DotSource
    }

    Write-StatusMessage "Cleaning up..."
    $OriginalFile = Get-Content $InstallLocation
    $OriginalBytes = $OriginalFile.Length
    $ModifiedFile = $OriginalFile

    if ($Online) {
        Remove-Item $OnlineInstallLocation -Force | Out-Null
    }
    
    $ModifiedFile = $ModifiedFile | Where-Object { $_.trim() -ne "" } # Remove blank lines
    $ModifiedFile = $ModifiedFile.Trim() # Trim excess spaces
    #$ModifiedFile = $ModifiedFile | Where-Object { -not ([String]::IsNullOrEmpty($_.Trim()) -or $_-match"^\s*# ") } | ForEach-Object { $_ -replace "(.*)(# .*)",'$1' } # Remove comments

    Set-Content -Value $ModifiedFile -Path $InstallLocation

    $ModifiedBytes = $ModifiedFile.Length
    $SavedBytes = $OriginalBytes - $ModifiedBytes
    $SavedBytesPercentage = (($ModifiedBytes - $OriginalBytes) / $OriginalBytes) * -1 * 100
    Write-StatusMessage "Shrunk by $([Math]::Round($SavedBytesPercentage, 2))% ($SavedBytes bytes)" -Type "Debug"
    
    $NewVersion = (Select-String -Path $InstallLocation -Pattern '^\$HelloVersion\s=\s"(\d+\.\d+)"$').Matches.Groups[1].Value
    if ($DevBranch) {
        $NewVersion = "$NewVersion-dev"
    }

    Write-StatusMessage "Hello $NewVersion installed!" -Type "Success"
    Write-StatusMessage -Messages @("Keep Hello updated by running Update-Hello", "Bug reports can be filed to https://github.com/electricduck/hello/issues", "", "To begin, restart your shell") -Type "Message"
}

function Restart-Shell {
    Clear-Host
    Write-Hello
}

#endregion

#region Startup

if ($MyInvocation.MyCommand.Name.ToLower() -eq "install-hello.ps1") {
    Update-Hello -Online $false -Path $MyInvocation.MyCommand.Path
    Exit 0
}

if ($Host.Name.ToString() -eq "ConsoleHost") {
    Restart-Shell

    if ((Assert-HelloUseBuiltInPrompt)) {
        function prompt {
            Write-HelloPrompt
            return ' '
        }
    }
}

#endregion