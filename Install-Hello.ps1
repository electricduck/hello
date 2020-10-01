#  _   _      _ _         ____  
# | | | | ___| | | ___   / /\ \ 
# | |_| |/ _ \ | |/ _ \ / /  \ \
# |  _  |  __/ | | (_) / /   / /
# |_| |_|\___|_|_|\___/_/   /_/
# ======================= 20.4 =
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

Set-Alias -Name clear -Value Restart-Shell -Option AllScope

enum PSCompat {
    UnknownEdition
    Core
    Legacy
}

enum OS {
    UnknownOS
    Linux
    MacOS
    Windows
}

$HelloVersion = "20.4"
$HostEncoding = ([Console]::OutputEncoding).CodePage
$Hostname = ([net.dns]::GetHostName())
$HostUsername = ([System.Environment]::UserName)
[OS]$OS = [OS]::UnknownOS
[PSCompat]$PSCompat = [PSCompat]::UnknownEdition
$PSVersion = $PSVersionTable.PSVersion

if ($PSVersion.Major -lt 6) {
    $PSCompat = [PSCompat]::Legacy
    $OS = [OS]::Windows
}
else {
    $PSCompat = [PSCompat]::Core

    if ($IsWindows) {
        $OS = [OS]::Windows
    }
    elseif ($IsMacOS) {
        $OS = [OS]::MacOS
    }
    elseif ($IsLinux) {
        $OS = [OS]::Linux
    }
}

function Assert-HelloSupportedPowershell {
    if (
        ($PSVersion.Major -ge 7) -or
        ($PSVersion.Major -eq 6 -and $PSVersion.Minor -ge 2) -or
        ($PSVersion.Major -eq 5 -and $PSVersion.Minor -ge 1)
    ) {
        $true
    }
    else {
        $false
    }
}

function Assert-HelloUseBuiltInPrompt {
    if (Get-Command "starship" -ErrorAction SilentlyContinue) {
        Invoke-Expression (&starship init powershell)
        $false
    }
    else {
        $true
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

    $OSName = ""
    $OSRelease = ""
    $OSVersion = [Environment]::OSVersion.Version

    $LinuxOSRelease = $null
    $WindowsCurrentVersion = $null

    if ($OS -eq [OS]::Linux) {
        if (Test-Path /etc/os-release) {
            $LinuxOSRelease = (Get-Content /etc/os-release)
        }
    }

    if ($OS -eq [OS]::Windows) {
        $WindowsCurrentVersion = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    }

    function Get-OSName {
        switch ($OS) {
            Linux {
                if ($LinuxOSRelease) {
                    (($LinuxOSRelease | select-string "NAME")[0].ToString().Replace("NAME=", "").Replace("`"", "")).
                    Replace("elementary OS", "elementaryOS").
                    Replace("Debian GNU/Linux", "Debian")
                }
                else {
                    "Linux"
                }
            }
            MacOS {
                if ($OSVersion.Build -lt 16) {
                    "OSX"
                }
                elseif ($OSVersion.Build -le 16) {
                    "macOS"
                }
            }
            Windows {
                if ($WindowsCurrentVersion.ProductName) {
                    $WindowsCurrentVersion.ProductName.
                    Replace("Microsoft Windows", "Windows")
                }
                else {
                    "Windows"
                }
            }
        }
    }

    function Get-OSRelease {
        switch ($OS) {
            Linux {
                if ($LinuxOSRelease) {
                    ($LinuxOSRelease | select-string "VERSION")[0].ToString().Replace("VERSION=", "").Replace("`"", "")
                }
                else {
                    "$($OSVersion.Major).$($OSVersion.Minor).$($OSVersion.Build)"
                }
            }
            MacOS {
                "$($OSVersion.Major).$($OSVersion.Minor)"
            }
            Windows {
                if ($WindowsCurrentVersion.CSDVersion) {
                    $WindowsCurrentVersion.CSDVersion
                }
                elseif ($WindowsCurrentVersion.ReleaseId) {
                    $WindowsCurrentVersion.ReleaseId
                }
                elseif ($OSVersion.Build -ge 9841) {
                    "Build $($OSVersion.Build)"
                }
                else {
                    "$($OSVersion.Major).$($OSVersion.Minor).$($OSVersion.Build)"
                }
            }
        }
    }

    $OSName = Get-OSName
    $OSRelease = Get-OSRelease

    $HelloOSDetailsReturn | Add-Member -MemberType NoteProperty -Name Name -Value $OSName
    $HelloOSDetailsReturn | Add-Member -MemberType NoteProperty -Name Release -Value $OSRelease
    $HelloOSDetailsReturn | Add-Member -MemberType NoteProperty -Name Version -Value $OSVersion

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

        if ($amount -eq 1) {
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

function Get-PaddedEmoji {
    Param(
        [string]$Emoji
    )

    if ($OS -eq [OS]::Windows) {
        "$Emoji "
    }
    else {
        if ($Emoji.Length -eq 1) {
            "$Emoji "
        }
        else {
            "$Emoji  "
        }
    }
}

function Write-HelloPrompt {
    $Caret = ">"
    $Path = (Get-Location).Path
    $ShortPath = Split-Path -leaf -path $Path

    if ($Path -eq "/") {
        $ShortPath = "/"
    }

    if ($Path -eq $HOME) {
        $ShortPath = "~"
    }

    if ($env:Hello_Caret) {
        $Caret = $env:Hello_Caret
    }
    else {
        if (
            $HostEncoding -eq 65001 -or
            $HostEncoding -eq 1208 -or
            $HostEncoding -eq 4110
        ) {
            $Caret = "➜"
        }
    }

    $Host.UI.RawUI.WindowTitle = "$($Hostname):$Path"

    Write-Host " "
    Write-Host $ShortPath -f Gray -n
    Write-Host " $Caret" -f Cyan -n
}

function Write-Hello {
    function Write-LinePrefix {
        Param(
            [int]$Line,
            [string]$Icon,
            [ConsoleColor]$IconColor = [ConsoleColor]::Gray
        )

        [ConsoleColor]$LogoColor = [ConsoleColor]::Cyan

        if ($env:Hello_LogoColor) {
            $LogoColor = $env:Hello_LogoColor
        }
        else {
            if ($PSVersion.Major -ge 6) {
                $LogoColor = [ConsoleColor]::Blue
            }
        }

        Write-Host (Get-HelloLogoPart -Line $Line) -ForegroundColor $LogoColor -n
    
        if ($Icon) {
            Write-Host "$Icon " -f $IconColor -n
        }
        else {
            Write-Host " "
        }
    }

    $OSDetails = Get-HelloOSDetails
    $Process = Get-HelloProcess
    $Uptime = Get-HelloUptime

    Write-Host " "
    Write-LinePrefix -Line 0

    Write-LinePrefix -Line 1 -Icon "$" -IconColor Red
    Write-Host "PowerShell " -ForegroundColor White -n
    Write-Host $PSVersion -ForegroundColor DarkGray

    Write-LinePrefix -Line 2 -Icon "#" -IconColor Yellow
    Write-Host $Process.PID -ForegroundColor White -n
    Write-Host " ($($Process.InstanceId))" -ForegroundColor DarkGray

    Write-LinePrefix -Line 3 -Icon "~" -IconColor Green
    Write-Host $OSDetails.Name -ForegroundColor White -n
    Write-Host " $($OSDetails.Release)" -ForegroundColor DarkGray

    Write-LinePrefix -Line 4 -Icon "@" -IconColor Cyan
    Write-Host $Hostname -ForegroundColor White -n
    Write-Host "/" -ForegroundColor DarkGray -n
    Write-Host $HostUsername -ForegroundColor White

    Write-LinePrefix -Line 5 -Icon "+" -IconColor Magenta
    Write-Host "$($Uptime.HoursRounded) $($Uptime.HourSuffix)" -ForegroundColor White -n
    if ($Uptime.Days -ne 0) {
        Write-Host " ($($Uptime.Days) $($Uptime.DaySuffix))" -ForegroundColor DarkGray
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
            [string[]]$DebugMessages,
            [string]$Icon = "⚙️",
            [ConsoleColor]$MessageColor = [ConsoleColor]::Yellow,
            [ConsoleColor]$DebugMessagesColor = [ConsoleColor]::DarkGray,
            [bool]$DebugMessagesOnly = $false
        )

        if (!$DebugMessagesOnly) {
            Write-Host (Get-PaddedEmoji $Icon) -n
            Write-Host $Message -ForegroundColor $MessageColor
        }
        
        if ($DebugMessages) {
            foreach ($DebugMessage in $DebugMessages) {
                Write-Host "   $DebugMessage" -ForegroundColor $DebugMessagesColor
            }
        }
    }

    if (!(Assert-HelloSupportedPowershell)) {
        Write-StatusMessage "Unsupported PowerShell version ($($PSVersion.Major).$($PSVersion.Minor))" -Icon "⚠️" -MessageColor Red -DebugMessages @("Set `$env:Hello_AllowUnsupported to `$true to continue with installation")

        if (!($env:Hello_AllowUnsupported -eq $true)) {
            Exit 0
        }
    }

    if (!(Test-Path $PROFILE)) {
        Write-StatusMessage "Creating PowerShell profile..." @($PROFILE)
        New-Item $PROFILE -ItemType File -Force | Out-Null
    }
    else {
        if ((Select-String -Path $PROFILE -Pattern "#  ____  _                           ___")) {
            Write-StatusMessage "Deleting old Plunge install..." -Icon "🗑" -MessageColor Red
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

    Write-Output $OnlineInstallUrl

    if ($Online) {
        $InstallSource = $OnlineInstallLocation
        Write-StatusMessage "Downloading from Github..." -Icon "⬇️"
        Invoke-WebRequest $OnlineInstallUrl -out $InstallSource | Out-Null
    }

    Write-StatusMessage "$InstallMessagePrefix..." @($InstallLocation)
    Copy-Item $InstallSource $InstallLocation -Force

    if (!(Select-String -Path $PROFILE -Pattern $DotSource)) {
        Write-StatusMessage "Appending to profile..."
        Add-Content $PROFILE $DotSource
    }

    Write-StatusMessage "Cleaning up..." -Icon "🧹"
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
    Write-StatusMessage -DebugMessagesOnly $true -DebugMessages @("Shrunk by $([Math]::Round($SavedBytesPercentage, 2))% ($SavedBytes bytes)")
    
    $NewVersion = (Select-String -Path $InstallLocation -Pattern '^\$HelloVersion\s=\s"(\d+\.\d+)"$').Matches.Groups[1].Value
    if($DevBranch)
    {
        $NewVersion = "$NewVersion-dev"
    }

    Write-StatusMessage "Hello $NewVersion installed!" @("Keep Hello updated by running Update-Hello", "Bug reports can be filed to https://github.com/electricduck/hello/issues", "", "To begin, restart your shell") -Icon "✔️" -MessageColor Green -DebugMessagesColor White
}

function Restart-Shell {
    Clear-Host
    Write-Hello
}

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