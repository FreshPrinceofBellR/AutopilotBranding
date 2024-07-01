#Setup initial logging function for tracking the Autopilot Branding process
function Log() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [String] $Message
	)
	$Timestamp = Get-Date -f "yyyy/MM/dd hh:mm:ss tt"
	Write-Output "$Timestamp $Message"
}

#Restart PowerShell in a 64-bit enviroment
If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
	Try {
		&"$ENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -File $PSCOMMANDPATH
	} Catch {
		Write-Error "Failed to start $PSCOMMANDPATH"
		Exit -Code 1
	}
	Exit
}

#Create a tag file to identify the application has been installed
If (-not (Test-Path "$($env:ProgramData)\Microsoft\AutopilotBranding")) {
	mkdir "$($env:ProgramData)\Microsoft\AutopilotBranding"
}
Set-Content -Path "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.ps1.tag" -Value "Installed"

#Start logging
Start-Transcript "$($env:ProgramData)\Microsoft\AutopilotBranding\AutopilotBranding.log"

#Load the config.xml
$InstallationFolder = "$PSScriptRoot\"
Log "Installation folder: $($InstallationFolder)Config.xml"
Log "Loading configuration: $($InstallationFolder)Config.xml"
[Xml]$Config = Get-Content "$($InstallationFolder)Config.xml"

#STEP 1: Apply the custom start menu layout
$CompInfo = Get-ComputerInfo
Log "OS Build number: $($CompInfo.OsBuildNumber)"

#If the OS build is less than 22000, run the Layout.xml
If ($CompInfo.OsBuildNumber -le 22000) {
	Log "Importing layout: $($InstallationFolder)Layout.xml"
	Copy-Item "$($InstallationFolder)Layout.xml" "C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Force
} 
#If the OS build number is anything other than being less than 22000, run the Start2.bin
Else {
	Log "Importing layout: $($InstallationFolder)Start2.bin"
	mkdir -Path "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Force -ErrorAction SilentlyContinue | Out-Null
	Copy-Item "$($InstallationFolder)Start2.bin" "C:\Users\Default\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\Start2.bin" -Force
}

#STEP 2: Configure the desktop background
reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Host
Log "Setting up Autopilot theme"

#Create the OEM themes folder and copy the Autopilot.theme file to the directory
mkdir "C:\Windows\Resources\OEM Themes" -Force | Out-Null
Copy-Item "$InstallationFolder\Autopilot.theme" "C:\Windows\Resources\OEM Themes\Autopilot.theme" -Force

#Create an Autopilot folder fo the desired desktop background and then copy the Autopilot.jpg to the directory
mkdir "C:\Windows\web\wallpaper\Autopilot" -Force | Out-Null
Copy-Item "$InstallationFolder\Autopilot.jpg" "C:\Windows\web\wallpaper\Autopilot\Autopilot.jpg" -Force

#Set the Autopilot theme to the user default and set the requirements in the registry
Log "Setting Autopilot theme as the new user default"
reg.exe add "HKLM\TempUser\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v InstallTheme /t REG_EXPAND_SZ /d "%SystemRoot%\resources\OEM Themes\Autopilot.theme" /f | Out-Host

#STEP 3: Set the timezone
If ($Config.Config.TimeZone) {
	Log "Setting time zone: $($Config.Config.TimeZone)"
	Set-TimeZone -Id $Config.Config.TimeZone
} Else {
	#Enable location services so the time zone will be set automatically (even when skipping the privacy page in OOBE) when an administrator signs in
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type "String" -Value "Allow" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type "DWord" -Value 1 -Force
	Start-Service -Name "lfsvc" -ErrorAction SilentlyContinue
}

#STEP 4: Remove targetted applications
Log "Removing specified in-box provisioned apps"
$Apps = Get-AppxProvisionedPackage -Online
$Config.Config.RemoveApps.App | % {
	$Current = $_
	$Apps | ? {$_.DisplayName -eq $Current} | % {
		try {
			Log "Removing provisioned app: $Current"
			$_ | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
		} catch { }
	}
}

#STEP 5: Install OneDrive
If ($Config.Config.OneDriveSetup) {
	Log "Downloading OneDriveSetup"
	$Destination = "$($env:TEMP)\OneDriveSetup.exe"
	$Client = New-Object System.Net.WebClient
	$Client.DownloadFile($config.Config.OneDriveSetup, $Destination)
	Log "Installing: $Destination"
	$Process = Start-Process $Destination -ArgumentList "/allusers" -WindowStyle Hidden -PassThru
	$Process.WaitForExit()
	Log "OneDriveSetup exit code: $($Process.ExitCode)"
}

#STEP 6: Prevent Edge creating destkop shortcuts
Log "Turning off (old) Edge desktop shortcut"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v DisableEdgeDesktopShortcutCreation /t REG_DWORD /d 1 /f /reg:64 | Out-Host

#STEP 7: Add language packs
Get-ChildItem "$($InstallationFolder)LPs" -Filter *.cab | % {
	Log "Adding language pack: $($_.FullName)"
	Add-WindowsPackage -Online -NoRestart -PackagePath $_.FullName
}

#STEP 8: Change language
If ($Config.Config.Language) {
	Log "Configuring language using: $($Config.Config.Language)"
	& $env:SystemRoot\System32\control.exe "intl.cpl,,/f:`"$($InstallationFolder)$($Config.Config.Language)`""
}

#STEP 9: Add on-demand features
If ($Config.Config.AddFeatures.Feature.Count -gt 0) {
	$Config.Config.AddFeatures.Feature | % {
		Log "Adding Windows feature: $_"
		Add-WindowsCapability -Online -Name $_ -ErrorAction SilentlyContinue | Out-Null
	}
}

#Step 10: Disable WSUS
$CurrentWU = (Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction Ignore).UseWuServer
if ($CurrentWU -eq 1) {
	Log "Turning off WSUS"
	Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"  -Name "UseWuServer" -Value 0
	Restart-Service wuauserv
}

#STEP 11: Customise default apps
if ($Config.Config.DefaultApps) {
	Log "Setting default apps: $($Config.Config.DefaultApps)"
	& Dism.exe /Online /Import-DefaultAppAssociations:`"$($InstallationFolder)$($Config.Config.DefaultApps)`"
}

#STEP 12: Set information from the config.xml
Log "Configuring registered user information"
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner /t REG_SZ /d "$($Config.Config.RegisteredOwner)" /f /reg:64 | Out-Host
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v RegisteredOrganization /t REG_SZ /d "$($Config.Config.RegisteredOrganization)" /f /reg:64 | Out-Host

#Step 13: Set OEM information
If ($Config.Config.OEMInfo) {
	Log "Configuring OEM branding info"
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Manufacturer /t REG_SZ /d "$($Config.Config.OEMInfo.Manufacturer)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Model /t REG_SZ /d "$($Config.Config.OEMInfo.Model)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportPhone /t REG_SZ /d "$($Config.Config.OEMInfo.SupportPhone)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportHours /t REG_SZ /d "$($Config.Config.OEMInfo.SupportHours)" /f /reg:64 | Out-Host
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v SupportURL /t REG_SZ /d "$($Config.Config.OEMInfo.SupportURL)" /f /reg:64 | Out-Host
	Copy-Item "$InstallationFolder\$($Config.Config.OEMInfo.Logo)" "C:\Windows\$($Config.Config.OEMInfo.Logo)" -Force
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "C:\Windows\$($Config.Config.OEMInfo.Logo)" /f /reg:64 | Out-Host
}

#Step 14: Enable UE-V
Log "Enabling UE-V"
Enable-UEV
Set-UevConfiguration -Computer -SettingsStoragePath "%OneDriveCommercial%\UEV" -SyncMethod External -DisableWaitForSyncOnLogon
Get-ChildItem "$($InstallationFolder)UEV" -Filter *.xml | % {
	Log "Registering template: $($_.FullName)"
	Register-UevTemplate -Path $_.FullName
}

#Step 15: Disable network location fly-out
Log "Turning off network location fly-out"
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f

#Step 16: Disable new Edge desktop icon
Log "Turning off Edge desktop icon"
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d 0 /f /reg:64 | Out-Host

Stop-Transcript