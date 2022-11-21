#==========================app installs
 
#=========Battle.Net Launcher
iwr -uri "https://www.battle.net/download/getInstallerForGame?os=win&gameProgram=BATTLENET_APP&version=Live&id=923777430.1668789114" -OutFile C:\users\public\scripts\battle.exe
C:\users\public\scripts\battle.exe
#del c:\users\dave\downloads\temp\battle.exe

#=========EVGA PrecisionX1
iwr -uri "https://www.evga.com/EVGA/GeneralDownloading.aspx?file=EVGA_Precision_X1_1.3.7.0.zip&survey=11.3.7.0" -outfile C:\users\public\scripts\evga.zip
Expand-Archive -path C:\users\public\scripts\evga.zip -destinationpath C:\users\public\scripts\evga

#=========Revo Uninstaller
iwr -uri "https://download.revouninstaller.com/download/revosetup.exe" -outfile C:\users\public\scripts\revo.exe

#=========various apps
winget install hwinfo
winget install 9WZDNCRDKRQ3
winget install 9PC3H3V7Q9CH
winget install vscode
winget install 7zip.7zip
winget install TechPowerUp.NVCleanstall
winget install Microsoft.PowerToys
winget install Valve.Steam
winget install ElectronicArts.EADesktop
winget install EpicGames.EpicGamesLauncher

#===========================new right click menu
Write-Host "Setting Classic Right-Click Menu..."
            New-Item -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" -Name "InprocServer32" -force -value "" 
winget install Nilesoft.Shell

expand-archive -path C:\users\public\scripts\rtss.zip -destinationpath C:\users\public\scripts\rtss
c:\users\public\scripts\rtss\rtsssetup733.exe


#=========Cura Slicer
iwr -uri "https://github.com/Ultimaker/Cura/releases/download/5.2.1/Ultimaker-Cura-5.2.1-win64.exe" -outfile C:\users\public\scripts\cura.exe
c:\users\public\scripts\cura.exe

c:\users\public\scripts.lnk
