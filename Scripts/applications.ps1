#=========Revo Uninstaller
iwr -uri "https://download.revouninstaller.com/download/revosetup.exe" -outfile C:\users\public\scripts\revo.exe
c:\users\public\scripts\revo.exe


#=========EVGA PrecisionX1
iwr -uri "https://www.evga.com/EVGA/GeneralDownloading.aspx?file=EVGA_Precision_X1_1.3.7.0.zip&survey=11.3.7.0" -outfile C:\users\public\scripts\evga.zip
Expand-Archive -path C:\users\public\scripts\evga.zip -destinationpath C:\users\public\scripts\evga
c:\users\public\scripts\evga\EVGAPr~1.exe



