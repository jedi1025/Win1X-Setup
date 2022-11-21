do {
    do {
        write-host ""
        write-host "A - Contrast"
        write-host "B - Amd Surface"
        write-host "C - Intel Surface"
        write-host "D - Zoey"
        write-host "E - MacPro"
        write-host "F - Base"
	  write-host ""
        write-host "X - Exit"
        write-host ""
        write-host -nonewline "Type your choice and press Enter: "
        
        $choice = read-host
        
        write-host ""
        
        $ok = $choice -match '^[abcdex]+$'
        
        if ( -not $ok) { write-host "Invalid selection" }
    } until ( $ok )
    
    switch -Regex ( $choice ) {
        "A"
        {
            write-host "Setting up Contrast..."
		c:\users\public\scripts\debloat2.ps1
		c:\users\public\scripts\update.ps1
		c:\users\public\scripts\applications.ps1
		c:\users\public\scripts\apps.ps1
		c:\users\public\scripts\battlenet.ps1
		c:\users\public\scripts\menu.ps1
		Rename-Computer -NewName "ContrastMK2"
        }
        
        "B"
        {
            write-host "Setting up Morgan's Surface..."
		c:\users\public\scripts\debloat2.ps1
		c:\users\public\scripts\update.ps1
		Rename-Computer -NewName "Morgan"
        }

        "C"
        {
            write-host "Setting up Dave's Surface..."
		c:\users\public\scripts\debloat2.ps1
		c:\users\public\scripts\update.ps1
		winget install 9PC3H3V7Q9CH
		winget install vscode
		winget install 7zip.7zip
		Rename-Computer -NewName "Surface"
        }

        "D"
        {
            write-host "Setting up Zoey's Computer..."
		c:\users\public\scripts\debloat2.ps1
		c:\users\public\scripts\update.ps1
		c:\users\public\scripts\battlenet.ps1
		Rename-Computer -NewName "Zoey"

        }

        "E"
	  {
		write-host "Setting up MacPro workstation..."
		c:\users\public\scripts\debloat2.ps1
		c:\users\public\scripts\update.ps1
		winget install 9PC3H3V7Q9CH
		winget install vscode
		winget install 7zip.7zip
		Rename-Computer -NewName "MacPro-WS"	
        }

        "F"
	  {
		write-host "Setting up basic install..."
		c:\users\public\scripts\debloat2.ps1
		c:\users\public\scripts\update.ps1
        }
    }
} until ( $choice -match "X" )