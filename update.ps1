Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Install-Module -Name PSWindowsUpdate -force
Hide-WindowsUpdate -KBArticleID KB5019980 -ignoreuserinput
