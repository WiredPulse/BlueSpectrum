# BlueSpectrum
An IOC framework written in PowerShell
<br>
BlueSpectrum searches for Indicators of Compromise (IOC) in Registry keys\values, network connections, file metadata, and or hashes. 
<br>
Adding IOCs:<br>
Open one of the five IOC files and input an applicable indicator on each line. Please see the folder labled "Examples" for how an indicator should look in the file. 
<br>
Usage:<br>
1) Download the ZIP of this repoository and unzip it.
2) Add applicable IOCs to the indicator files.
3) Run BlueSpectrum.ps1 from a PS console.
4) When prompted, select the applicable options.
5) Review findings in the "Results" folder.
<br>
Remote Usage:
There are a few ways to run BlueSpectrum remotely to include using PSRemoting, PSEXEC, and/or WMI. We only address running it locally. 
