![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/BlueSpectrum.PNG?raw=true "Optional Title")


BlueSpectrum is an IOC framework written in PowerShell. It searches for Indicators of Compromise (IOC) in Registry keys\values, network connections, file metadata, and or hashes. 
<br>
<br>
# Adding IOCs:<br>
Open one of the five IOC files and input an applicable indicator on each line. Please see the folder labled "IOC_Examples" for how an indicator should look in the file. 
<br>
<br>
# Usage:<br>
1) Download the ZIP of this repoository and unzip it.<br>
2) Add applicable IOCs to the indicator files.<br>
3) Run BlueSpectrum.ps1 from a PS console.<br>
4) When prompted, select the applicable options.<br>
5) Review findings in the "Results" folder.<br>
<br>
<br>
# Remote Usage:<br>
There are a few ways to run BlueSpectrum remotely to include using PSRemoting, PSEXEC, and/or WMI. We only address running it locally. 
