![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/BlueSpectrum.PNG?raw=true "Optional Title")


BlueSpectrum is an IOC framework written in PowerShell. It searches for Indicators of Compromise (IOC) in Registry keys\values, network connections, file metadata, and or hashes. 
<br>
<br>
# Adding IOCs:<br>
Open one of the five IOC files and input an applicable indicator on each line. Please see the folder labled "IOC_Examples" for how an indicator should look in the file. 
<br>
<br>
# Usage:<br>
1)* Download this repository and unzip it.<br>
2) Add applicable IOCs to the indicator files.<br>
3) Change applicable variables
 3) BlueSpectrum_Process_Call.ps1 -- Lines 18, 21, 24, and 27<br>
 * BlueSpectrum.ps1 -- Line 46<br>
4) Run BlueSpectrum.ps1 from a PS console.<br>
5) When prompted, select the applicable options.<br>
6)) Review findings in the "Results" folder.<br>
<br>
<br>
# Remote Usage:<br>
There are a few ways to run BlueSpectrum remotely to include using PSRemoting, PSEXEC, and/or WMI. We only address running it locally. 

* Bullet list<br> 
 * Nested bullet<br>
* Sub-nested bullet etc<Br>
* Bullet list item 2<br>
