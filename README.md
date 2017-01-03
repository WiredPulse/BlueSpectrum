![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/BlueSpectrum.PNG?raw=true "Optional Title")


BlueSpectrum is an IOC framework written in PowerShell. It searches for Indicators of Compromise (IOC) in Registry keys\values, network connections, file metadata, and or hashes on local or remote systems using WMI as the remote process caller. This script works with PowerShell v2 and newer. 
<br>
<br>
# Adding IOCs:<br>
Open one of the five IOC files and input an applicable indicator on each line. Please see the folder labled "IOC_Examples" for how an indicator should look in the file. 
<br>
<br>
# Usage:<br>
1)* Download this repository and unzip it.<br>
2) Add applicable IOCs to the indicator files.<br>
3) Change applicable variables.<br>
&#160;&#160;&#160;&#160;- BlueSpectrum_Process_Call.ps1 -- Lines 18, 21, 24, and 27<br>
&#160;&#160;&#160;&#160;- BlueSpectrum.ps1 -- Line 46<br>
4) Run BlueSpectrum_Process_Call.ps1 from a PS console.<br>
5) Review findings in the "Results" folder.<br>
<br>
<br>
# Remote Usage:<br>
There are a few ways to run BlueSpectrum remotely to include using PSRemoting, PSEXEC, and/or WMI. We only address running it locally. 

# Screenshots
## Indicators
![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/Indicators.PNG?raw=true "Optional Title")
<br>
<br>
## Process Call in action with status updates<br>
![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/Process_Call.PNG?raw=true "Optional Title")
<br>
<br>
## Results are returned to the local machine and begin with the IP or hostname of the system it came from.<br>
![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/Results.PNG?raw=true "Optional Title")
<br>
<br>
## Connection hits
![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/connscan_hits.PNG?raw=true "Optional Title")
<br>
<br>
## Registry scan hits
![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/registry_hits.PNG?raw=true "Optional Title")
<br>
<br>
## Hash scan hits hits
![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/hashscan_hits.PNG?raw=true "Optional Title")
<br>
<br>
## File size scan hits
![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/filesize_hits.PNG?raw=true "Optional Title")
<br>
<br>
## Filename scan hits
![Alt text](https://github.com/WiredPulse/BlueSpectrum/blob/master/Screenshots/filename_hits.PNG?raw=true "Optional Title")
