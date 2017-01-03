<#
    .SYNOPSIS
        Copies and runs BlueSpectrum on a remote system or systems. After completion, it retrieves the results of the script from the distant compter and 
        saves it to the local machine. Lastly, the copied script and output are deleted from the distant machine.

    .REQUIREMENTS
        - Requires an account on the remote computer (Hopefully one with permissions and excluded from the execution policy)
        - Requires C$ or Admin Share

    .USAGE
        1 - Replace the following variables:
                In this script: $computers, $dir2copy, $script2run, and $results variable (lines 18, 21, 24, and 27) to represent your environment
                In BlueSpectrum: $dir_hash_files (line 46) to depict the directory to scan
        2 - Execute the script
#>

# Reads in a list of computers that we will be running the script on
$computers = get-content C:\users\blue\Desktop\computers.txt

# Directory containing BlueSpectrum and supporting files that we will copy to the distant machines
$dir2copy = "C:\Users\blue\Desktop\BlueSpectrum\BlueSpectrum-master\"

# Name of the actual script that we want to run
$script2run = "BlueSpectrum.ps1"

# Directory to save results on the local machine
$results = "C:\users\blue\Desktop\BlueSpectrum_Results"
New-Item $results -ItemType directory | out-null

foreach($computer in $computers)
    {
    # Deletes directory we are copying if it already exists on distant machine
    $distant_path = "\\$computer\c$\BlueSpectrum-master"
        if ($distant_path -ne $null)
            {
            Remove-Item $distant_path -recurse -force -ErrorAction SilentlyContinue
            }

    # Copies script to be run on distant workstation
    Copy-Item $dir2copy \\$computer\c$\. -Recurse

    # Creates variable for WMI process
    $Action = [wmiclass] "\\$computer\ROOT\CIMv2:Win32_Process"

    # Creates process creation to invoke the BlueSpectrum script that we copied.
    $Method = $Action.create("powershell /c c:\BlueSpectrum-master\$script2run")

    write-host "Initiated process on $computer" -ForegroundColor Green
    }

# Allow time for the command to run
sleep 60

foreach($computer in $computers)
    {
    # Retrieves the results from the distant machine and saves it locally
    copy-Item \\$computer\c$\BlueSpectrum-master\results\*  $results\ 

    write-host "Pulled data back from $computer" -ForegroundColor Cyan

    # Deletes the script and log file on the distant machine
    remove-item \\$computer\c$\users\public\BlueSpectrum-master\ -Recurse -Force -ErrorAction SilentlyContinue
}


