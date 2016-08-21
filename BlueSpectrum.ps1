#requires -runasadministrator

# Requires at least PowerShell version 2 
<#

.DISCLAIMER

<Disclaimer: All Scripts and Other Powershell References on this blog are Offered "as is" with no Warranty.  
While These Scripts are Tested and Working in my Environment, it is Recommended that you test These Scripts 
in a test Environment Before Using in your Production Environment.>

.SYNOPSIS
  
  <BLUESPECTRUM is a PowerShell Script Designed to Search for Indicators of Compromise(IOCs) Inside of a File System and Registry.>

.DESCRIPTION
  
  <BLUESPECTRUM Searches a Given Directory Recusively for Indicators Of Compromise Specified in .txt files ..\BLUESPECTRUM\Indicators\, and Outputs Matches into a Corresponding Results File.
  After Parsing the FileSystem, BLUESPECTRUM then Searches the Registry for Specified keys.  >

.REQUIREMENTS
 
  <BLUESPECTRUM Requires:
                    
                    You run PowerShell with Administrator Rights
                    Your Present Working Directory to Be ..\BLUESPECTRUM\>

.OUTPUTS
  
  <Outputs File Scan Results to ..\BLUESPECTRUM\ScanResults.txt
   Outputs Registry Scan Results to ..\BLUESPECTRUM\RegistryScanResults.txt>

.NOTES
  
  Version:        1.0
  Author:         <PFC Blaine Milburn>
                  <CW3 Fernando Tomlinson>
  Creation Date:  <June 28th 2016>
  Purpose/Change: Initial Script Development
  
.EXAMPLE
  
  <To run the Script Simply type .\BLUESPECTRUM.ps1\ in an Administrator PowerShell Prompt>

.ADDING INDICATORS
  
  To add Indicators for BLUESPECTRUM to Search for, Simply Place the Item on a Newline 
  Within one of the IOC Files Located in ..\BLUESPECTRUM\Indicators\  

#>








$Date = Get-Date
$Looping = $true
While ($Looping -eq $true)
{
Clear-Host

Write-Host "
██████╗ ██╗     ██╗   ██╗███████╗    ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ██╗   ██╗███╗   ███╗
██╔══██╗██║     ██║   ██║██╔════╝    ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║   ██║████╗ ████║
██████╔╝██║     ██║   ██║█████╗      ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝██║   ██║██╔████╔██║
██╔══██╗██║     ██║   ██║██╔══╝      ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██║   ██║██║╚██╔╝██║
██████╔╝███████╗╚██████╔╝███████╗    ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║╚██████╔╝██║ ╚═╝ ██║
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝    ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝

    | A POWERSHELL FRAMEWORK FOR DETECTING IOC's PRODUCED BY BLAINE MILBURN AND FERNANDO TOMLINSON |
    |______________________________________________________________________________________________|

DISCLAIMER: All Scripts and Other Powershell References on this blog are Offered `"as is`" with no Warranty.  
While These Scripts are Tested and Working in our Environment, it is Recommended that you test These Scripts 
in a test Environment Before Using them in your Production Environment.
                                                                                                          "

Write-Host "`nPlease Select from the Following Options:`n_____________________________________________"
Write-Host "`n1) Search file MetaData, Registry, and Ports`n"
Write-Host "2) Hash and Match Files`n"
Write-Host "3) Documentation (For First time Users)`n"
Write-Host "4) Exit Script`n"
$Choice = Read-Host "_____________________________________________`n`nYour Selection"

if ($Choice -eq '1')
    {
$Dir_hash_files = (Read-Host "`n_____________________________________________`n`nPlease Provide a Directory to scan Recursively")
$TestPath = Test-Path $Dir_hash_files
if ($TestPath -eq $true)
    {
$FilesToScan = Get-ChildItem -Recurse $Dir_hash_files -ErrorAction SilentlyContinue

#Grab the name and size of each file inside of the specified directory
Clear-Host
Write-Host "Now Scanning $Dir_hash_files. Do Pushups, this may take a Moment"
foreach ($File in $FilestoScan)
{
$File.Name +  ":" +  $File.Length >> .\Unfiltered_Files.txt 
}
#************************** F I L E  S I Z E  S C A N ******************************
"-----------------------------------------------------------------------------------" > .\Results\FileSizeScan.txt    
"`nScan Initiated on $Date`n" >> .\Results\FileSizeScan.txt
"-----------------------------------------------------------------------------------`n" >> .\Results\FileSizeScan.txt
write-output -erroraction SilentlyContinue "" >> .\Results\FileSizeScan.txt
write-output -erroraction SilentlyContinue "********* FILE SIZE IOC HITS FOR $env:COMPUTERNAME ***********" >> .\Results\FileSizeScan.txt
write-output -erroraction SilentlyContinue "_________________________________________________________" >> .\Results\FileSizeScan.txt

#Select the files that match the sizes specified in your IOC and put the results into a text file.
$FileSizeIOC = get-content .\Indicators\File_Size_IOC.txt
foreach ($Size in $FileSizeIOC)
{
get-content ".\Unfiltered_Files.txt" | Select-String -Pattern :$Size\Z >> .\Results\FileSizeScan.txt
}

#************************** F I L E  N A M E  S C A N *******************************

"-----------------------------------------------------------------------------------" > .\Results\FileNameScan.txt    
"`nScan Initiated on $Date`n" >> .\Results\FileNameScan.txt
"-----------------------------------------------------------------------------------`n" >> .\Results\FileNameScan.txt
Write-Output -ErrorAction SilentlyContinue "" >> .\Results\FileNameScan.txt
write-output -erroraction SilentlyContinue "********* FILE NAME IOC HITS FOR $env:COMPUTERNAME ***********" >> .\Results\FileNameScan.txt
write-output -erroraction SilentlyContinue "_________________________________________________________" >> .\Results\FileNameScan.txt

#Select the files that match the names specified in your IOC and put the results into a text file.
$FileNameIOC = get-content .\Indicators\File_Name_IOC.txt
foreach ($Name in $FileNameIOC)
{
get-content ".\Unfiltered_Files.txt" | Select-String $Name >> .\Results\FileNameScan.txt
}

#Clean up Files that did not match any IOCs
Remove-Item .\Unfiltered_Files.txt

#************************* C O N N E C T I O N   S C A N ****************************

$PortIOC = get-content .\Indicators\PORT_IOC.txt
$Netstat = netstat -ano

"-----------------------------------------------------------------------------------" > .\Results\ConnScan.txt    
"`nScan Initiated on $Date`n" >> .\Results\ConnScan.txt
"-----------------------------------------------------------------------------------`n" >> .\Results\ConnScan.txt  

write-output -erroraction SilentlyContinue "" >> .\Results\ConnScan.txt
write-output -erroraction SilentlyContinue "********* CONNECTION SCAN RESULTS FOR $env:COMPUTERNAME ***********" >> .\Results\ConnScan.txt
write-output -erroraction SilentlyContinue "______________________________________________________________" >> .\Results\ConnScan.txt
foreach ($IOC in $PortIOC)
{
$Netstat | select-string -Pattern :$IOC\s >> .\Results\ConnScan.txt
}


Clear-Host
Write-Host "Files Finished Scanning, Beginnning Registry and port scan"
sleep 3
clear-Host

#************************* R E G I S T R Y   S C A N *********************************

# Variables to get the user listing (Vista and up) and reads in the list of registry IOCs. It excludes the currently logged on user since the hive is already loaded.
$userlist = Get-ChildItem "C:\users" -Exclude $env:username
$reg_ioc = get-content .\Indicators\Reg_IOC.txt

# Loops through to load the ntuser.dats.
foreach ($user in $userlist) 
{
    $username = $user.name
    reg load "hku\$username" "C:\users\$username\NTUSER.DAT" 
}

# This is the header for the output
"-----------------------------------------------------------------------------------" > .\Results\Registryscan.txt
"`nScan Initiated on $Date`n" >> .\Results\Registryscan.txt
"-----------------------------------------------------------------------------------`n" >> .\Results\Registryscan.txt
write-output -erroraction SilentlyContinue "" >> .\Results\RegistryScan.txt
write-output -erroraction SilentlyContinue "********* REGISTRY SCAN RESULTS FOR $env:COMPUTERNAME ***********" >> .\Results\RegistryScan.txt
write-output -erroraction SilentlyContinue "____________________________________________________________" >> .\Results\RegistryScan.txt

# Begins the work of searching for the IOCs in the manually loaded ntuser.dat.
foreach ($myusers in $user_list)
{
    foreach ($ioc in $reg_ioc) 
    { 
        try
        {
            # Splits the IOC file with a tab as delimmiter. This enables searching for just the key, if need be.
            $regKey ,$regValue= $ioc.split("`t",2) 
            # Checks if the key ends with "\". If not, it will be added.
            if (-not $regKey.EndsWith("\"))
            {
                $regKey+= '\'
            }
            # Serves as a header to identify what keys and/or values that are triggered.
            "`r`n<<<< Reg Key: HKU\" + $myusers.ToUpper() + "\" + $regKey.ToUpper() + " - Value : "+ $regValue +" >>>>" >> .\Results\Registryscan.txt
                if($regValue -eq $null)
                {
                    # No Registry value specified (only a key).
                    ($foundValue = Get-ChildItem hku:\$myusers\$regKey -force  -ErrorAction Stop)
                    echo "********************* " >> .\Results\Registryscan.txt
                    echo "***** IOC HIT ! ***** " >> .\Results\Registryscan.txt
                    echo "********************* " >> .\Results\Registryscan.txt
                    if ( $foundValue -eq $null) 
                    {
                        # If it's a key with no more subkeys, we will use Get-ItemProperty to list any values.
                        ($foundValue = Get-ItemProperty -ErrorAction stop hku:\$myusers\$regKey)
                        echo "********************* " >> .\Results\Registryscan.txt
                        echo "***** IOC HIT ! ***** " >> .\Results\Registryscan.txt
                        echo "********************* " >> .\Results\Registryscan.txt
                        # If no values are found.
                            if ( $foundValue -eq $null) 
                            {
                            Write-Error("No Hit") -ErrorAction stop
                            }
                    } 
                }
             else
             {
                 # Registry key plus value specified
                 ($foundValue = Get-ItemProperty -ErrorAction stop hku:\$myusers\$regKey | Select-Object -ExpandProperty $regValue -ErrorAction stop  >> .\Results\Registryscan.txt)
                 # Will be visible in the reg_scan.txt file anywhere/anytime there is a hit on an IOC.
                 echo "************************ " >> .\Results\Registryscan.txt
                 echo "****** IOC HIT ! ******* " >> .\Results\Registryscan.txt
                 echo "************************ " >> .\Results\Registryscan.txt
                     if ( $foundValue -eq $null) {Write-Error("No Hit") -ErrorAction stop}
             }
        }
        catch
        {
            # Does nothing,  it is just here to hide errors from the screen.
            
        }
    }
}

# Begins the work of searching the currently logged on user's HKCU.
foreach ($current_user in $env:username)
{
    foreach ($ioc in $reg_ioc) 
    { 
        try
        {
            # Splits the IOC file with a tab as delimmiter. This enables searching for just the key, if need be.
            $regKey ,$regValue= $ioc.split("`t",2) 
            # Checks if the key ends with "\". If not, it will be added.
            if (-not $regKey.EndsWith("\"))
            {
                $regKey+= '\'
            }
            # Serves as a header to identify what keys and/or values that are triggered.
            "`r`n<<<< Reg Key for user $env:username : HKCU\" + $regKey.ToUpper() + " - Value : "+ $regValue +" >>>>" >> .\Results\Registryscan.txt
                if($regValue -eq $null)
                {
                    # No Registry value specified (only a key).
                    ($foundValue = Get-ChildItem hkcu:\$regKey -force  -ErrorAction Stop)
                    echo "********************* " >> .\Results\Registryscan.txt
                    echo "***** IOC HIT ! ***** " >> .\Results\Registryscan.txt
                    echo "********************* " >> .\Results\Registryscan.txt
                    if ( $foundValue -eq $null) 
                    {
                        # If it's a key with no more subkeys, we will use Get-ItemProperty to list any values.
                        ($foundValue = Get-ItemProperty -ErrorAction stop hkcu:\$regKey)
                        echo "********************* " >> .\Results\Registryscan.txt
                        echo "***** IOC HIT ! ***** " >> .\Results\Registryscan.txt
                        echo "********************* " >> .\Results\Registryscan.txt
                        # If no values are found.
                            if ( $foundValue -eq $null) 
                            {
                            Write-Error("No Hit") -ErrorAction stop
                            }
                    } 
                }
             else
             {
                 # Registry key plus value specified
                 ($foundValue = Get-ItemProperty -ErrorAction stop hkcu:\$regKey | Select-Object -ExpandProperty $regValue -ErrorAction stop  >> .\Results\Registryscan.txt)
                 # Will be visible in the reg.txt file anywhere/anytime there is a hit on an IOC.
                 echo "********************* " >> .\Results\Registryscan.txt
                 echo "***** IOC HIT ! ***** " >> .\Results\Registryscan.txt
                 echo "********************* " >> .\Results\Registryscan.txt
                     if ( $foundValue -eq $null) {Write-Error("No Hit") -ErrorAction stop}
             }
        }
        catch
        {
            # Does nothing,  it is just here to hide errors from the screen.
            
        }
    }
}

# Begins the work of searching the HKLM hive.
foreach ($current_user in $env:computername)
{
    foreach ($ioc in $reg_ioc) 
    { 
        try
        {
            # Splits the IOC file with a tab as delimmiter. This enables searching for just the key, if need be.
            $regKey ,$regValue= $ioc.split("`t",2) 
            # Checks if the key ends with "\". If not, it will be added.
            if (-not $regKey.EndsWith("\"))
            {
                $regKey+= '\'
            }
            # Serves as a header to identify what keys and/or values that are triggered.
            "`r`n<<<< Reg Key for $env:computername : HKLM\" + $regKey.ToUpper() + " - Value : "+ $regValue +" >>>>" >> .\Results\Registryscan.txt
                if($regValue -eq $null)
                {
                    # No Registry value specified (only a key).
                    ($foundValue = Get-ChildItem hklm:\$regKey -force  -ErrorAction Stop >> .\Results\Registryscan.txt)
                    echo "********************* " >> .\Results\Registryscan.txt
                    echo "***** IOC HIT ! ***** " >> .\Results\Registryscan.txt
                    echo "********************* " >> .\Results\Registryscan.txt
                    if ( $foundValue -eq $null) 
                    {
                        # If it's a key with no more subkeys, we will use Get-ItemProperty to list any values.
                        ($foundValue = Get-ItemProperty -ErrorAction stop hklm:\$regKey >> .\Results\Registryscan.txt)
                        echo "********************* " >> .\Results\Registryscan.txt
                        echo "***** IOC HIT ! ***** " >> .\Results\Registryscan.txt
                        echo "********************* " >> .\Results\Registryscan.txt
                        # If no values are found.

                            if ( $foundValue -eq $null) 
                            {
                            Write-Error("No Hit") -ErrorAction stop
                            }
                    } 
                }
             else
             {
                 # Registry key plus value specified
                 ($foundValue = Get-ItemProperty -ErrorAction stop hklm:\$regKey | Select-Object -ExpandProperty $regValue -ErrorAction stop  >> .\Results\Registryscan.txt)
                 # Will be visible in the reg.txt file anywhere/anytime there is a hit on an IOC.
                 echo "********************* " >> .\Results\Registryscan.txt
                 echo "***** IOC HIT ! ***** " >> .\Results\Registryscan.txt
                 echo "********************* " >> .\Results\Registryscan.txt
                     if ( $foundValue -eq $null) {Write-Error("No Hit") -ErrorAction stop}
             }
        }
        catch
        {
            # Does nothing,  it is just here to hide errors from the screen.
            
        }
    }
}

# Cleans up objects no longer needed.
[gc]::collect()
start-sleep -s 3

# Unloads the ntuser.dats from the Registry.
foreach ($user in $userlist)
{
    $username = $user.name
    reg unload "hku\$username" 
}

Write-Host "Registry scan Finished, Results Saved in .\BlueSpectrum\Results\"
Sleep (4)
Clear-Host
    }
   else
   {
   Write-Host "Invalid Path Chosen!"
   sleep 7
   }
    }

#HASH SCAN 
elseif($Choice -eq '2')
{
$hashloop = $true
While ($hashloop -eq $true)
{
# Directory to recursively hash. 
$user_input = read-host "`n_____________________________________________`n`nPlease Enter a Directory to hash and scan"
$dir_hash_files = get-childitem $user_input -ErrorAction SilentlyContinue
$hashgate = Test-Path $user_input
# Hash(es) to scan for.
$hash = get-content -ErrorAction SilentlyContinue  .\hashes.txt
if ($hashgate -eq $false)
{
Write-Host "Invalid Directory Entered!"
sleep(3)
Clear-Host
}
Else{
clear-host
# Does the hashing.
function Get-d_hashes
{

[CmdletBinding(DefaultParameterSetName="Path")]
param(
  [Parameter(ParameterSetName="Path",Position=0,Mandatory=$TRUE,ValueFromPipeline=$TRUE)]
    [String[]] $Path,
  [Parameter(ParameterSetName="LiteralPath",Position=0,Mandatory=$TRUE)]
    [String[]] $LiteralPath,
  [Parameter(Position=1)]
    [String] $HashType="MD5"
)

begin {
  switch ($HashType) {
    "MD5" {
      $Provider = new-object System.Security.Cryptography.MD5CryptoServiceProvider -ErrorAction SilentlyContinue
      break
    }
    "SHA1" {
      $Provider = new-object System.Security.Cryptography.SHA1CryptoServiceProvider -ErrorAction SilentlyContinue
      break
    }
    default {
      throw "HashType must be one of the following: MD5 SHA1" 
    }
  }

  # If the Path parameter is not bound, assume input comes from the pipeline.
  if ($PSCMDLET.ParameterSetName -eq "Path") {
    $PIPELINEINPUT = -not $PSBOUNDPARAMETERS.ContainsKey("Path")
  }

  # Returns an object containing the file's path and its hash as a hexadecimal string.
  # The Provider object must have a ComputeHash method that returns an array of bytes.
  function get-filehash2($file) {
    if ($file -isnot [System.IO.FileInfo]) {
      write-error "'$($file)' is not a file."
      return
    }
    $hashstring = new-object System.Text.StringBuilder
    $stream = $file.OpenRead()
    if ($stream) {
      foreach ($byte in $Provider.ComputeHash($stream)) {
        [Void] $hashstring.Append($byte.ToString("X2"))
      }
      $stream.Close()
    }
    "" | select-object @{Name="Path"; Expression={$file.FullName}},
      @{Name="$($Provider.GetType().BaseType.Name) Hash"; Expression={$hashstring.ToString()}}
  }
}

process {
  if ($PSCMDLET.ParameterSetName -eq "Path") {
    if ($PIPELINEINPUT) {
      get-filehash2 $_
    }
    else {
      get-item $Path -force | foreach-object {
        get-filehash2 $_
      }
    }
  }
  else {
    $file = get-item -literalpath $LiteralPath
    if ($file) {
      get-filehash2 $file
    }
  }
}
}

# Runs the above Function for the entries in our variable. Also does error handling.
foreach ($ioc in $dir_hash_files) { 
       try{
            $dir_hash_files | Get-d_hashes -ErrorAction silentlycontinue > .\dir_hash.txt
        }
        catch{
            # Does nothing, its here just to hide errors from the screen.
        }
    }
"-----------------------------------------------------------------------------------" > .\Results\HashScan.txt    
"Scan Initiated on $Date" >> .\Results\HashScan.txt   
write-output -erroraction SilentlyContinue "" >> .\Results\HashScan.txt
write-output -erroraction SilentlyContinue "********* HASH SCAN RESULTS FOR $env:COMPUTERNAME ***********" >> .\Results\HashScan.txt
write-output -erroraction SilentlyContinue "________________________________________________________" >> .\Results\HashScan.txt   
$hash = get-content .\Indicators\hash_ioc.txt
# Looks for the hash(es) we give it.
foreach ($ioc_out in $hash) { 
 get-content ".\dir_hash.txt" | select-string $ioc_out >> .\Results\HashScan.txt   
    }

# Removes initial directory file hashes.

remove-item .\dir_hash.txt -ErrorAction SilentlyContinue
Write-Host "Hashing Finished, Results are Located in .\hash_scan.txt"
Sleep 2
Clear-Host
$hashloop = $false


}
}
}




elseif ($Choice -eq '3')
    {
    Clear-Host  
    Write-Host "
██████╗ ██╗     ██╗   ██╗███████╗    ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ██╗   ██╗███╗   ███╗
██╔══██╗██║     ██║   ██║██╔════╝    ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║   ██║████╗ ████║
██████╔╝██║     ██║   ██║█████╗      ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝██║   ██║██╔████╔██║
██╔══██╗██║     ██║   ██║██╔══╝      ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██║   ██║██║╚██╔╝██║
██████╔╝███████╗╚██████╔╝███████╗    ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║╚██████╔╝██║ ╚═╝ ██║
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝    ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝

                                | DOCUMENTATION AND RELEASE NOTES |
                                                                                                          "        
   Write-Host  "WHAT IS BLUESPECTRUM:"
    Write-Host "`n`tBLUE SPECTRUM Is a Powershell V2 Script made to Detect Indicators of Compromise (IOCs)"
    Write-Host "`tWhether it be via Registry, Network Connections, file MetaData, or Hashes. BLUESPECTRUM   "
    Write-Host "`tuses 5 IOC Files, all Distributed With the Script, to Search for Matches To These IOCs"
    Write-Host "`nREQUIREMENTS:`n
     This Script must be ran in an Administrator Powershell Instance and Within ..\BLUESPECTRUM\"
    Write-Host "`n`n HOW TO EDIT IOC FILES:"
    Write-Host "`n      In Order to edit IOC Files you Simply add one IOC per line to the Corresponding file via"
    Write-Host "      your Favorite text Editor (Notepad++) and put one Indicator of Compromise per line. `n`t  For Examples of what your IOC Files Should look like, we have Included an Example Directory(.\BlueSpectrum\Examples)`n`t  with IOC Files Loaded with Proper Entries. You may also add IOC's via Powershell, and here are some Examples Below. "
    Write-Host "`n`n`tEXAMPLES:`n`n`t`tFILE NAMES:                    EvilFile.txt >> .\Indicators\File_Name_IOC.txt`n`t`tFILE SIZE(IN BYTES):           35342 >> .\Indicators\File_Size_IOC.txt`n`t    FILE HASH(MD5):                9BE55BAE64F3684667266F0F1E5EACD2  >> .\Indicators\Hash_IOC.txt         `n`t`tREGISTRY:                      Software\Microsoft\Windows\CurrentVersion\Run\	GizmoDriveDelegate >> .\Indicators\Reg_Ioc.txt`n`t`tPORT:`t`t`t`t`t`t   4444 >> .\Indicators\Port_IOC.txt" 
    Write-Host "`n`n WHERE TO FIND RESULTS:"
    Write-Host "`n      The Results Of this scan will be Placed in .\BlueSpectrum\Results\" 
    Write-Host
    Pause
    

    }
elseif ($Choice -eq '4')
    {
    Clear-Host
    Write-Host 
    "
██████╗ ██╗     ██╗   ██╗███████╗    ███████╗██████╗ ███████╗ ██████╗████████╗██████╗ ██╗   ██╗███╗   ███╗                        
██╔══██╗██║     ██║   ██║██╔════╝    ██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔══██╗██║   ██║████╗ ████║                        
██████╔╝██║     ██║   ██║█████╗      ███████╗██████╔╝█████╗  ██║        ██║   ██████╔╝██║   ██║██╔████╔██║                        
██╔══██╗██║     ██║   ██║██╔══╝      ╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██╔══██╗██║   ██║██║╚██╔╝██║                        
██████╔╝███████╗╚██████╔╝███████╗    ███████║██║     ███████╗╚██████╗   ██║   ██║  ██║╚██████╔╝██║ ╚═╝ ██║                        
╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝    ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝ "

Sleep 2
Clear-Host

    
$Looping = $false
    }
else
    {
    
    }
    }