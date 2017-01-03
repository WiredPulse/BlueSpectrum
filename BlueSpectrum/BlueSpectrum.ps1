#requires -runasadministrator

<#

.DISCLAIMER
    Disclaimer: All scripts and other Powershell references in this script are offered "as is" with no warranty.  
    While this script has been tested and working in our environment, it is recommended that you test this script 
    in your own test environment before using it in your production environment.

.SYNOPSIS
    BLUESPECTRUM is a PowerShell script designed to search for Indicators of Compromises (IOCs) inside of a filesystem, netork connections, and/or Registry.

.DESCRIPTION
    BLUESPECTRUM searches a system or systems for IOCs specified in .txt files within ..\BLUESPECTRUM-MASTER\Indicators\ and outputs the matches 
    into a corresponding results folder (\BLUESPECTRUM-MASTER\Results\). 

.REQUIREMENTS
    BLUESPECTRUM Requires:
        - A shell invoked with admin rights
        - PowerShell v2 or newer

.OUTPUTS
    Outputs File Scan Results to ..\BLUESPECTRUM-MASTER\<Host Name>_FileNameScan.txt
    Outputs File Scan Results to ..\BLUESPECTRUM-MASTER\<Host Name>_FileSizeScan.txt
    Outputs Port Scan Results to ..\BLUESPECTRUM-MASTER\<Host Name>_ConnScan.txt
    Outputs Registry Scan Results to ..\BLUESPECTRUM-MASTER\<Host Name>_RegistryScan.txt
    Outputs Hash Scan Results to ..\BLUESPECTRUM-MASTER\<Host Name>_HashScan.txt

.NOTES
    Version:        2.0
    Author:         @AflluentPanda
                    @wiredPulse or @Wired_Pulse
    Creation Date:  October 11th, 2016
  
.ADDING INDICATORS
    To add IOCs for BLUESPECTRUM to search for, simply place the item on a newline within one of the IOC files located in ..\BLUESPECTRUM-MASTER\Indicators\  

.EXAMPLE
    IOC file examples are located in ..\BLUESPECTRUM-MASTER\IOC_Examples

#>


# Directory to scan
$Dir_hash_files = "C:\windows\system32"
$FilesToScan = Get-ChildItem $Dir_hash_files -ErrorAction SilentlyContinue

# Setting conditions
Set-Location C:\BlueSpectrum-master
$Date = Get-Date

# Grab the name and size of each file inside of the specified directory
foreach ($File in $FilestoScan)
    {
    $File.Name +  ":" +  $File.Length >> .\Unfiltered_Files.txt 
    }

#************************** F I L E  S I Z E  S C A N ******************************
"-----------------------------------------------------------------------------------" > .\Results\$env:COMPUTERNAME"_FileSizeScan.txt"    
"`nScan Initiated on $Date`n" >> .\Results\$env:COMPUTERNAME"_FileSizeScan.txt"
"-----------------------------------------------------------------------------------`n" >> .\Results\$env:COMPUTERNAME"_FileSizeScan.txt"
write-output -erroraction SilentlyContinue "" >> .\Results\$env:COMPUTERNAME"_FileSizeScan.txt" 
write-output -erroraction SilentlyContinue "********* FILE SIZE IOC HITS FOR $env:COMPUTERNAME ***********" >> .\Results\$env:COMPUTERNAME"_FileSizeScan.txt"
write-output -erroraction SilentlyContinue "_________________________________________________________" >> .\Results\$env:COMPUTERNAME"_FileSizeScan.txt"

# Select the files that match the sizes specified in your IOC and put the results into a text file.
$FileSizeIOC = get-content .\Indicators\File_Size_IOC.txt
foreach ($Size in $FileSizeIOC)
    {
    get-content ".\Unfiltered_Files.txt" | Select-String -Pattern :$Size\Z >> .\Results\$env:COMPUTERNAME"_FileSizeScan.txt"
    }


#************************** F I L E  N A M E  S C A N *******************************
"-----------------------------------------------------------------------------------" > .\Results\$env:COMPUTERNAME"_FileNameScan.txt"    
"`nScan Initiated on $Date`n" >> .\Results\$env:COMPUTERNAME"_FileNameScan.txt"
"-----------------------------------------------------------------------------------`n" >> .\Results\$env:COMPUTERNAME"_FileNameScan.txt"
Write-Output -ErrorAction SilentlyContinue "" >> .\Results\$env:COMPUTERNAME"_FileNameScan.txt"
write-output -erroraction SilentlyContinue "********* FILE NAME IOC HITS FOR $env:COMPUTERNAME ***********" >> .\Results\$env:COMPUTERNAME"_FileNameScan.txt"
write-output -erroraction SilentlyContinue "_________________________________________________________" >> .\Results\$env:COMPUTERNAME"_FileNameScan.txt"

# Select the files that match the names specified in your IOC and put the results into a text file.
$FileNameIOC = get-content .\Indicators\File_Name_IOC.txt
foreach ($Name in $FileNameIOC)
    {
    get-content ".\Unfiltered_Files.txt" | Select-String $Name >> .\Results\$env:COMPUTERNAME"_FileNameScan.txt"
    }
# Clean up Files that did not match any IOCs
Remove-Item .\Unfiltered_Files.txt


#************************* C O N N E C T I O N   S C A N ****************************
$PortIOC = get-content .\Indicators\PORT_IOC.txt
$Netstat = netstat -ano
"-----------------------------------------------------------------------------------" > .\Results\$env:COMPUTERNAME"_ConnScan.txt"    
"`nScan Initiated on $Date`n" >> .\Results\$env:COMPUTERNAME"_ConnScan.txt"
"-----------------------------------------------------------------------------------`n" >> .\Results\$env:COMPUTERNAME"_ConnScan.txt"  
write-output -erroraction SilentlyContinue "" >> .\Results\$env:COMPUTERNAME"_ConnScan.txt"
write-output -erroraction SilentlyContinue "********* CONNECTION SCAN RESULTS FOR $env:COMPUTERNAME ***********" >> .\Results\$env:COMPUTERNAME"_ConnScan.txt"
write-output -erroraction SilentlyContinue "______________________________________________________________" >> .\Results\$env:COMPUTERNAME"_ConnScan.txt"

foreach ($IOC in $PortIOC)
    {
    $Netstat | select-string -Pattern :$IOC\s >> .\Results\$env:COMPUTERNAME"_ConnScan.txt"
    }
sleep 3


#************************** H A S H   S C A N ******************************
"-----------------------------------------------------------------------------------" > .\Results\$env:COMPUTERNAME"_HashScan.txt"    
"`nScan Initiated on $Date`n" >> .\Results\$env:COMPUTERNAME"_HashScan.txt"
"-----------------------------------------------------------------------------------`n" >> .\Results\$env:COMPUTERNAME"_HashScan.txt"
write-output -erroraction SilentlyContinue "" >> .\Results\$env:COMPUTERNAME"_HashScan.txt"
write-output -erroraction SilentlyContinue "********* HASH SCAN IOC HITS FOR $env:COMPUTERNAME ***********" >> .\Results\$env:COMPUTERNAME"_HashScan.txt"
write-output -erroraction SilentlyContinue "________________________________________________________" >> .\Results\$env:COMPUTERNAME"_HashScan.txt"

# Hash(es) to scan for.
$hash = get-content -ErrorAction SilentlyContinue  .\Indicators\HASH_IOC.txt

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
Get-d_hashes $Dir_hash_files\* -ErrorAction SilentlyContinue > .\dir_hash.txt
   
$hash = get-content .\Indicators\hash_ioc.txt
# Looks for the hash(es) we give it.
foreach ($ioc_out in $hash) 
    { 
    get-content ".\dir_hash.txt" | select-string $ioc_out >> .\Results\$env:COMPUTERNAME"_HashScan.txt"   
    }

# Removes initial directory file hashes.
remove-item .\dir_hash.txt -ErrorAction SilentlyContinue
Sleep 2


#************************* R E G I S T R Y   S C A N *********************************
# Variables to get the user listing (Vista and up) and reads in the list of registry IOCs. It excludes the currently logged on user since the hive is already loaded.
$userlist = Get-ChildItem "C:\users" -Exclude $env:username
$reg_ioc = get-content .\Indicators\Reg_IOC.txt

# Loops through to load the ntuser.dats.
foreach ($user in $userlist) 
    {
    $username = $user.name
    reg load "hku\$username" "C:\users\$username\NTUSER.DAT" 2>&1 | out-null
    }

"-----------------------------------------------------------------------------------" > .\Results\$env:COMPUTERNAME"_Registryscan.txt"
"`nScan Initiated on $Date`n" >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
"-----------------------------------------------------------------------------------`n" >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
write-output -erroraction SilentlyContinue "" >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
write-output -erroraction SilentlyContinue "********* REGISTRY SCAN RESULTS FOR $env:COMPUTERNAME ***********" >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
write-output -erroraction SilentlyContinue "____________________________________________________________" >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"

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
            "`r`n<<<< Reg Key: HKU\" + $myusers.ToUpper() + "\" + $regKey.ToUpper() + " - Value : "+ $regValue +" >>>>" >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                if($regValue -eq $null)
                    {
                    # No Registry value specified (only a key).
                    ($foundValue = Get-ChildItem hku:\$myusers\$regKey -force  -ErrorAction Stop)
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                    echo "***** IOC HIT ! ***** " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                    if ( $foundValue -eq $null) 
                        {
                        # If it's a key with no more subkeys, we will use Get-ItemProperty to list any values.
                        ($foundValue = Get-ItemProperty -ErrorAction stop hku:\$myusers\$regKey)
                        echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                        echo "***** IOC HIT ! ***** " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                        echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
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
                ($foundValue = Get-ItemProperty -ErrorAction stop hku:\$myusers\$regKey | Select-Object -ExpandProperty $regValue -ErrorAction stop  >> .\Results\$env:COMPUTERNAME"_Registryscan.txt")
                # Will be visible in the reg_scan.txt file anywhere/anytime there is a hit on an IOC.
                echo "************************ " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                echo "****** IOC HIT ! ******* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                echo "************************ " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                if ( $foundValue -eq $null) 
                    {
                    Write-Error("No Hit") -ErrorAction stop
                    }
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
                "`r`n<<<< Reg Key for user $env:username : HKCU\" + $regKey.ToUpper() + " - Value : "+ $regValue +" >>>>" >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                if($regValue -eq $null)
                    {
                    # No Registry value specified (only a key).
                    ($foundValue = Get-ChildItem hkcu:\$regKey -force  -ErrorAction Stop)
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                    echo "***** IOC HIT ! ***** " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                    if ( $foundValue -eq $null) 
                        {
                        # If it's a key with no more subkeys, we will use Get-ItemProperty to list any values.
                        ($foundValue = Get-ItemProperty -ErrorAction stop hkcu:\$regKey)
                        echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                        echo "***** IOC HIT ! ***** " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                        echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
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
                    ($foundValue = Get-ItemProperty -ErrorAction stop hkcu:\$regKey | Select-Object -ExpandProperty $regValue -ErrorAction stop  >> .\Results\$env:COMPUTERNAME"_Registryscan.txt")
                    # Will be visible in the reg.txt file anywhere/anytime there is a hit on an IOC.
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                    echo "***** IOC HIT ! ***** " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_Registryscan.txt"
                    if ( $foundValue -eq $null) 
                        {
                        Write-Error("No Hit") -ErrorAction stop
                        }
                    }
                }
        catch
            {
            # Does nothing, it is just here to hide errors from the screen.    
            }
        }
    }

# Begins the work of searching the HKLM hive.
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
                "`r`n<<<< Reg Key for $env:computername : HKLM\" + $regKey.ToUpper() + " - Value : "+ $regValue +" >>>>" >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
                if($regValue -eq $null)
                    {
                    # No Registry value specified (only a key).
                    ($foundValue = Get-ChildItem hklm:\$regKey -force  -ErrorAction Stop >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt")
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
                    echo "***** IOC HIT ! ***** " >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
                    if ( $foundValue -eq $null) 
                        {
                        # If it's a key with no more subkeys, we will use Get-ItemProperty to list any values.
                        ($foundValue = Get-ItemProperty -ErrorAction stop hklm:\$regKey >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt")
                        echo "********************* " >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
                        echo "***** IOC HIT ! ***** " >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
                        echo "********************* " >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
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
                    ($foundValue = Get-ItemProperty -ErrorAction stop hklm:\$regKey | Select-Object -ExpandProperty $regValue -ErrorAction stop  >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt")
                    # Will be visible in the reg.txt file anywhere/anytime there is a hit on an IOC.
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
                    echo "***** IOC HIT ! ***** " >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
                    echo "********************* " >> .\Results\$env:COMPUTERNAME"_RegistryScan.txt"
                    if ( $foundValue -eq $null) 
                        {
                        Write-Error("No Hit") -ErrorAction stop
                        }
                    }
            }
        catch
            {
            # Does nothing,  it is just here to hide errors from the screen.  
            }
        }

sleep 3

# Cleans up objects no longer needed.
[gc]::collect()
start-sleep -s 3

# Unloads the ntuser.dats from the Registry.
foreach ($user in $userlist)
    {
    $username = $user.name
    reg unload "hku\$username" 2>&1 | out-null
    }

Sleep (4)
