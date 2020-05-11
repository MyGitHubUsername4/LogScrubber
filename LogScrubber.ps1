#Author: Paul Harrison
#Date Written: 5/4/2020
#
#
#
#LogScrubber - searches unstructured data and scrubs it while maintaining a log of what was scrubbed and a key to the scrubbed data

<#
    Features that could be added:
     - Support for IPv6
     - Scrub only certain octets of the IPs
     - 
#>


<#
.Synopsis
   Removes IPv4 IPs and bad words from an unstructured log file
.DESCRIPTION
   Searches LogFileName for IPv4 addresses then logs those IPs in LogFileName-IPsKey with a list of fake IPs.  If the same IP is used multiple times in the log file it will have the same fake IP replacing it each time.
   It then checks the log file for every bad word listed in the BadWordFile and replaces them with fake bad words.  If a bad word is used multiple times in the log file it will have the same fake bad word replacing it each time.
.EXAMPLE
   New-LSIPs -IPList MyFile.txt-IPs
.INPUTS
   LogFileName - The path and name of the log file to scrub
   BadWordFile - The path and name of the bad words file
.OUTPUTS
   LogFileName-BadWordKey - file with the list of bad words and the correlating fake bad word
   LogFileName-IPScrubbed - a copy of the logfile with fake IPs instead of real IPs but still containing the bad words
   LogFileName-IPsKey     - file with the list of IPs in the log file and correlating fake IPs
   LogFileName-Scrubbed   - file with IPs and bad words removed fromt he file and replaced with correlating fake IPs and bad words
.NOTES
   This function is very efficient at scrubbing IPs but very ineffecient at scrubbing bad words.  I will look into a more efficient way of scrubbing bad words.
#>
Function Invoke-LSScrub{
    Param
    (
        #LogFileName - The path and name of the log file to scrub
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        $LogFileName,
        #BadWordFile - The path and name of the file with the bad words list
        [Parameter(Mandatory=$false, 
                   ValueFromPipeline=$false,
                   Position=1)]
        $BadWordFile,
        [Switch]$First3Octets
    )
    #Validation
    If($null -ne $BadWordFile -and  (gc $BadWordFile -TotalCount 1) -ne 'Original'){
        $Fix = (Read-Host -Prompt 'The header line of $BadWordFile should only be "Original" (without quotes).  Shall I fix this for you (Y/N)?').ToUpper()
        If($Fix -eq 'Y'){
            $BadWordContents = gc $BadWordFile
            "Original" | Set-Content $BadWordFile
            $BadWordContents | Add-Content $BadWordFile
        }Else{
            Write-Error "Bad formatting in $BadWordFile." -ErrorAction Stop
        }
    }

    Clear-LSScrubFiles -LogFileName $LogFileName
    Write-Host "IP scrubbing Started" -ForegroundColor Green -BackgroundColor Black
    Invoke-LSIPScrub -LogFileName $LogFileName -First3Octets:$First3Octets
    Write-Host "IP Scrubbing Complete" -ForegroundColor Green -BackgroundColor Black

    If($null -ne $BadWordFile -and  (Test-Path $BadWordFile)){
        Write-Host "Bad Word Scrubbing started... This could take a while depending on the size of the log and the size of the badwords list." -ForegroundColor Green -BackgroundColor Black
        Invoke-LSBadWordScrub -LogFileName ($LogFileName+"-IPScrubbed") -BadWordFile $BadWordFile -BadWordList ($LogFileName+"-BadWords") -BadWordKeyFile ($LogFileName+"-BadWordKey") -ScrubbedFile ($LogFileName+"-Scrubbed") #-OriginalLogFileName $LogFileName
        Write-Host "Scrubbing Complete!" -ForegroundColor Green -BackgroundColor Black
        Write-Host "`t$LogFileName-BadWords`t`t- List of bad words found in $LogFileName"
        Write-Host "`t$LogFileName-BadWordKey`t`t- Key of bad words to fake bad words"
        Write-Host "`t$BadWordFile`t`t- The source file for bad words"
        Write-Host "`t$LogFileName-Scrubbed`t`t- Scrubbed log." -ForegroundColor Green -BackgroundColor Black
    }Else{
        Write-Host "No BadWordFile entered or file does not exist, only IPs scrubbed, not bad words."
        Write-Host "Log file with only IPs scrubbed: $LogFileName-IPScrubbed"        
    }

}

<#
.Synopsis
   Removes output files generated for a log file generated previously by Invoke-LSScrub
.DESCRIPTION
   Removes LogFileName-IPScrubbed, LogFileName-IPsKey, LogFileName-BadWordKey, LogFileName-Scrubbed
.EXAMPLE
   Clear-LSScrubFiles -LogFileName MyFile.txt-IPs
.INPUTS
   LogFileName - The path and name of the log file to scrub
.OUTPUTS
.NOTES
.FUNCTIONALITY
#>
Function Clear-LSScrubFiles{
    Param(
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        $LogFileName
    )
    rm -Force ($LogFileName+"-IPScrubbed"),($LogFileName+"-IPsKey"),($LogFileName+"-BadWordKey"),($LogFileName+"-Scrubbed"),($LogFileName+"-BadWords"),($LogFileName+"-IPKey"),($LogFileName+"-IPs")  -ea 0
}

<#
.Synopsis
   Removes IPv4 IPs from LogFileName
.DESCRIPTION
   Searches LogFileName for IPv4 addresses then logs those IPs in LogFileName-IPsKey with a list of fake IPs.  If the same IP is used multiple times in the log file it will have the same fake IP replacing it each time.
.EXAMPLE
   Invoke-LSIPScrub -LogFileName MyFile.txt-IPs
.INPUTS
   LogFileName - The path and name of the log file to scrub
.OUTPUTS
   LogFileName-IPSKey - A file containing all IPv4 IPs found in the log file and the correlating fake IP it is replaced with
   LogFileName-IPScrubbed - A file containing a scrubbed copy of the log file with fake IPs instead of real IPv4 IPs
.NOTES
.FUNCTIONALITY
#>
Function Invoke-LSIPScrub{
    Param
    (
        #LogFileName - The path and name of the log file to scrub
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        $LogFileName,
        [Switch]$First3Octets
    )
    Find-LSIPs -LogFileName $LogFileName -First3Octets:$First3Octets
    New-LSList -List ($LogFileName+"-IPs") -ItemType "IP" -OutputFile ($LogFileName+"-IPKey")    
    Set-LSLogFile -LogFile $LogFileName -KeyFile ($LogFileName+"-IPKey") -OutputFile ($LogFileName+"-IPScrubbed")

    Write-Host "`t$LogFileName`t`t- Original Log"
    Write-Host "`t$LogFileName-IPs`t`t- List of all IPs found in $LogFileName"
    Write-Host "`t$LogFileName-IPKey`t`t- Key of IPs in the log to fake IPs"
    Write-Host "`t$LogFileName-IPScrubbed`t`t- Log file is IPs scrubbed but with bad words remaining"
}

<#
.Synopsis
   Removes bad words from LogFileName
.DESCRIPTION
   Searches LogFileName for bad words from BadWordFile then logs those bad words in LogFileName-BadWordKey with a list of fake bad words.  If the same bad word is used multiple times in the log file it will have the same fake bad word replacing it each time.
.EXAMPLE
   Invoke-LSBadWordScrub -LogFileName MyFile.txt-IPs
.INPUTS
   LogFileName - The path and name of the log file to scrub
   BadWordFile - The path and name of the file containing the bad words
   BadWordKeyFile - The path and name of the file that will contain the key to lookup between existing bad words and fake bad words
   ScrubbedFile - The path and name of the file that will contain the scrubbed log
.OUTPUTS
   BadWordKeyFile - The path and name of the file that will contain the key to lookup between existing bad words and fake bad words
   ScrubbedFile - The path and name of the file that will contain the scrubbed log
.NOTES
.FUNCTIONALITY
#>
Function Invoke-LSBadWordScrub{
    Param
    (
        #LogFileName - The path and name of the log file to scrub
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        $LogFileName,
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   Position=1)]
        [ValidateNotNullOrEmpty()]
        $BadWordFile, # a file with bad words to find
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   Position=2)]
        [ValidateNotNullOrEmpty()]
        $BadWordList, #bad words found in the log file
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   Position=2)]
        [ValidateNotNullOrEmpty()]
        $BadWordKeyFile, #the file with the bad word and fake word
        [Parameter(Mandatory=$true,
                    ValueFromPipeline=$false,
                    Position=3)]
        [ValidateNotNullOrEmpty()]
        $ScrubbedFile
    )

    Find-LSBadWords -LogFileName $LogFileName -BadWordFile $BadWordFile -BadWordList $BadWordList
    New-LSList -List $BadWordList -ItemType "BadWord" -OutputFile $BadWordKeyFile    
    Set-LSLogFile -LogFile $LogFileName -KeyFile $BadWordKeyFile -OutputFile $ScrubbedFile
}

<#
.Synopsis
   Finds the IPs in the LogFileName
.DESCRIPTION
   Searches the file LogFileName using a regular expression then outputs the data to $LogFileName-IPs
.EXAMPLE
   Invoke-LSIPScrub -LogFileName MyFile.txt
.INPUTS
   LogFileName
.OUTPUTS
   LogFileName-IPs
.NOTES
   Users should use Invoke-LSScrub which will call this function
.FUNCTIONALITY
   Helper function for Invoke-LSScrub
#>
Function Find-LSIPs{
    Param
    (
        #LogFileName - The path and name of the log file to scrub
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        $LogFileName,
        [switch]$First3Octets
    )
    Begin{
        $IPRegex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b’
    }
    Process{
        $IPListFile = $LogFileName + "-IPs"
        ((select-string -Path $LogFileName -Pattern $IPRegex -AllMatches).Matches).Value | select @{N="Original";E={If($First3Octets){$_.split('.')[0..2] -join '.'}Else{$_}}} -Unique | Export-Csv $IPListFile -NoTypeInformation
    }
}


<#
.Synopsis
   Generates a list of fake values for each real value used in the log file
.DESCRIPTION
   Generates a list of fake values for each real value used in the log file
.EXAMPLE
   New-LSList -List MyLog.txt-IPs -ItemType IP -OutputFile MyLog.txt-IPKey
.INPUTS
   List - the path and file name of a list of values that appear in the log file as output by a Find function (Find-LSBadWords or Find-LSIPs)
   ItemType - A string to be used as part of the replacement data in a scrubbed file in the format <Fake$ItemType$Num> where $Num is a number startingat 0 and incrementing by 1
   OutputFile - the file to output the finished key to
.OUTPUTS
   OutputFile - The file with Original and Replacement values based on $List
.NOTES
   Users should use Invoke-LSScrub which will call this function
.FUNCTIONALITY
   Helper function for Invoke-LSScrub
#>
Function New-LSList{
    Param
    (
        # IPList - The list of IPs 
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        $List,
        # Output File
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()] 
        $ItemType, #(IP,BadWord)
        # Output File
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $OutputFile #($FileName+"-IP") or ($FileName+"-BadWord")
    )

    $RequiredLength = ((gc $List | measure -Line).Lines).ToString().Length
    $formatter = "{0:d"+$FakeIPLength+"}"
    $ItemNum = 0
    If(Test-Path $OutputFile){rm $OutputFile}
        Import-Csv $List | ForEach-Object {
        Add-Member -MemberType NoteProperty -InputObject $_ -Name "Replacement" -Value ("<Fake$ItemType{0:d$($RequiredLength)}>" -f $ItemNum) -PassThru
        $ItemNum++
    } | Export-Csv $OutputFile -Force -NoTypeInformation

}

<#
.Synopsis
   Generates a list of fake values for each real value used in the log file
.DESCRIPTION
   Generates a list of fake values for each real value used in the log file
.EXAMPLE
   New-LSList -List MyLog.txt-IPs -ItemType IP -OutputFile MyLog.txt-IPKey
.INPUTS
   List - the path and file name of a list of values that appear in the log file as output by a Find function (Find-LSBadWords or Find-LSIPs)
   ItemType - A string to be used as part of the replacement data in a scrubbed file in the format <Fake$ItemType$Num> where $Num is a number startingat 0 and incrementing by 1
   OutputFile - the file to output the finished key to
.OUTPUTS
   OutputFile - The file with Original and Replacement values based on $List
.NOTES
   Users should use Invoke-LSScrub which will call this function
.FUNCTIONALITY
   Helper function for Invoke-LSScrub
#>
Function Set-LSLogFile{
    Param
    (
        # LogFile The log to scrub
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        $LogFile,
        # Key - File containing the original word and replacement value.  The header lines for this file must be: "Original","Replacement"
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $KeyFile,
        #OutputFile - File for output to go to containing the scrubbed log
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        $OutputFile
    )
    If(Test-Path $OutputFile){rm $OutputFile}
    $LogFileContents = gc $LogFile
    ForEach($line in (Import-Csv $KeyFile)){
        $LogFileContents = $LogFileContents -Replace($line.Original,$line.Replacement)
    }
    $LogFileContents | Out-File $OutputFile
}

<#
.Synopsis
   Find bad words in LogFileName from BadWordFile and writes them to BadWordList
.DESCRIPTION
   Find bad words in LogFileName from BadWordFile and writes them to BadWordList.  This way only bad words actually in your log file are shown in the list.
.EXAMPLE
   Find-LSBadWords -LogFileName MyLog.txt -BadWordFile badwords.txt -BadWordList MyLog.txt-BadWords
.INPUTS
   LogFileName - The path and name of the log file to examine
   BadWordFile - The path and name of the file containing the bad words
   BadWordList - The path and name of the file that will contain the list of bad words in LogFileName
.OUTPUTS
   BadWordList - The path and name of the file that will contain the list of bad words in LogFileName
.NOTES
   Users should use Invoke-LSScrub which will call this function
.FUNCTIONALITY
   Helper function for Invoke-LSScrub
#>
Function Find-LSBadWords{
    Param
    (
        # LogFileName The path and name of the log file to scrub
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   Position=0)]
        [ValidateNotNullOrEmpty()]
        $LogFileName,
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   Position=1)]
        [ValidateNotNullOrEmpty()]
        $BadWordFile,
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$false,
                   Position=2)]
        [ValidateNotNullOrEmpty()]
        $BadWordList
    )
    If(Test-Path $BadWordList){rm $BadWordList -Force}
    $BadWords = @()
    gc $BadWordFile | %{$BadWords += $_}
    ((gc $LogFileName | Select-String $BadWords -AllMatches).Matches).Value | select @{N="Original";E={$_}} -Unique | Export-Csv ($BadWordList ) -NoTypeInformation
}










#Export-ModuleMember -Function Invoke-LSScrub, Invoke-LSBadWordScrub, Invoke-LSIPScrub