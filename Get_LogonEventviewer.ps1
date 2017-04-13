Clear-Host

$user = $null
$date = $null
$computer = $null
$Computer = Read-Host "Computername?"

$isonline = Test-Connection $Computer -Count 1 -ErrorAction SilentlyContinue
$date = (get-date).AddDays(-100)  #choose number of days to go back
if($isonline){

        $ET = $null #EventType
        $Result = @() #array showing results
        $skip = 1 #settings
        $skipLocksAndUnlocks = 0 #If value = 1, only logon, logoff, boot and shutdown are captured.

        if($skip -ne 1){        
            $settings = @("Aanmelden","Afmelden","Andere aan- of afmeldingsgebeurtenissen","Accountvergrendeling")
            #$settings = @("logon","logoff"," Other Logon/Logoff Events"," Account Lockout")
            foreach($setting in $settings)
            {
                $check =  &psexec \\$Computer auditpol /get /subcategory:"$setting"                
                sleep 2

                if($check -like "*voltooid*"){                    
                    Write-host "Auditpol-setting ""$setting"" was already correctly applied." -ForegroundColor Yellow
                    sleep 2
                }else{
                   &psexec \\$Computer auditpol /set /subcategory:"$setting" /success:enable /failure:enable
                    Write-host "Auditpol-setting ""$setting"" was installed just now. From now on, lock/unlock events will be saved to the logfile." -ForegroundColor Yellow
                    sleep 5
                }
            }#end foreach
        } # end skip debug

         Write-Host "Gathering Event Logs, this can take awhile..." -ForegroundColor Gray

        # retrieve logfiles into 1 variable, only those that match our filter
        $ELogs = Get-WinEvent -ComputerName $computer -FilterHashTable @{LogName = "system"; ID = 7001,7002,6005,6006;StartTime = $date; }

        If ($ELogs)
        {
            Write-Host "Processing logon..." -foregroundcolor cyan
             ForEach ($Log in $ELogs) # loop trough each event and check what event that is
             {
                # label the ID
                IF ($Log.Id -eq 7001){
                    $ET = "Logon"
                }

                IF ($Log.Id -eq 7002){
                    $ET = "Logoff"
                }

                IF ($Log.Id -eq 6005){
                    $ET = "Boot initiated"
                }

                IF ($Log.Id -eq 6006){
                    $ET = "Shutdown initiated"
                }

                #$ET  Convert to XML
                $eventXML = [xml]$Log.ToXml()
                #if there is data in the XML
                if($eventXML.Event.EventData.Data){
                    $sid =  $eventXML.Event.EventData.Data[1].'#text' #take dataobject 2 (0,1)
                    write-host $sid -ForegroundColor Yellow
                    if($sid){
                    $objSID = New-Object System.Security.Principal.SecurityIdentifier("$sid")

                       # if SID is a local administrator
                        if($sid.Substring(0,6) -eq "S-1-5-" -and $sid.Substring(($sid.Length)-3,3) -eq "500"){
                            $user = "Administrator"
                        }
                        else{
                            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
                            $user = $objUser.Value
                            write-host $user -ForegroundColor Magenta
                        }
                    }
                }
                #create hashtable "result" with keys and values
                $Result += New-Object PSObject -Property @{
                    Computer = $log.MachineName
                    Time = $Log.TimeCreated
                    EventId = $Log.Id
                   'Event Type' = $ET
                    user = $user
                    sid = $objSID
                    message = $log.Message
                }
             }#end foreach
            #$Result | Select Time,"Event Type",User,sid,message | Sort Time -Descending | Out-GridView
        }
        Else
         {
            Write-Host "Problem with receiving system-logfiles." -ForegroundColor red
         }

      if($skipLocksAndUnlocks -eq 0)
      {
         write-host "Gathering Workstation Locks..." -ForegroundColor Cyan
         #function lock
         # retrieve logfiles into 1 variable, only those that match our filter
        $ELogs =  Get-WinEvent  -ComputerName $computer -FilterHashTable @{LogName = "Security"; ID = 4800,4801;StartTime = $date; } #-ErrorAction SilentlyContinue
        If ($ELogs)
         {
             ForEach ($Log in $ELogs)# loop trough each event and check what event that is
             {
                Write-Host "Processing Workstation Locks..." -ForegroundColor Cyan
                       # label the ID
                   If ($Log.Id -eq  4800){
                        $ET = "Lock"
                   }
                   ElseIf ($Log.Id -eq 4801){
                     $ET = "unlock"
                   }
                   Else {
                    Continue
                   }
                   #Convert to XML
                   $eventXML = [xml]$log.ToXml()

                   if($eventXML.Event.EventData.Data){
                      $sid =  $eventXML.Event.EventData.Data[0].'#text'     #take dataobject 0      = SID
                      $user =  $eventXML.Event.EventData.Data[1].'#text'    #take dataobject 1      = readable username (samaccountname), in this eventlog the samaccountname was kept, we don't need to convert SID into SAM
                    }
                    #add row with data to the hashtable $result
                   $Result += New-Object PSObject -Property @{
                       Computer = $log.MachineName
                       Time = $Log.TimeCreated
                       EventId = $Log.Id
                       'Event Type' = $ET
                       user = $user
                       sid = $sid
                       message = $Log.Message
                   }
            }#end foreach

            # export all data to gridview sorted by time
            $Result | Select-Object Computer, Time, EventId, "Event Type", User, SID, Message | Sort-Object Time -Descending | Out-GridView
         }

         Else {
            ""
            Write-Host "Problem with receiving Workstation Locks logfiles or the computers has no such logs." -ForegroundColor Magenta
            ""
            $Result | Select-Object Computer, Time,EventId, "Event Type",User,SID,Message | Sort-Object Time -Descending | Out-GridView
         }

        }else{
            $Result | Select-Object Computer, Time,EventId, "Event Type",User,SID,Message | Sort-Object Time -Descending | Out-GridView
        }
         ""
         Write-Host "Done." -ForegroundColor green
}#end IF test-connection
else{
    write-host "PC niet online" -ForegroundColor cyan
}