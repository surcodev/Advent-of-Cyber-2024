# Define the YARA rule path
$yaraRulePath = "C:\Tools\YARARULES\CheckRegCommand.yar"
# Define the path to the YARA executable
$yaraExecutable = "C:\ProgramData\chocolatey\lib\yara\tools\yara64.exe"
$logFilePath = "C:\Tools\YaraMatches.txt"


# Function to log event data to a file
function Log-EventDataToFile {
    param (
        [string]$commandLine,
        [string]$yaraResult,
        [string]$eventId,
        [string]$eventTimeCreated,
        [string]$eventRecordID
    )

    # Prepare log entry
    $logEntry = "Event Time: $eventTimeCreated`r`nEvent ID: $eventId`r`nEvent Record ID: $eventRecordID`r`nCommand Line: $commandLine`r`nYARA Result: $yaraResult`r`n"
    $logEntry += "--------------------------------------`r`n"

    # Debugging output to ensure logging function is called
    Write-Host "Logging to file: $logFilePath"
    Write-Host $logEntry

    # Append the log entry to the file
    Add-Content -Path $logFilePath -Value $logEntry
}


# Function to run YARA on the command line and log result only if a match is found
function Run-YaraRule {
    param (
        [string]$commandLine,
        [string]$eventId,
        [string]$eventTimeCreated,
        [string]$eventRecordId

    )

    # Create a temporary file to store the command line for YARA processing
    $tempFile = [System.IO.Path]::GetTempFileName()
    try {
        # Write the command line to the temporary file
        Set-Content -Path $tempFile -Value $commandLine

        # Run YARA on the temporary file
        $result = & $yaraExecutable $yaraRulePath $tempFile

        # Only log if YARA finds a match (non-empty result)
        if ($result) {
            #Write-Host "YARA Match Found for Command Line: $commandLine"
            Write-Host "YARA Result: $result"

            # Log the event data to a file in C:\Tools
            Log-EventDataToFile -commandLine $commandLine -yaraResult $result -eventId $eventId -eventTimeCreated $eventTimeCreated -eventRecordID $eventRecordId
            
            # Display warning
            $warning = "Malicious command detected!THM{GlitchWasHere}"
            Show-MessageBox -Message $warning

        }
    } finally {
        # Clean up the temporary file after processing
        Remove-Item -Path $tempFile -Force
    }
}

# Function to display Popup
Add-Type -AssemblyName System.Windows.Forms
function Show-MessageBox {

    param (
        [string]$Message,
        [string]$Title = "Notification"
        
    )

   # Start a new PowerShell job that runs asynchronously and doesn't block the main flow
    Start-Job -ScriptBlock {
        param($msg, $ttl)
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show($msg, $ttl)
    } -ArgumentList $Message, $Title
    
}

# Function to handle Sysmon events
function Handle-SysmonEvent {
    param (
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$event
    )
    #write-host "handling event"

    # Extract Event ID, time created, and relevant properties
    $eventID = $event.Id
    $eventRecordID = $event.RecordId
    $eventTimeCreated = $event.TimeCreated
    $commandLine = $null

    #write-host "Current event record id: " $event.RecordId
    #write-host "Last event record id: " $lastRecordId
    if ($eventID -eq 1 -and ($event.Properties[4] -notcontains "C:\ProgramData\chocolatey\lib\yara\tools\yara64.exe") ) {  
    # Event ID 1: Process Creation
        $commandLine = $event.Properties[10].Value  # Get the command line used to start the process
        #write-host $commandLine
        if ($commandLine) {
        Run-YaraRule -commandLine $commandLine -eventId $eventID -eventTimeCreated $eventTimeCreated -eventRecordId $eventRecordID

    }
    }
  
    
}

# Poll for new events in the Sysmon log
$logName = "Microsoft-Windows-Sysmon/Operational"
wevtutil cl "Microsoft-Windows-Sysmon/Operational"

# Initialize lastRecordId safely
$lastRecordId = $null
[int[]]$processedEventIds=1
try {
    $lastEvent = Get-WinEvent -LogName $logName -MaxEvents 1
    if ($lastEvent) {
        $lastRecordId = $lastEvent.RecordId
    } else {
        Write-Host "No events found in Sysmon log."
    }
} catch {
    Write-Host "Error retrieving last record ID: $_"
    exit
}

Write-Host "Monitoring Sysmon events... Press Ctrl+C to exit."

while ($true) {
    try {
        # Get new events after the last recorded ID
        $processedEventIds= $processedEventIds|Sort-Object
        #write-host $processedEventIds
        $lastRecordId=$processedEventIds[-1]
        #write-host $lastRecordId
        $newEvents = Get-WinEvent -LogName $logName | Where-Object { $_.RecordId -gt $lastRecordId }
        #write-host $newEvents.Count

        if ($newEvents.Count -eq 0) {
            Write-Host "No new events found."
        }

        else{

        foreach ($event in $newEvents) {
            # Check if this event ID has already been processed
            if ($event.RecordId -in $processedEventId ) {
             Write-Host "Record ID $($event.RecordId) has already been processed"
            
            }
                
            else{    
                # Process only new events
                Handle-SysmonEvent -event $event

                # Add the event ID to the processed set
                $processedEventIds+=$event.RecordId
                #write-host "processed events: " $processedEventIds
                }

                # Update the last processed event ID
                
            }
        }
    } catch {
        Write-Host "Log is empty"
    }

    # Sleep for 5 seconds before checking again
    Start-Sleep -Seconds 2
}
