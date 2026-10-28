#Requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateSet('Processes','Memory','Events','State','Log')][string[]]$Sections=@('Processes','Memory'),
    [int[]]$ProcessIds,
    [string]$StateDirectory,
    [ValidateRange(1,30)][int]$EventDays=14,
    [ValidateRange(1,100)][int]$MaximumEvents=20,
    [ValidateRange(256,65536)][int]$LogTailBytes=6000,
    [string]$ResultJson
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Diagnostics.Common.ps1')
if(-not $StateDirectory){$StateDirectory=Join-Path $env:ProgramData 'GephTun'}
$StateDirectory=Get-GephPackageFullPath $StateDirectory
$checks=[Collections.Generic.List[object]]::new()
$data=[ordered]@{}
foreach($section in $Sections){
    try{
        switch($section){
            'Processes' {
                if($ProcessIds){$ids=@($ProcessIds|Select-Object -Unique)}
                else{
                    $processRows=@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe' OR Name='tun2socks-windows-amd64.exe' OR Name LIKE 'geph%'" -ErrorAction Stop)
                    $ids=@($processRows|Select-Object -ExpandProperty ProcessId)
                    $data.ProcessDiscovery=@($processRows|ForEach-Object{[pscustomobject]@{ProcessId=$_.ProcessId;Name=$_.Name;CommandLine=$_.CommandLine;CommandReadable=![string]::IsNullOrWhiteSpace($_.CommandLine)}})
                }
                foreach($idValue in $ids){if($idValue -lt 1){throw 'Process IDs must be positive.'}}
                $data.Processes=@($ids|ForEach-Object{Get-DiagnosticProcess ([int]$_)})
                if(@($data.Processes|Where-Object{$_.State -eq 'UNKNOWN'}).Count){throw 'Some process details could not be read; see individual records.'}
            }
            'Memory' {
                $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
                $data.Memory=[pscustomobject]@{FreePhysicalBytes=[long]$os.FreePhysicalMemory*1024;TotalPhysicalBytes=[long]$os.TotalVisibleMemorySize*1024;LastBoot=$os.LastBootUpTime}
            }
            'Events' {
                $events=@(Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Microsoft-Windows-Resource-Exhaustion-Detector';StartTime=(Get-Date).AddDays(-$EventDays)} -MaxEvents $MaximumEvents -ErrorAction Stop)
                $data.Events=@($events|Select-Object TimeCreated,Id,Message)
            }
            'State' {
                $records=@(foreach($leaf in @('session.json','status.json')){
                    $path=Join-Path $StateDirectory $leaf
                    $state=Get-DiagnosticFileState $path
                    $value=$null
                    if($state.State -eq 'PRESENT'){
                        try{$value=Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop|ConvertFrom-Json -ErrorAction Stop}
                        catch{$state.State='UNKNOWN';$state.Error=$_.Exception.Message}
                    }
                    [pscustomobject]@{Path=$path;State=$state.State;Error=$state.Error;Value=$value}
                })
                $data.State=$records
                if(@($records|Where-Object{$_.State -eq 'UNKNOWN'}).Count){throw 'Some state files could not be read; absence was not assumed.'}
            }
            'Log' {
                $path=Join-Path $StateDirectory 'logs/GephTun.log'
                $state=Get-DiagnosticFileState $path
                $text=$null
                if($state.State -eq 'PRESENT'){
                    $stream=$null
                    try{
                        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                        $take=[int][Math]::Min($stream.Length,$LogTailBytes)
                        $encoding=[Text.Encoding]::UTF8
                        if($stream.Length -ge 2){
                            $first=$stream.ReadByte();$second=$stream.ReadByte()
                            if($first -eq 255 -and $second -eq 254){$encoding=[Text.Encoding]::Unicode;$take-=$take%2}
                        }
                        [void]$stream.Seek(-$take,[IO.SeekOrigin]::End)
                        $buffer=New-Object byte[] $take
                        $offset=0
                        while($offset -lt $take){$read=$stream.Read($buffer,$offset,$take-$offset);if($read -eq 0){break};$offset+=$read}
                        $text=$encoding.GetString($buffer,0,$offset)
                    }finally{if($null -ne $stream){$stream.Dispose()}}
                }
                $data.Log=[pscustomobject]@{Path=$path;State=$state.State;Tail=$text;Error=$state.Error}
                if($state.State -eq 'UNKNOWN'){throw $state.Error}
            }
        }
        $checks.Add([pscustomobject]@{Section=$section;Result='READ';Error=''})
    }catch{
        if($section -eq 'Events' -and $_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*'){
            $data.Events=@();$checks.Add([pscustomobject]@{Section=$section;Result='EMPTY';Error=''})
        }else{$checks.Add([pscustomobject]@{Section=$section;Result='UNKNOWN';Error=$_.Exception.Message})}
    }
}
$report=[ordered]@{Kind='GephTunDiagnostics';CapturedUtc=[DateTime]::UtcNow.ToString('o');Result=$(if(@($checks|Where-Object{$_.Result -eq 'UNKNOWN'}).Count){'PARTIAL'}else{'COMPLETE'});Checks=$checks.ToArray();Data=$data;Scope='Read-only observations; no networking changes or qualification claim.'}
Write-DiagnosticResult $report $ResultJson
