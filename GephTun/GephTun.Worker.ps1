#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateSet('Check','Connect','Disconnect','Status')][string]$Action,
    [ValidateRange(0,65535)][int]$Port = 0,
    [ValidateRange(0,2147483647)][int]$OwnerProcessId = 0,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$OperationToken,
    [string]$ResultFile
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$lock = $null
$connected = $false
$failureMessage = $null
$script:ResultSent = $false
$script:ResultTargetValidated = $false
$exitCode = 0

function Get-ValidatedWorkerResultPath {
    param([string]$Root, [string]$Path)
    $directory = [IO.Path]::GetFullPath((Join-Path $Root 'results')).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $target = [IO.Path]::GetFullPath($Path)
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($target), $directory, [StringComparison]::OrdinalIgnoreCase) -or
        [IO.Path]::GetFileName($target) -notmatch '^[a-zA-Z0-9-]{1,128}\.json$') {
        throw 'Worker result files must be direct JSON children of the protected results directory.'
    }
    return $target
}

function Complete-WorkerResult($Value) {
    # A Connect result acknowledges startup once; subsequent supervision failures
    # belong in status/logs. Rewriting an already consumed result hid such errors.
    if ($script:ResultSent) { return }
    if ($ResultFile) {
        if (-not $script:ResultTargetValidated) { return }
        Write-GephTunJson $ResultFile $Value
    }
    else { $Value | ConvertTo-Json -Depth 10 }
    $script:ResultSent = $true
}

try {
    Import-Module (Join-Path $PSScriptRoot 'GephTun.Core.psm1') -Force
    Initialize-GephTunStorage
    if ($ResultFile) {
        $ResultFile = Get-ValidatedWorkerResultPath (Get-GephTunRoot) $ResultFile
        $script:ResultTargetValidated = $true
    }
    switch ($Action) {
        'Status' {
            $current = Get-GephTunStatus
            # Status is read-only; never publish an independently derived warning over live setup state.
            Complete-WorkerResult @{ Success = $true; Message = 'Status loaded.'; Details = $current }
        }
        'Check' {
            $lock = Get-GephTunLock
            if ((Get-GephTunProtectionStatus).State -eq 'Enabled') { Open-GephTunProtectionLease }
            $check = Test-GephTunPreflight $Port
            Complete-WorkerResult @{ Success = $true; Message = $check.Message; Details = @{ ProxyPort = $check.Proxy.Port; Network = $check.Network.Alias; ProxyPath = $check.Proxy.Process.Path } }
        }
        'Connect' {
            $lock = Get-GephTunLock
            Initialize-GephTunConnectionIntent -Port $Port -OwnerProcessId $OwnerProcessId -OperationToken $OperationToken
            $connectArguments = @{ Port = $Port; OwnerProcessId = $OwnerProcessId }
            if ($OperationToken) { $connectArguments.OperationToken = $OperationToken }
            $result = Start-GephTunSession @connectArguments
            $connected = $true
            Complete-WorkerResult $result
            Watch-GephTunSession
        }
        'Disconnect' {
            Request-GephTunDisconnect
            Complete-WorkerResult @{ Success = $true; Message = 'Disconnected. Session changes have been removed.' }
        }
    }
}
catch {
    $failureMessage = $_.Exception.Message
    $exitCode = 1
    try { Write-GephTunLog ($Action + ': ' + $failureMessage) } catch { }
    try { Complete-WorkerResult @{ Success = $false; Message = $failureMessage } }
    catch { Write-Error ('Could not write the worker result: ' + $_.Exception.Message) -ErrorAction Continue }
    if ($connected) {
        try { Set-GephTunStatus 'Error' $failureMessage } catch { }
    }
    Write-Error $failureMessage -ErrorAction Continue
}
finally {
    try {
        if ($Action -eq 'Connect' -and $null -ne $lock) {
            Wait-GephTunRecovery
            if ($failureMessage) {
                if (Test-Path -LiteralPath (Join-Path (Get-GephTunRoot) 'session.json') -ErrorAction Stop) {
                    Set-GephTunStatus 'RecoveryRequired' ('Connection stopped: ' + $failureMessage + ' A saved session still needs Disconnect / Recover.')
                }
                else {
                    Set-GephTunStatus 'Disconnected' ('Disconnected: ' + $failureMessage + ' No saved GephTun session remains.')
                }
            }
        }
    }
    catch {
        $exitCode = 1
        try { Write-GephTunLog ('Worker recovery: ' + $_.Exception.Message) } catch { }
        Write-Error ('Recovery needs attention: ' + $_.Exception.Message) -ErrorAction Continue
    }
    finally {
        try {
            if ($Action -eq 'Connect' -and $null -ne $lock) {
                Clear-GephTunConnectionIntent
                if (-not $failureMessage -and -not (Test-Path -LiteralPath (Join-Path (Get-GephTunRoot) 'session.json'))) {
                    Set-GephTunStatus 'Disconnected' 'Disconnected. Automatic reconnect is stopped; no saved session remains.'
                }
            }
        }
        catch {
            $exitCode = 1
            try { Set-GephTunStatus 'RecoveryRequired' ('Connection-intent cleanup needs attention: ' + $_.Exception.Message) } catch { }
            Write-Error $_ -ErrorAction Continue
        }
        finally {
            try { Close-GephTunProtectionLease }
            catch { $exitCode=1; Write-Error ('Temporary WFP permission close needs attention: '+$_.Exception.Message) -ErrorAction Continue }
            finally { if ($null -ne $lock) { Release-GephTunLock $lock } }
        }
    }
}
exit $exitCode
