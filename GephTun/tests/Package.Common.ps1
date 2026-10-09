# Shared read-only release checks. This file does not load the network controller.
Set-StrictMode -Version 2.0

function Get-GephPackageFullPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'A nonempty filesystem path is required.' }
    # Resolve relative paths against PowerShell's current location. .NET's
    # process working directory is not updated by Set-Location.
    $full = [IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path))
    $volume = [IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $volume.Length) { $full = $full.TrimEnd([char[]]@('\','/')) }
    return $full
}

function Test-GephPackageWithin([string]$Path, [string]$Root) {
    if ($Path.Equals($Root, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    $prefix = $Root.TrimEnd([char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar
    return $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Get-GephPackageRawAttributes([string]$Path) {
    # Query the filesystem directly. The PowerShell provider can cache invalid
    # FileInfo attributes while another process atomically replaces a file.
    return [IO.File]::GetAttributes($Path)
}

function Get-GephPackageAttributes([string]$Path, [switch]$AllowMissing) {
    # 1.3.8 harness repair (D-006): Windows PowerShell 5.1 typed catch matching
    # classifies a plain [IO.IOException]::new() instance by its generic HResult,
    # sending it into the FileNotFoundException/DirectoryNotFoundException
    # clauses (both IOException subclasses). With -AllowMissing that silently
    # turned sustained IO failure into "absent". Classify with explicit -is
    # checks - real type inheritance - so a sustained IO failure keeps its
    # original exception and never becomes absence.
    for ($attempt = 0; $attempt -lt 4; $attempt++) {
        try { return Get-GephPackageRawAttributes $Path }
        catch {
            # Native .NET failures cross as MethodInvocationException with the
            # real cause inside; script-thrown instances arrive as themselves.
            # Classify on the base exception and rethrow the original record.
            $kind = $_.Exception.GetBaseException()
            if ($kind -is [IO.FileNotFoundException] -or $kind -is [IO.DirectoryNotFoundException]) {
                if ($attempt -eq 3) { if ($AllowMissing) { return $null }; throw }
            }
            elseif ($kind -is [IO.IOException]) {
                # A sharing or replacement race may settle; a sustained IO failure
                # must retain its original exception and must never mean absent.
                if ($attempt -eq 3) { throw }
            }
            else { throw }
        }
        # Access denial and every other unexpected exception propagate directly.
        [Threading.Thread]::Sleep(40)
    }
}

function Assert-GephPackageNoRedirect([string]$Path) {
    $cursor = Get-GephPackageFullPath $Path
    while ($cursor) {
        $attributes = Get-GephPackageAttributes $cursor -AllowMissing
        # Any real raw reparse flag refuses the path immediately. A subsequent
        # missing/error observation must not erase a redirection already seen.
        if ($null -ne $attributes -and ($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('Redirected filesystem path is not supported: ' + $cursor)
        }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function Assert-GephPackageRelative([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Contains('\') -or $Path.StartsWith('/') -or
        $Path -match '[<>:"|?*\x00-\x1f\x7f]' -or
        @($Path.Split('/') | Where-Object {
            $_ -in @('', '.', '..') -or $_ -match '[. ]$' -or
            $_ -match '^(CON|PRN|AUX|NUL|COM[1-9\u00B9\u00B2\u00B3]|LPT[1-9\u00B9\u00B2\u00B3])($|\.)'
        }).Count -gt 0) { throw ('Unsafe package path: ' + $Path) }
}

function Test-GephPackageSource([string]$Path) {
    return [IO.Path]::GetExtension($Path) -in @('.ps1','.psm1','.cs','.py','.cmd') -or $Path -in @('RELEASE.json','DEPENDENCIES.json')
}

function Get-GephPackageInventory([string]$Root, [switch]$SourceTree) {
    Assert-GephPackageNoRedirect $Root
    if (-not [IO.Directory]::Exists($Root)) { throw ('Package directory is missing: ' + $Root) }
    if ($Root -eq [IO.Path]::GetPathRoot($Root)) { throw 'A filesystem root cannot be used as a package directory.' }
    $files = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $entries = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $queue = New-Object 'Collections.Generic.Queue[string]'
    $queue.Enqueue($Root)
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        if (((Get-GephPackageAttributes $directory) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Redirected package directory is not supported.' }
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -Force)) {
            $attributes = Get-GephPackageAttributes $item.FullName
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw ('Redirected package entry: ' + $item.Name) }
            $relative = $item.FullName.Substring($Root.Length + 1).Replace('\','/')
            # Source checkout metadata is never part of a delivery. This is an
            # explicit caller choice; strict package verification still sees
            # every entry and rejects unlisted files, including Git metadata.
            if ($SourceTree -and $relative -cin @('.git','.gitignore','.gitattributes','AGENTS.md')) { continue }
            Assert-GephPackageRelative $relative
            if (-not $entries.Add($relative)) { throw ('Duplicate package path: ' + $relative) }
            if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { $queue.Enqueue($item.FullName); continue }
            $files.Add($relative, $item)
        }
    }
    # Do not enumerate DictionaryEntry objects on return.
    return ,$files
}

function Get-GephPackageProperty($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-GephPackageProperty($Object, [string]$Name) {
    return $null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]
}

function Assert-GephPackageArray($Object, [string]$Name) {
    if (-not (Test-GephPackageProperty $Object $Name) -or $Object.PSObject.Properties[$Name].Value -isnot [Array]) {
        throw ('An explicit JSON array is required: ' + $Name)
    }
}

function Get-GephPackageSupplementalMap($Files) {
    $mapping = [ordered]@{}
    if ($Files.ContainsKey('tests/Acceptance.Tests.ps1') -or $Files.ContainsKey('tests/Collect-WindowsAcceptance.ps1') -or
        $Files.ContainsKey('tests/acceptance-results.json')) { $mapping.Acceptance = 'tests/acceptance-results.json' }
    if ($Files.ContainsKey('tools/diagnostics/Diagnostics.Common.ps1') -or $Files.ContainsKey('tests/Diagnostics.Tests.ps1') -or
        $Files.ContainsKey('tests/diagnostic-results.json')) { $mapping.Diagnostics = 'tests/diagnostic-results.json' }
    return ,$mapping
}

function Get-GephPackageTotals($Suites) {
    $totals = [ordered]@{ Total = [long]0; Passed = [long]0; Failed = [long]0; Skipped = [long]0 }
    foreach ($suite in @($Suites)) {
        if ($null -eq $suite) { continue }
        foreach ($key in @('Total','Passed','Failed','Skipped')) {
            Assert-GephPackageCount $suite.$key ('Totals ' + $key)
            $sum = [decimal]$totals[$key] + [decimal]$suite.$key
            if ($sum -gt [long]::MaxValue) { throw 'Validation totals overflow.' }
            $totals[$key] = [long]$sum
        }
    }
    return [pscustomobject]$totals
}

function Assert-GephPackageCapabilityCases($Records, [string[]]$Names, [bool]$Executed, [string]$Capability) {
    foreach ($name in $Names) {
        if (-not $Records.ContainsKey($name)) { throw ($Capability + ' case omitted from test records: ' + $name) }
        $result = Get-GephPackageProperty $Records[$name] 'Result'
        $passed = Get-GephPackageProperty $Records[$name] 'Passed'
        if ($Executed) {
            if ($result -cne 'PASS' -and -not ($null -eq $result -and $passed -is [bool] -and $passed)) {
                throw ($Capability + ' executed flag disagrees with its test records: ' + $name)
            }
        } elseif ($result -cnotin @('SKIP','NOT_RUN','BLOCKED_BY_HOST','UNSUPPORTED')) {
            throw ($Capability + ' unexecuted cases must appear as skipped test records: ' + $name)
        }
    }
}

function Assert-GephPackageCount($Value, [string]$Name, [long]$Minimum = 0) {
    if ($Value -isnot [byte] -and $Value -isnot [int16] -and $Value -isnot [int32] -and $Value -isnot [int64]) { throw ('Invalid integer count: ' + $Name) }
    if ([long]$Value -lt $Minimum) { throw ('Invalid integer count: ' + $Name) }
}

function Assert-GephPackageHash($Value, [string]$Name) {
    if ($Value -isnot [string] -or $Value -notmatch '\A[0-9a-fA-F]{64}\z') { throw ('Invalid SHA256: ' + $Name) }
}

function Assert-GephPackageRelease($Release) {
    if ($Release.Package -cne 'GephTun' -or $Release.Version -isnot [string] -or
        $Release.Version -cnotmatch '\A[0-9]+\.[0-9]+\.[0-9]+\z') { throw 'Invalid release identity.' }
    # Release data becomes an archive filename and ZIP timestamps; reject invalid
    # values before creating the output directory or copying any source file.
    $date = [DateTime]::MinValue
    if ($Release.Date -isnot [string] -or -not [DateTime]::TryParseExact($Release.Date, 'yyyy-MM-dd',
        [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$date) -or
        $date.Year -lt 1980 -or $date.Year -gt 2107) { throw 'Invalid release date for ZIP format.' }
    if ($Release.Status -isnot [string] -or [string]::IsNullOrWhiteSpace($Release.Status)) { throw 'A release status is required.' }
    Assert-GephPackageHash $Release.InputArchiveSha256 'InputArchiveSha256'
}

function Assert-GephPackageHashMatches([string]$Relative, $Hash, $Files) {
    Assert-GephPackageRelative $Relative
    Assert-GephPackageHash $Hash $Relative
    if (-not $Files.ContainsKey($Relative)) { throw ('Missing validated source: ' + $Relative) }
    if ((Get-FileHash -LiteralPath $Files[$Relative].FullName -Algorithm SHA256).Hash -ne $Hash) { throw ('Source changed since validation: ' + $Relative) }
}

function Assert-GephPackageCaseCoverage($Report, $Reference, [string]$Name) {
    # Source hashes identify code, not which cases a new execution actually
    # reported. An otherwise all-pass one-case report must not stand in for the
    # complete canonical suite. Skips keep their identities and remain explicit.
    $expected = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $actual = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($pair in @(@{Report=$Reference;Set=$expected},@{Report=$Report;Set=$actual})) {
        Assert-GephPackageArray $pair.Report 'Tests'
        foreach ($test in $pair.Report.Tests) {
            $identity = $null
            foreach ($field in @('Test','Name','File')) {
                $candidate = Get-GephPackageProperty $test $field
                if ($null -ne $candidate) { $identity=$candidate;break }
            }
            if ($identity -isnot [string] -or [string]::IsNullOrWhiteSpace($identity) -or -not $pair.Set.Add($identity)) {
                throw ('Missing or duplicate suite test identity: ' + $Name)
            }
        }
    }
    if ($expected.Count -eq 0 -or -not $expected.SetEquals($actual)) { throw ('Suite report does not cover the exact packaged test cases: ' + $Name) }
}

function Assert-GephPackageDesktopCoverage($Report) {
    # Keep this acceptance contract explicit when changing the native matrix.
    # Counts alone must not let a truncated single-layout run report completion.
    $matrix = Get-GephPackageProperty $Report 'LayoutMatrix'
    if ($null -eq $matrix) { throw 'Desktop result is missing its layout matrix.' }
    Assert-GephPackageArray $matrix 'FontSizeFactors'
    Assert-GephPackageArray $matrix 'Widths'
    if (($matrix.FontSizeFactors -join ',') -cne '1,1.5,2' -or ($matrix.Widths -join ',') -cne '940,640' -or
        (Get-GephPackageProperty $matrix 'MessageCases') -ne 5) { throw 'Desktop result does not cover the complete expected layout matrix.' }
    foreach ($field in @('ExpectedLayoutScenarios','LayoutScenarios')) {
        $value=Get-GephPackageProperty $Report $field
        Assert-GephPackageCount $value ('Desktop ' + $field)
        if ($value -ne 30) { throw 'Desktop result does not complete all 30 expected layout scenarios.' }
    }
}

function Get-GephPackageSuiteSummary($Report, [string]$Name) {
    $passed = Get-GephPackageProperty $Report 'Passed'
    $failed = Get-GephPackageProperty $Report 'Failed'
    $skipped = Get-GephPackageProperty $Report 'Skipped'
    if (-not (Test-GephPackageProperty $Report 'Skipped')) { $skipped = 0 }
    Assert-GephPackageCount $passed ($Name + ' report Passed')
    Assert-GephPackageCount $failed ($Name + ' report Failed')
    Assert-GephPackageCount $skipped ($Name + ' report Skipped')
    # Decimal addition avoids Int64 overflow before comparing malformed counters.
    $sum = [decimal]$passed + [decimal]$failed + [decimal]$skipped
    if ($sum -gt [long]::MaxValue) { throw ('Suite report counts overflow: ' + $Name) }
    $total = Get-GephPackageProperty $Report 'Total'
    if (-not (Test-GephPackageProperty $Report 'Total')) { $total = [long]$sum }
    Assert-GephPackageCount $total ($Name + ' report Total') 1
    if ($sum -ne $total) { throw ('Suite report counts disagree: ' + $Name) }
    Assert-GephPackageArray $Report 'Tests'
    $tests = @($Report.Tests)
    if ($tests.Count -ne $total) { throw ('Suite test records disagree: ' + $Name) }
    $identities = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $records = New-Object 'Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $actualPassed = 0; $actualFailed = 0; $actualSkipped = 0
    foreach ($test in $tests) {
        $identity = $null
        foreach ($field in @('Test','Name','File')) {
            $candidate = Get-GephPackageProperty $test $field
            if ($null -ne $candidate) { $identity = $candidate; break }
        }
        if ($identity -isnot [string] -or [string]::IsNullOrWhiteSpace($identity) -or -not $identities.Add($identity)) {
            throw ('Missing or duplicate suite test identity: ' + $Name)
        }
        $records.Add($identity, $test)
        $success = Get-GephPackageProperty $test 'Passed'
        $result = Get-GephPackageProperty $test 'Result'
        if ((Test-GephPackageProperty $test 'Passed') -and $success -isnot [bool]) { throw ('Unsuccessful test record: ' + $Name) }
        if ((Test-GephPackageProperty $test 'Result') -and ($result -isnot [string] -or $result -cnotin @('PASS','FAIL','SKIP','NOT_RUN','BLOCKED_BY_HOST','UNSUPPORTED'))) {
            throw ('Unsuccessful test record: ' + $Name)
        }
        if ($null -eq $success -and $null -eq $result) { throw ('Unsuccessful test record: ' + $Name) }
        if ($result -cin @('SKIP','NOT_RUN','BLOCKED_BY_HOST','UNSUPPORTED')) {
            if ($null -ne $success -and $success) { throw ('Skipped test cannot also pass: ' + $Name) }
            $reason = Get-GephPackageProperty $test 'Detail'
            if ([string]::IsNullOrWhiteSpace([string]$reason)) { $reason = Get-GephPackageProperty $test 'Reason' }
            if ($reason -isnot [string] -or [string]::IsNullOrWhiteSpace($reason)) { throw ('Skipped test requires a reason: ' + $Name) }
            $actualSkipped++
        } elseif ($result -ceq 'FAIL' -or ($null -ne $success -and -not $success)) {
            # Conflicting success fields never hide a failed test.
            if ($result -ceq 'PASS' -or ($null -ne $success -and $success)) { throw ('Unsuccessful test record: ' + $Name) }
            $actualFailed++
        } else { $actualPassed++ }
    }
    if ($actualPassed -ne $passed -or $actualFailed -ne $failed -or $actualSkipped -ne $skipped) {
        throw ('Unsuccessful test record or suite report counts disagree: ' + $Name)
    }
    $linkExecuted = Get-GephPackageProperty $Report 'SymbolicLinkCasesExecuted'
    if ($null -ne $linkExecuted -and ($linkExecuted -isnot [bool] -or (-not $linkExecuted -and $skipped -eq 0))) {
        throw 'Unexecuted symbolic-link cases must appear as skipped test records.'
    }
    if ($Name -eq 'Package') {
        if ($linkExecuted -isnot [bool]) { throw 'Package suite must declare symbolic-link execution status.' }
        Assert-GephPackageCapabilityCases $records @('Build rejects a redirected output ancestor into the source','Package verifier rejects redirected source ancestors','Verifier rejects redirected package entries','Source validator rejects redirected result ancestors') $linkExecuted 'Symbolic-link'
    }
    if ($Name -eq 'Network') {
        $tlsExecuted = Get-GephPackageProperty $Report 'tlsTrustCases'
        if ($tlsExecuted -isnot [bool]) { throw 'Network suite must declare TLS execution status.' }
        $tlsTrustNames = @('TLS trusted','TLS untrusted','TLS wrong_hostname')
        $tlsNames = @($tlsTrustNames) + @('bounded timeout hang_tls')
        Assert-GephPackageArray $Report 'declaredTlsCases'
        $declared = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($item in $Report.declaredTlsCases) {
            if ($item -isnot [string] -or $item -cnotin $tlsNames -or -not $declared.Add($item)) { throw 'Invalid or duplicate declared TLS case.' }
        }
        if ($declared.Count -ne $tlsNames.Count) { throw 'Network suite must declare its complete TLS case set.' }
        Assert-GephPackageCapabilityCases $records $tlsTrustNames $tlsExecuted 'TLS'
        $timeoutExecuted = Get-GephPackageProperty $Report 'tlsTimeoutCaseExecuted'
        if ($timeoutExecuted -isnot [bool] -or -not $timeoutExecuted) { throw 'TLS timeout must execute independently of certificate trust fixture availability.' }
        Assert-GephPackageCapabilityCases $records @('bounded timeout hang_tls') $true 'TLS timeout'
    }
    if (Test-GephPackageProperty $Report 'CoverageComplete') {
        if ($Report.CoverageComplete -isnot [bool] -or $Report.CoverageComplete -ne ($skipped -eq 0)) { throw ('Suite coverage flag disagrees with skipped tests: ' + $Name) }
    }
    if (Test-GephPackageProperty $Report 'Success') {
        if ($Report.Success -isnot [bool] -or $Report.Success -ne ($failed -eq 0)) { throw ('Suite success flag disagrees with failed tests: ' + $Name) }
    }
    if (Test-GephPackageProperty $Report 'NativeWindowsAcceptance') {
        if ($Report.NativeWindowsAcceptance -isnot [string] -or $Report.NativeWindowsAcceptance -cnotin @('NOT RUN','NOT_RUN')) {
            throw ('Portable suite cannot assert native Windows acceptance: ' + $Name)
        }
    }
    return [pscustomobject]@{ Total = [long]$total; Passed = [long]$passed; Failed = [long]$failed; Skipped = [long]$skipped }
}

function Assert-GephPackageValidation([string]$Root, [string]$Version, $Files, $EvidenceObject = $null) {
    $path = 'tests/current-validation.json'
    if ($null -eq $EvidenceObject) {
        if (-not $Files.ContainsKey($path)) { throw 'Successful current validation evidence is required.' }
        $evidence = Get-Content -LiteralPath $Files[$path].FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    } else { $evidence = $EvidenceObject }
    foreach ($arrayName in @('Sources','Suites','SupplementalSuites')) { Assert-GephPackageArray $evidence $arrayName }
    if ($evidence.Success -isnot [bool] -or -not $evidence.Success -or $evidence.Version -ne $Version -or
        $evidence.NativeWindowsAcceptance -cne 'NOT RUN' -or [string]::IsNullOrWhiteSpace([string]$evidence.Platform)) {
        throw 'Successful current validation evidence with the correct version and honest native status is required.'
    }
    $captured = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse([string]$evidence.CapturedUtc, [ref]$captured)) { throw 'Invalid validation capture date.' }
    $sources = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in @($evidence.Sources)) {
        $relative = [string]$entry.Path
        Assert-GephPackageRelative $relative
        if (-not (Test-GephPackageSource $relative) -or -not $sources.Add($relative)) { throw ('Unexpected or duplicate evidence source: ' + $relative) }
        Assert-GephPackageHashMatches $relative $entry.Sha256 $Files
    }
    $actualSources = @($Files.Keys | Where-Object { Test-GephPackageSource $_ })
    if ($actualSources.Count -ne $sources.Count) { throw 'Validation evidence does not cover the exact current source set.' }
    foreach ($relative in $actualSources) {
        if (-not $sources.Contains($relative)) { throw ('Source absent from validation: ' + $relative) }
    }
    $requiredMap = [ordered]@{
        Controller='tests/controller-results.json'; Network='tests/proxy-helper-results.json'
        UI='tests/ui-results.json'; Source='tests/parser-compile-results.json'; Package='tests/package-results.json'
    }
    $required = @($requiredMap.Keys)
    $supplementalMap = Get-GephPackageSupplementalMap $Files
    foreach ($suite in $evidence.Suites) {
        if ($suite.Name -notin $required) { throw 'Unexpected required validation suite.' }
        Assert-GephPackageRelative ([string]$suite.Path)
        if ($suite.Path -cne $requiredMap[$suite.Name]) { throw 'Invalid required suite report path.' }
    }
    foreach ($suite in $evidence.SupplementalSuites) {
        if ($suite.Name -notin @($supplementalMap.Keys)) { throw 'Unexpected supplemental validation suite.' }
        if ($suite.Path -cne $supplementalMap[$suite.Name]) { throw 'Invalid supplemental report path.' }
    }
    $names = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $reportPaths = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    [long]$allSkipped = 0
    $allSuites = @($evidence.Suites) + @($evidence.SupplementalSuites)
    foreach ($suite in $allSuites) {
        if (-not $names.Add([string]$suite.Name)) { throw 'Unexpected or duplicate validation suite.' }
        $relative = [string]$suite.Path
        Assert-GephPackageRelative $relative
        if (-not $relative.StartsWith('tests/', [StringComparison]::OrdinalIgnoreCase) -or
            $relative -eq $path -or [IO.Path]::GetExtension($relative) -ne '.json' -or -not $reportPaths.Add($relative)) { throw 'Invalid or duplicate suite report path.' }
        Assert-GephPackageHashMatches $relative $suite.Sha256 $Files
        foreach ($countName in @('Total','Passed','Failed','Skipped')) { Assert-GephPackageCount $suite.$countName ($suite.Name + '.' + $countName) }
        if ($suite.Total -le 0 -or $suite.Passed -le 0 -or ([decimal]$suite.Passed + [decimal]$suite.Skipped) -ne $suite.Total -or $suite.Failed -ne 0 -or
            [string]::IsNullOrWhiteSpace([string]$suite.Scope)) { throw ('Unsuccessful validation suite: ' + $suite.Name) }
        $report = Get-Content -LiteralPath $Files[$relative].FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($suite.Name -eq 'Network' -and ((Get-GephPackageProperty $report 'complete') -isnot [bool] -or -not $report.complete)) { throw 'Network suite must report complete=true.' }
        $summary = Get-GephPackageSuiteSummary $report ([string]$suite.Name)
        foreach ($countName in @('Total','Passed','Failed','Skipped')) {
            if ($summary.$countName -ne $suite.$countName) { throw ('Suite report counts disagree: ' + $suite.Name) }
        }
        $allSkipped += $summary.Skipped
        $tests = @(Get-GephPackageProperty $report 'Tests')
        # Report-embedded source hashes bind the suite to the code it actually read.
        Assert-GephPackageArray $report 'Sources'
        $reportSources = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in @(Get-GephPackageProperty $report 'Sources')) {
            if ($null -eq $entry) { continue }
            if (-not (Test-GephPackageSource ([string]$entry.Path)) -or -not $reportSources.Add([string]$entry.Path)) { throw 'Unexpected or duplicate report source path.' }
            Assert-GephPackageHashMatches ([string]$entry.Path) $entry.Sha256 $Files
        }
        $expectedReportSources = @()
        if ($suite.Name -eq 'Controller') { $expectedReportSources = @('GephTun.Core.psm1','GephTun-BootReconcile.ps1','tests/Controller.Tests.ps1','tests/BootRecovery.Tests.ps1') }
        if ($suite.Name -eq 'Network') { $expectedReportSources = @('GephTun.Network.cs','tests/proxy-helper-tests.py','tests/proxy-helper-driver.ps1') }
        if ($suite.Name -eq 'UI') { $expectedReportSources = @('GephTun.UI.ps1','GephTun.Worker.ps1','GephTun.WorkerHost.ps1','Launch-GephTun.ps1','Launch-GephTun.cmd','Start-GephTun.cmd','Stop-GephTun.cmd','tests/UI.Tests.ps1','tests/tray-harness.ps1') }
        if ($suite.Name -eq 'Package') { $expectedReportSources = @('Verify-GephTun.ps1','tests/Package.Common.ps1','tests/build-package.ps1','tests/Validate-Source.ps1','tests/Collect-Validation.ps1','tests/Package.Tests.ps1','tests/Verify-Runtime.ps1','tests/Run-WindowsValidation.ps1') }
        if ($suite.Name -eq 'Source') { $expectedReportSources = $actualSources }
        if ($suite.Name -eq 'Acceptance') { $expectedReportSources = @('tests/Collect-WindowsAcceptance.ps1','tests/Test-NrptConflict.ps1','tests/Acceptance.Tests.ps1','tests/Package.Common.ps1') }
        if ($suite.Name -eq 'Diagnostics') { $expectedReportSources = @('tools/diagnostics/Diagnostics.Common.ps1','tools/diagnostics/Get-GephTunDiagnostics.ps1','tools/diagnostics/Compare-GephTunFiles.ps1','tools/diagnostics/Measure-CimWorkload.ps1','tools/diagnostics/Get-GephTunCleanupState.ps1','tests/Diagnostics.Tests.ps1','tests/Measure-WindowsResources.ps1','tests/Package.Common.ps1') }
        if ($expectedReportSources.Count -gt 0) {
            if ($reportSources.Count -ne $expectedReportSources.Count) { throw ('Suite report does not bind its exact source set: ' + $suite.Name) }
            foreach ($sourcePath in $expectedReportSources) { if (-not $reportSources.Contains($sourcePath)) { throw ('Suite report source absent: ' + $sourcePath) } }
        }
        if ($suite.Name -eq 'Controller') { Assert-GephPackageHashMatches 'GephTun.Core.psm1' $report.ModuleSha256 $Files }
        if ($suite.Name -eq 'Network') {
            Assert-GephPackageHashMatches 'GephTun.Network.cs' $report.sourceSha256 $Files
            Assert-GephPackageHashMatches 'tests/proxy-helper-tests.py' $report.testScriptSha256 $Files
            Assert-GephPackageHashMatches 'tests/proxy-helper-driver.ps1' $report.driverSha256 $Files
        }
        if ($suite.Name -eq 'Source') {
            $checked = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($test in $tests) {
                $sourcePath = [string]$test.File
                if (-not $checked.Add($sourcePath)) { throw 'Duplicate parser/compile source record.' }
                Assert-GephPackageHashMatches $sourcePath $test.Sha256 $Files
            }
            $parseFiles = @($actualSources | Where-Object { [IO.Path]::GetExtension($_) -in @('.ps1','.psm1','.cs') })
            if ($checked.Count -ne $parseFiles.Count) { throw 'Parser/compile evidence does not cover the current source set.' }
            foreach ($sourcePath in $parseFiles) { if (-not $checked.Contains($sourcePath)) { throw ('Parser/compile source absent: ' + $sourcePath) } }
        }
    }
    if (@($evidence.Suites).Count -ne $required.Count) { throw 'All five current validation suites are required.' }
    if (@($evidence.SupplementalSuites).Count -ne $supplementalMap.Count) { throw 'All current supplemental validation suites are required.' }
    $expectedTotals = @{
        RequiredTotals = (Get-GephPackageTotals $evidence.Suites)
        SupplementalTotals = (Get-GephPackageTotals $evidence.SupplementalSuites)
        Totals = (Get-GephPackageTotals $allSuites)
    }
    foreach ($group in @('RequiredTotals','SupplementalTotals','Totals')) {
        $actual = Get-GephPackageProperty $evidence $group
        if ($null -eq $actual) { throw ('Missing validation totals: ' + $group) }
        foreach ($key in @('Total','Passed','Failed','Skipped')) {
            Assert-GephPackageCount (Get-GephPackageProperty $actual $key) ($group + '.' + $key)
            if ($actual.$key -ne $expectedTotals[$group].$key) { throw ('Validation totals disagree: ' + $group + '.' + $key) }
        }
    }
    Assert-GephPackageCount $evidence.Skipped 'Evidence Skipped'
    if ($evidence.Skipped -ne $allSkipped -or $evidence.CoverageComplete -isnot [bool] -or $evidence.CoverageComplete -ne ($allSkipped -eq 0)) {
        throw 'Validation skipped count or coverage status disagrees with the suite reports.'
    }
    return $evidence
}

function Assert-GephPackageQualification([string]$Root, $Release, $Files, $Validation) {
    # Qualification depends on the collected report. Check it only at final
    # verification/build time, never while collecting the report it references.
    if (-not $Files.ContainsKey('QUALIFICATION.json')) { throw 'QUALIFICATION.json is required; native acceptance status cannot be omitted.' }
    $qualification = Get-Content -LiteralPath $Files['QUALIFICATION.json'].FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($qualification.Package -cne 'GephTun' -or $qualification.Version -cne $Release.Version -or
        $qualification.ProductionQualified -isnot [bool] -or $qualification.ProductionQualified -or
        $qualification.NativeWindowsAcceptance -isnot [string] -or
        $qualification.NativeWindowsAcceptance -cnotin @('NOT_RUN','NOT RUN')) {
        throw 'Qualification identity or native production status is inconsistent with this validation build.'
    }
    Assert-GephPackageHash $qualification.InputArchiveSha256 'Qualification InputArchiveSha256'
    if ($qualification.InputArchiveSha256 -ne $Release.InputArchiveSha256) { throw 'Qualification input archive identity disagrees with release.' }
    $expectedCounts = @{
        PortableRequiredSuitePassed = $Validation.RequiredTotals.Passed
        PortableSupplementalPassed = $Validation.SupplementalTotals.Passed
        PortableFailed = $Validation.Totals.Failed
        PortableSkipped = $Validation.Totals.Skipped
    }
    foreach ($name in $expectedCounts.Keys) {
        $value = Get-GephPackageProperty $qualification $name
        Assert-GephPackageCount $value ('Qualification ' + $name)
        if ($value -ne $expectedCounts[$name]) { throw ('Qualification totals disagree: ' + $name) }
    }
    foreach ($group in @('RequiredTotals','SupplementalTotals','Totals')) {
        $actual = Get-GephPackageProperty $qualification $group
        foreach ($name in @('Total','Passed','Failed','Skipped')) {
            $value = Get-GephPackageProperty $actual $name
            Assert-GephPackageCount $value ('Qualification ' + $group + '.' + $name)
            if ($value -ne $Validation.$group.$name) { throw ('Qualification totals disagree: ' + $group + '.' + $name) }
        }
    }
    Assert-GephPackageArray $qualification 'Sources'
    $sourceNames = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $qualification.Sources) {
        $relative = [string]$entry.Path
        if (-not (Test-GephPackageSource $relative) -or -not $sourceNames.Add($relative)) { throw 'Unexpected or duplicate qualification source.' }
        Assert-GephPackageHashMatches $relative $entry.Sha256 $Files
    }
    if ($sourceNames.Count -ne @($Validation.Sources).Count) { throw 'Qualification does not bind the exact current source set.' }
    foreach ($entry in $Validation.Sources) {
        if (-not $sourceNames.Contains([string]$entry.Path)) { throw ('Qualification source absent: ' + $entry.Path) }
    }
    Assert-GephPackageArray $qualification 'Evidence'
    $reportNames = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($entry in $qualification.Evidence) {
        $relative = [string]$entry.Path
        if ($relative -eq 'QUALIFICATION.json' -or -not $reportNames.Add($relative)) { throw 'Invalid or duplicate qualification evidence.' }
        Assert-GephPackageHashMatches $relative $entry.Sha256 $Files
    }
    foreach ($relative in (@('tests/current-validation.json') + @($Validation.SupplementalSuites | ForEach-Object { $_.Path }))) {
        if (-not $reportNames.Contains($relative)) { throw ('Qualification evidence absent: ' + $relative) }
    }
}

function Assert-GephPackageOutput([string]$Output, [string]$Source, [switch]$Directory) {
    Assert-GephPackageNoRedirect $Output
    if (Test-GephPackageWithin $Output $Source) { throw 'Output must be outside the source folder.' }
    if ($Output -eq [IO.Path]::GetPathRoot($Output)) { throw 'A filesystem root cannot be used as output.' }
    $existing = Get-Item -LiteralPath $Output -Force -ErrorAction SilentlyContinue
    if ($null -ne $existing -and (-not $Directory -or -not $existing.PSIsContainer)) { throw ('Output already exists: ' + $Output) }
}

function Write-GephPackageNewJson([string]$Path, $Value) {
    Assert-GephPackageNoRedirect $Path
    [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($Path))
    Assert-GephPackageNoRedirect $Path
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Value | ConvertTo-Json -Depth 12))
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
}
