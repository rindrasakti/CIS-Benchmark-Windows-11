<#
.SYNOPSIS
    Audit-only CIS-style benchmark checks for Windows 11.

.DESCRIPTION
    This script only reads local configuration and creates an HTML report
    containing settings that are not compliant or could not be checked.
    It does not install modules, change registry values, modify policy,
    call Intune, or alter the system.

.PARAMETER OutputPath
    Full path for the generated HTML report.

.PARAMETER OpenReport
    Opens the HTML report after generation.

.NOTES
    Run from an elevated PowerShell session for the most complete results.
    Some CIS benchmark items are organization-specific and are intentionally
    not hard-coded here, such as legal notice text and enterprise update rings.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PSScriptRoot ("CIS-Windows11-Audit-{0}.html" -f (Get-Date -Format "yyyyMMdd-HHmmss"))),
    [switch]$OpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Results = New-Object System.Collections.Generic.List[object]
$SecurityPolicy = $null
$SecurityPolicyLoaded = $false

function Convert-ToHtmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode(($Value | Out-String).Trim())
}

function Add-AuditResult {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Category,
        [string]$Expected,
        [AllowNull()][object]$Actual,
        [bool]$Compliant,
        [string]$Source,
        [string]$Recommendation,
        [string]$Status = "Checked"
    )

    $Results.Add([pscustomobject]@{
        Id             = $Id
        Title          = $Title
        Category       = $Category
        Expected       = $Expected
        Actual         = if ($null -eq $Actual) { "Not configured / unavailable" } else { [string]$Actual }
        Status         = if ($Compliant) { "Compliant" } elseif ($Status -eq "Error") { "Error" } else { "Not compliant" }
        Compliant      = $Compliant
        Source         = $Source
        Recommendation = $Recommendation
    })
}

function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    }
    catch {
        return $null
    }
}

function Test-RegistryEquals {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Category,
        [string]$Path,
        [string]$Name,
        [object[]]$ExpectedValue,
        [string]$ExpectedText,
        [string]$Recommendation
    )

    $actual = Get-RegistryValue -Path $Path -Name $Name
    $compliant = $false
    if ($null -ne $actual) {
        foreach ($expected in $ExpectedValue) {
            if ([string]$actual -eq [string]$expected) {
                $compliant = $true
                break
            }
        }
    }

    Add-AuditResult -Id $Id -Title $Title -Category $Category -Expected $ExpectedText -Actual $actual -Compliant $compliant -Source "$Path\$Name" -Recommendation $Recommendation
}

function Get-SecurityPolicy {
    if ($script:SecurityPolicyLoaded) { return $script:SecurityPolicy }

    $script:SecurityPolicyLoaded = $true
    $script:SecurityPolicy = @{}
    $tempFile = Join-Path $env:TEMP ("cis-security-policy-{0}.inf" -f ([guid]::NewGuid()))

    try {
        $null = & secedit.exe /export /cfg $tempFile 2>$null
        if (Test-Path -LiteralPath $tempFile) {
            foreach ($line in Get-Content -LiteralPath $tempFile) {
                if ($line -match "^\s*([^=]+?)\s*=\s*(.*?)\s*$") {
                    $script:SecurityPolicy[$matches[1].Trim()] = $matches[2].Trim()
                }
            }
        }
    }
    catch {
        $script:SecurityPolicy = $null
    }
    finally {
        if (Test-Path -LiteralPath $tempFile) {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    return $script:SecurityPolicy
}

function Test-SecurityPolicy {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Category,
        [string]$Name,
        [ValidateSet("Equals", "GreaterOrEqual", "LessOrEqual", "Between")]
        [string]$Operator,
        [int]$ExpectedValue,
        [int]$Minimum,
        [int]$Maximum,
        [string]$ExpectedText,
        [string]$Recommendation
    )

    $policy = Get-SecurityPolicy
    if ($null -eq $policy -or -not $policy.ContainsKey($Name)) {
        Add-AuditResult -Id $Id -Title $Title -Category $Category -Expected $ExpectedText -Actual $null -Compliant $false -Source "Local Security Policy: $Name" -Recommendation $Recommendation -Status "Error"
        return
    }

    $actual = $policy[$Name]
    $compliant = $false
    if ($actual -as [int]) {
        $number = [int]$actual
        switch ($Operator) {
            "Equals"         { $compliant = ($number -eq $ExpectedValue) }
            "GreaterOrEqual" { $compliant = ($number -ge $Minimum) }
            "LessOrEqual"    { $compliant = ($number -le $Maximum) }
            "Between"        { $compliant = ($number -ge $Minimum -and $number -le $Maximum) }
        }
    }

    Add-AuditResult -Id $Id -Title $Title -Category $Category -Expected $ExpectedText -Actual $actual -Compliant $compliant -Source "Local Security Policy: $Name" -Recommendation $Recommendation
}

function Test-FirewallProfile {
    param([string]$ProfileName)

    try {
        $profile = Get-NetFirewallProfile -Name $ProfileName -ErrorAction Stop
        Add-AuditResult -Id "FW-$ProfileName-Enabled" -Title "$ProfileName firewall profile is enabled" -Category "Firewall" -Expected "Enabled = True" -Actual $profile.Enabled -Compliant ([bool]$profile.Enabled) -Source "Get-NetFirewallProfile -Name $ProfileName" -Recommendation "Enable Windows Defender Firewall for the $ProfileName profile."
        Add-AuditResult -Id "FW-$ProfileName-Inbound" -Title "$ProfileName inbound connections are blocked by default" -Category "Firewall" -Expected "DefaultInboundAction = Block" -Actual $profile.DefaultInboundAction -Compliant ([string]$profile.DefaultInboundAction -eq "Block") -Source "Get-NetFirewallProfile -Name $ProfileName" -Recommendation "Set the default inbound action to Block for the $ProfileName firewall profile."
    }
    catch {
        Add-AuditResult -Id "FW-$ProfileName" -Title "$ProfileName firewall profile can be checked" -Category "Firewall" -Expected "Profile available" -Actual $_.Exception.Message -Compliant $false -Source "Get-NetFirewallProfile -Name $ProfileName" -Recommendation "Run this audit on Windows 11 with the NetSecurity module available." -Status "Error"
    }
}

function Test-DefenderPreference {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Name,
        [object[]]$ExpectedValue,
        [string]$ExpectedText,
        [string]$Recommendation
    )

    try {
        $preference = Get-MpPreference -ErrorAction Stop
        $actual = $preference.$Name
        $compliant = $false
        foreach ($expected in $ExpectedValue) {
            if ([string]$actual -eq [string]$expected) {
                $compliant = $true
                break
            }
        }
        Add-AuditResult -Id $Id -Title $Title -Category "Microsoft Defender" -Expected $ExpectedText -Actual $actual -Compliant $compliant -Source "Get-MpPreference.$Name" -Recommendation $Recommendation
    }
    catch {
        Add-AuditResult -Id $Id -Title $Title -Category "Microsoft Defender" -Expected $ExpectedText -Actual $_.Exception.Message -Compliant $false -Source "Get-MpPreference.$Name" -Recommendation "Run this audit on Windows 11 with Microsoft Defender cmdlets available." -Status "Error"
    }
}

function Test-ServiceState {
    param(
        [string]$Id,
        [string]$Title,
        [string]$Name,
        [string[]]$ExpectedStartType,
        [string]$ExpectedText,
        [string]$Recommendation
    )

    try {
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
        if ($null -eq $service) {
            Add-AuditResult -Id $Id -Title $Title -Category "Services" -Expected $ExpectedText -Actual "Service not found" -Compliant $true -Source "Win32_Service: $Name" -Recommendation $Recommendation
            return
        }

        $compliant = $ExpectedStartType -contains [string]$service.StartMode
        Add-AuditResult -Id $Id -Title $Title -Category "Services" -Expected $ExpectedText -Actual ("StartMode={0}; State={1}" -f $service.StartMode, $service.State) -Compliant $compliant -Source "Win32_Service: $Name" -Recommendation $Recommendation
    }
    catch {
        Add-AuditResult -Id $Id -Title $Title -Category "Services" -Expected $ExpectedText -Actual $_.Exception.Message -Compliant $false -Source "Win32_Service: $Name" -Recommendation "Verify the service manually." -Status "Error"
    }
}

function Invoke-CISWindows11Audit {
    Write-Host "Running Windows 11 CIS-style audit checks. No system settings will be changed." -ForegroundColor Cyan

    Test-SecurityPolicy -Id "1.1.1" -Title "Enforce password history" -Category "Account Policies" -Name "PasswordHistorySize" -Operator "GreaterOrEqual" -Minimum 24 -ExpectedText "24 or more passwords remembered" -Recommendation "Configure password history to 24 or more."
    Test-SecurityPolicy -Id "1.1.2" -Title "Maximum password age" -Category "Account Policies" -Name "MaximumPasswordAge" -Operator "Between" -Minimum 1 -Maximum 365 -ExpectedText "Between 1 and 365 days" -Recommendation "Configure maximum password age to 365 days or less, but not 0."
    Test-SecurityPolicy -Id "1.1.3" -Title "Minimum password age" -Category "Account Policies" -Name "MinimumPasswordAge" -Operator "GreaterOrEqual" -Minimum 1 -ExpectedText "1 or more days" -Recommendation "Configure minimum password age to at least 1 day."
    Test-SecurityPolicy -Id "1.1.4" -Title "Minimum password length" -Category "Account Policies" -Name "MinimumPasswordLength" -Operator "GreaterOrEqual" -Minimum 14 -ExpectedText "14 or more characters" -Recommendation "Configure minimum password length to 14 or more characters."
    Test-SecurityPolicy -Id "1.1.5" -Title "Password complexity" -Category "Account Policies" -Name "PasswordComplexity" -Operator "Equals" -ExpectedValue 1 -ExpectedText "Enabled" -Recommendation "Enable password complexity requirements."
    Test-SecurityPolicy -Id "1.2.1" -Title "Account lockout duration" -Category "Account Lockout Policy" -Name "LockoutDuration" -Operator "GreaterOrEqual" -Minimum 15 -ExpectedText "15 or more minutes" -Recommendation "Configure account lockout duration to 15 minutes or more."
    Test-SecurityPolicy -Id "1.2.2" -Title "Account lockout threshold" -Category "Account Lockout Policy" -Name "LockoutBadCount" -Operator "Between" -Minimum 1 -Maximum 5 -ExpectedText "1 to 5 invalid attempts" -Recommendation "Configure account lockout threshold to 5 or fewer invalid attempts, but not 0."
    Test-SecurityPolicy -Id "1.2.3" -Title "Reset account lockout counter" -Category "Account Lockout Policy" -Name "ResetLockoutCount" -Operator "GreaterOrEqual" -Minimum 15 -ExpectedText "15 or more minutes" -Recommendation "Configure reset account lockout counter after 15 minutes or more."

    $systemPolicyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Test-RegistryEquals -Id "2.3.17.1" -Title "User Account Control is enabled" -Category "Local Policies" -Path $systemPolicyPath -Name "EnableLUA" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Enable User Account Control."
    Test-RegistryEquals -Id "2.3.17.2" -Title "Admin elevation prompt uses secure consent" -Category "Local Policies" -Path $systemPolicyPath -Name "ConsentPromptBehaviorAdmin" -ExpectedValue @(2) -ExpectedText "Prompt for consent on the secure desktop (2)" -Recommendation "Configure administrator elevation prompt behavior to require secure consent."
    Test-RegistryEquals -Id "2.3.17.3" -Title "Elevation prompts use the secure desktop" -Category "Local Policies" -Path $systemPolicyPath -Name "PromptOnSecureDesktop" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Require elevation prompts on the secure desktop."
    Test-RegistryEquals -Id "2.3.17.4" -Title "Built-in Administrator account uses Admin Approval Mode" -Category "Local Policies" -Path $systemPolicyPath -Name "FilterAdministratorToken" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Enable Admin Approval Mode for the built-in Administrator account."
    Test-RegistryEquals -Id "2.3.7.1" -Title "Do not require Ctrl+Alt+Del is disabled" -Category "Local Policies" -Path $systemPolicyPath -Name "DisableCAD" -ExpectedValue @(0) -ExpectedText "Disabled (0)" -Recommendation "Require Ctrl+Alt+Del for interactive logon."

    $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    Test-RegistryEquals -Id "2.3.11.1" -Title "LAN Manager authentication level" -Category "Network Security" -Path $lsaPath -Name "LmCompatibilityLevel" -ExpectedValue @(5) -ExpectedText "Send NTLMv2 response only; refuse LM and NTLM (5)" -Recommendation "Configure LAN Manager authentication level to refuse LM and NTLM."
    Test-RegistryEquals -Id "2.3.11.2" -Title "Do not store LM hash values" -Category "Network Security" -Path $lsaPath -Name "NoLMHash" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Prevent storage of LAN Manager hash values."
    Test-RegistryEquals -Id "2.3.10.1" -Title "Anonymous enumeration of SAM accounts is restricted" -Category "Network Access" -Path $lsaPath -Name "RestrictAnonymousSAM" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Restrict anonymous enumeration of SAM accounts."
    Test-RegistryEquals -Id "2.3.10.2" -Title "Anonymous enumeration of SAM accounts and shares is restricted" -Category "Network Access" -Path $lsaPath -Name "RestrictAnonymous" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Restrict anonymous enumeration of SAM accounts and shares."
    Test-RegistryEquals -Id "2.3.10.3" -Title "Everyone permissions do not apply to anonymous users" -Category "Network Access" -Path $lsaPath -Name "EveryoneIncludesAnonymous" -ExpectedValue @(0) -ExpectedText "Disabled (0)" -Recommendation "Ensure Everyone permissions do not apply to anonymous users."
    Test-RegistryEquals -Id "2.3.1.1" -Title "Local accounts with blank passwords are limited to console logon" -Category "Accounts" -Path $lsaPath -Name "LimitBlankPasswordUse" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Limit blank-password local accounts to console logon only."

    Test-RegistryEquals -Id "18.3.3" -Title "SMBv1 server is disabled" -Category "SMB" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -ExpectedValue @(0) -ExpectedText "Disabled (0)" -Recommendation "Disable SMBv1 server support."
    Test-RegistryEquals -Id "18.3.4" -Title "Microsoft network client digitally signs communications" -Category "SMB" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "RequireSecuritySignature" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Require SMB client signing."
    Test-RegistryEquals -Id "18.3.5" -Title "Microsoft network client does not send plaintext password" -Category "SMB" -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "EnablePlainTextPassword" -ExpectedValue @(0) -ExpectedText "Disabled (0)" -Recommendation "Disable plaintext passwords for the SMB client."

    Test-RegistryEquals -Id "18.9.8.1" -Title "AutoPlay is turned off for all drives" -Category "Windows Components" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ExpectedValue @(255) -ExpectedText "All drives disabled (255)" -Recommendation "Turn off AutoPlay for all drives."
    Test-RegistryEquals -Id "18.9.8.2" -Title "AutoRun is disabled" -Category "Windows Components" -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Disable AutoRun commands."
    Test-RegistryEquals -Id "18.9.85.1" -Title "Remote Desktop connections are denied by default" -Category "Remote Desktop" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ExpectedValue @(1) -ExpectedText "Deny connections (1)" -Recommendation "Disable Remote Desktop when it is not explicitly required."
    Test-RegistryEquals -Id "18.9.85.2" -Title "Remote Desktop requires Network Level Authentication" -Category "Remote Desktop" -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Require Network Level Authentication for Remote Desktop."

    foreach ($profileName in @("Domain", "Private", "Public")) {
        Test-FirewallProfile -ProfileName $profileName
    }

    Test-DefenderPreference -Id "18.10.43.1" -Title "Defender real-time monitoring is enabled" -Name "DisableRealtimeMonitoring" -ExpectedValue @($false) -ExpectedText "False" -Recommendation "Enable Microsoft Defender real-time monitoring."
    Test-DefenderPreference -Id "18.10.43.2" -Title "Potentially unwanted app protection is enabled" -Name "PUAProtection" -ExpectedValue @(1) -ExpectedText "Enabled (1)" -Recommendation "Enable potentially unwanted app protection."
    Test-DefenderPreference -Id "18.10.43.3" -Title "Cloud-delivered protection is enabled" -Name "MAPSReporting" -ExpectedValue @(1, 2) -ExpectedText "Basic or Advanced Microsoft MAPS reporting (1 or 2)" -Recommendation "Enable Microsoft Defender cloud-delivered protection."

    Test-ServiceState -Id "5.1" -Title "Remote Registry service is disabled" -Name "RemoteRegistry" -ExpectedStartType @("Disabled") -ExpectedText "StartMode = Disabled" -Recommendation "Disable the Remote Registry service unless there is a documented operational requirement."
    Test-ServiceState -Id "5.2" -Title "SSDP Discovery service is disabled" -Name "SSDPSRV" -ExpectedStartType @("Disabled") -ExpectedText "StartMode = Disabled" -Recommendation "Disable SSDP Discovery unless it is explicitly required."
    Test-ServiceState -Id "5.3" -Title "UPnP Device Host service is disabled" -Name "upnphost" -ExpectedStartType @("Disabled") -ExpectedText "StartMode = Disabled" -Recommendation "Disable UPnP Device Host unless it is explicitly required."
}

function New-AuditHtmlReport {
    param([object[]]$AllResults, [string]$Path)

    $findings = @($AllResults | Where-Object { -not $_.Compliant })
    $checkedCount = @($AllResults).Count
    $passedCount = @($AllResults | Where-Object { $_.Compliant }).Count
    $failedCount = $findings.Count
    $generatedAt = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
    $computerName = $env:COMPUTERNAME
    $userName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    $rows = if ($failedCount -eq 0) {
        '<tr><td colspan="7" class="empty">No non-compliant settings were found by this audit set.</td></tr>'
    }
    else {
        ($findings | Sort-Object Category, Id | ForEach-Object {
            $statusClass = if ($_.Status -eq "Error") { "error" } else { "fail" }
            "<tr><td>$($_.Id)</td><td>$(Convert-ToHtmlText $_.Category)</td><td>$(Convert-ToHtmlText $_.Title)</td><td><span class=""badge $statusClass"">$(Convert-ToHtmlText $_.Status)</span></td><td>$(Convert-ToHtmlText $_.Expected)</td><td>$(Convert-ToHtmlText $_.Actual)</td><td>$(Convert-ToHtmlText $_.Recommendation)</td></tr>"
        }) -join "`n"
    }

    $html = @"
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>CIS Windows 11 Audit Report</title>
    <style>
        :root { --bg: #f6f7f9; --panel: #ffffff; --text: #17202a; --muted: #5f6b7a; --line: #d9dee7; --fail: #b42318; --error: #8a4b00; --ok: #067647; }
        * { box-sizing: border-box; }
        body { margin: 0; background: var(--bg); color: var(--text); font-family: "Segoe UI", Arial, sans-serif; font-size: 14px; line-height: 1.5; }
        header { background: #111827; color: #fff; padding: 28px 36px; }
        h1 { margin: 0 0 8px; font-size: 28px; font-weight: 650; letter-spacing: 0; }
        .meta { color: #d1d5db; display: flex; flex-wrap: wrap; gap: 16px; }
        main { padding: 28px 36px 40px; }
        .summary { display: grid; grid-template-columns: repeat(3, minmax(160px, 1fr)); gap: 14px; margin-bottom: 22px; }
        .metric { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
        .metric span { display: block; color: var(--muted); font-size: 13px; }
        .metric strong { display: block; margin-top: 4px; font-size: 26px; }
        .metric.failed strong { color: var(--fail); }
        .metric.passed strong { color: var(--ok); }
        .table-wrap { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; overflow: auto; }
        table { width: 100%; border-collapse: collapse; min-width: 1100px; }
        th, td { border-bottom: 1px solid var(--line); padding: 10px 12px; text-align: left; vertical-align: top; }
        th { background: #eef2f7; color: #344054; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
        tr:last-child td { border-bottom: 0; }
        .badge { display: inline-block; border-radius: 999px; padding: 2px 9px; color: #fff; font-size: 12px; white-space: nowrap; }
        .badge.fail { background: var(--fail); }
        .badge.error { background: var(--error); }
        .empty { color: var(--ok); font-weight: 600; padding: 22px; text-align: center; }
        .note { color: var(--muted); margin-top: 14px; max-width: 980px; }
        @media (max-width: 800px) { header, main { padding-left: 18px; padding-right: 18px; } .summary { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <header>
        <h1>CIS Windows 11 Audit Report</h1>
        <div class="meta">
            <span>Computer: $(Convert-ToHtmlText $computerName)</span>
            <span>User: $(Convert-ToHtmlText $userName)</span>
            <span>Generated: $(Convert-ToHtmlText $generatedAt)</span>
        </div>
    </header>
    <main>
        <section class="summary" aria-label="Audit summary">
            <div class="metric"><span>Total checks</span><strong>$checkedCount</strong></div>
            <div class="metric passed"><span>Compliant</span><strong>$passedCount</strong></div>
            <div class="metric failed"><span>Non-compliant or error</span><strong>$failedCount</strong></div>
        </section>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr><th>Control</th><th>Category</th><th>Setting</th><th>Status</th><th>Expected</th><th>Actual</th><th>Recommendation</th></tr>
                </thead>
                <tbody>$rows</tbody>
            </table>
        </div>
        <p class="note">This is an audit-only helper for common Windows 11 CIS benchmark-aligned checks. It reports findings only and does not change system configuration.</p>
    </main>
</body>
</html>
"@

    $directory = Split-Path -Path $Path -Parent
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
    return $findings
}

Invoke-CISWindows11Audit
$nonCompliant = New-AuditHtmlReport -AllResults $Results -Path $OutputPath

Write-Host ""
Write-Host "Audit complete. No system settings were changed." -ForegroundColor Green
Write-Host ("Total checks: {0}" -f $Results.Count)
Write-Host ("Non-compliant or error findings: {0}" -f $nonCompliant.Count)
Write-Host ("HTML report: {0}" -f $OutputPath) -ForegroundColor Cyan

if ($OpenReport) {
    Start-Process -FilePath $OutputPath
}
