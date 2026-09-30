<#
.SYNOPSIS
    Attack Hunting investigation script.

.DESCRIPTION
    On launch it ASKS (unless the answers are passed as parameters):
       - which tool the report came from (Blumira / CrowdStrike / ThreatLocker / Nessus / Barracuda / Other),
         which sets how it was detected and what the tool typically already blocked/did;
       - the raw log line/parse that TRIGGERED the alert;
       - any correlated logs (pasted, or -CorrelatedLogFiles);
       - any manual actions already taken.
    It then:
      1. Parses the pasted logs (JSON / CEF / LEEF / key=value / syslog) plus any CSV/Excel exports.
      2. Runs everything against the threat-hunting vectors: MITRE ATT&CK techniques (live from MITRE's
         CTI repo), CISA KEV, and IOC reputation (OTX / AbuseIPDB / ThreatFox when keys are set).
      3. Links related activity into attack chains (per host, ordered by kill-chain tactic).
      4. Produces a branded PDF report (TMS logo, "Prepared by <name>, Network Security Engineer") with a
         detailed, step-by-step THREAT EXPLANATION, the detection/response context, attack chains and vectors.
      5. Exports an ACTION CSV (Action_Plan.csv) where every fix has a step-by-step fix path + reference link
         and is assigned to the owner whose area it falls in:
             Devon Brown          - Network & Security Engineering (network security, all security matters,
                                     AD / NPS / enterprise identity, IOC & C2 blocking, email/web exposure)
             Steven Golden        - System Administration (endpoints, OS config, host services/tasks, endpoint patching)
             Brian Symanski       - Server & Virtualization Administration (servers, VMs, backups/recovery, file servers)
             Christian Perez-Waldo - Further intervention / major incident (ransomware, exfiltration, domain-wide
                                     credential compromise, anything needing leadership/legal)
         Re-run with -PreviousPlan to carry over owners/status and flag anything that recurred.

.PARAMETER InputPath
    Optional. One or more .csv / .xlsx / .xls files, or a folder. Can be used together with, or instead
    of, the pasted logs from the intake prompts.

.PARAMETER DetectionSource / PreDoneActions / TriggerLog / CorrelatedLogFiles / ManualActions
    Answers to the intake questions. Supply them to run unattended; omit them to be prompted.

.PARAMETER NoIntake
    Skip the interactive questions entirely (for scheduled/unattended runs).

.PARAMETER OutputDir
    Where the report and outputs are written. Default: .\AttackHunt_<timestamp>

.PARAMETER OtxApiKey / AbuseIpDbKey / ThreatFoxKey
    Optional API keys (free accounts). Can also be set via env vars:
    OTX_API_KEY, ABUSEIPDB_API_KEY, THREATFOX_API_KEY.

.PARAMETER PreviousPlan
    Remediation_Plan.csv from an earlier run. Status/Owner/Notes are carried over;
    items marked Closed that show up again are set to "Reopened".

.PARAMETER Offline
    Skip all internet lookups (uses cached MITRE data if present).

.PARAMETER AuthorName
    Name shown as the report author. Default: the display name of whoever runs the script
    (AD / Windows account full name, falling back to the username). Set the ATTACKHUNT_AUTHOR
    environment variable to fix a name permanently.

.PARAMETER AuthorTitle
    Author's title on the report. Default: Network Security Engineer.

.PARAMETER LogoPath
    Logo for the cover page and page headers (png/jpg/svg). Default: TMS_logo.png (or .jpg/.svg)
    in the same folder as this script.

.PARAMETER Organization / ReportTitle / Classification
    Branding text. Defaults: TMS / Attack Hunting Investigation Report / CONFIDENTIAL.

.PARAMETER BrowserPath
    PDF is rendered with Microsoft Edge or Chrome in headless mode (Edge ships with Windows 10/11).
    Only needed if the browser is installed in a non-standard location. wkhtmltopdf is used as a fallback.

.PARAMETER KeepHtml
    Keep the intermediate HTML report next to the PDF.

.EXAMPLE
    .\Invoke-AttackHunt.ps1 -InputPath .\siem_export.csv

.EXAMPLE
    .\Invoke-AttackHunt.ps1 -InputPath .\alerts.xlsx -AuthorName "D. Brown" -LogoPath .\TMS_logo.png

.EXAMPLE
    .\Invoke-AttackHunt.ps1 -InputPath C:\Exports\ -OtxApiKey $otx -AbuseIpDbKey $abuse -PreviousPlan .\last\Remediation_Plan.csv

.NOTES
    Works on Windows PowerShell 5.1 and PowerShell 7+.
    Excel input/output uses the ImportExcel module if installed (Install-Module ImportExcel -Scope CurrentUser);
    on Windows it falls back to Excel COM for reading. Without either, use CSV.
#>
[CmdletBinding()]
param(
    [string[]]$InputPath,                                 # optional: CSV/Excel export(s). If omitted you can paste logs in the intake prompts.
    [string]$OutputDir = (Join-Path (Get-Location) ("AttackHunt_" + (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    # --- Intake (asked interactively when not supplied on the command line)
    [ValidateSet('Blumira','CrowdStrike','ThreatLocker','Nessus','Barracuda','Other')]
    [string]$DetectionSource,                             # which tool the report came from
    [string]$PreDoneActions,                              # what the tool already did / how it was detected
    [string]$TriggerLog,                                  # the raw log line that triggered the alert
    [string[]]$CorrelatedLogFiles,                        # files holding correlated / raw logs to ingest
    [string]$ManualActions,                               # any manual response already taken
    [switch]$NoIntake,                                    # skip the interactive questions (unattended / scheduled runs)
    [string]$OtxApiKey = $env:OTX_API_KEY,
    [string]$AbuseIpDbKey = $env:ABUSEIPDB_API_KEY,
    [string]$ThreatFoxKey = $env:THREATFOX_API_KEY,
    [string]$PreviousPlan,
    [string]$CacheDir,
    [int]$MitreCacheDays = 7,
    [int]$ChainWindowMinutes = 240,
    [int]$MaxIntelLookups = 50,
    [switch]$Offline,
    # --- Report branding / authorship
    [string]$AuthorName = $env:ATTACKHUNT_AUTHOR,       # default: display name of whoever runs the script
    [string]$AuthorTitle = 'Network Security Engineer',
    [string]$Organization = 'TMS',
    [string]$LogoPath,                                   # default: TMS_logo.png/.jpg/.svg next to this script
    [string]$ReportTitle = 'Attack Hunting Investigation Report',
    [string]$Classification = 'INTERNAL',
    [string]$BrowserPath,                                # optional path to msedge.exe / chrome.exe for PDF rendering
    [switch]$KeepHtml
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

if (-not $PSBoundParameters.ContainsKey('CacheDir')) {
    $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } elseif ($env:HOME) { $env:HOME } else { [IO.Path]::GetTempPath() }
    $CacheDir = Join-Path $base 'AttackHuntCache'
}
foreach ($d in @($OutputDir, $CacheDir)) { if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null } }

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Good($msg) { Write-Host "[+] $msg" -ForegroundColor Green }
function Show-StartupBanner {
    $bar = '============================================================'
    Write-Host ''
    Write-Host $bar -ForegroundColor Cyan
    Write-Host '   TTTTTTT  M     M   SSSSS' -ForegroundColor Cyan
    Write-Host '      T     MM   MM  S     ' -ForegroundColor Cyan
    Write-Host '      T     M M M M   SSSS ' -ForegroundColor Cyan
    Write-Host '      T     M  M  M       S' -ForegroundColor Cyan
    Write-Host '      T     M     M  SSSSS ' -ForegroundColor Cyan
    Write-Host $bar -ForegroundColor Cyan
    Write-Host ''
}
function HtmlEnc($s) { if ($null -eq $s) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$s) } }

$HasImportExcel = [bool](Get-Module -ListAvailable -Name ImportExcel)

# ---------------------------------------------------------------------------
# Reference data
# ---------------------------------------------------------------------------
# Kill-chain order. Replaced at runtime by the order in MITRE's live matrix (ATT&CK v18 split
# Defense Evasion into Stealth + Defense Impairment; older names kept for older caches).
$script:TacticOrder = @('reconnaissance','resource-development','initial-access','execution','persistence',
                 'privilege-escalation','defense-evasion','stealth','defense-impairment','credential-access','discovery',
                 'lateral-movement','collection','command-and-control','exfiltration','impact')

$SeverityWeight = @{ 'Critical' = 10; 'High' = 7; 'Medium' = 4; 'Low' = 2; 'Info' = 1 }
$DueDays        = @{ 'Critical' = 1;  'High' = 3; 'Medium' = 14; 'Low' = 30 }

# Column aliases -> normalized field names
$ColumnAliases = [ordered]@{
    Timestamp   = @('timestamp','time','_time','datetime','date','eventtime','event_time','timegenerated','created','@timestamp','first_seen','detected')
    Host        = @('host','hostname','computer','computername','device','devicename','endpoint','asset','machine','src_host','workstation')
    User        = @('user','username','account','accountname','user_name','targetusername','subjectusername','userprincipalname','upn')
    SourceIP    = @('sourceip','src_ip','srcip','src','source_ip','source','ipaddress','clientip','client_ip','remoteip','callerip')
    DestIP      = @('destip','dst_ip','dstip','dst','dest','destination','destinationip','dest_ip','destination_ip','remote_address')
    DestPort    = @('destport','dst_port','dstport','dest_port','port','destinationport')
    EventID     = @('eventid','event_id','eventcode','event_code','id','signatureid','ruleid')
    AlertName   = @('alertname','alert','alert_name','title','rule','rulename','signature','name','detection','threat','message','description')
    Severity    = @('severity','priority','level','risk','risklevel','sev')
    Process     = @('process','processname','image','process_name','newprocessname','parentimage','app','application')
    CommandLine = @('commandline','command_line','cmdline','cmd','processcommandline','scriptblocktext')
    Hash        = @('hash','sha256','sha1','md5','filehash','file_hash')
    Domain      = @('domain','url','fqdn','hostname_dst','query','dns_query','queryname','remoteurl')
}

# Detection rules: event-ID and/or regex over the whole row -> ATT&CK technique
$Rules = @(
    @{ T='T1110';     N='Brute force / password spraying';     E=@(4625,4771,4776); P='failed (log[io]n|password|sign-?in)|brute.?force|password spray' }
    @{ T='T1078';     N='Valid accounts misuse';               E=@();               P='impossible travel|anomalous (log[io]n|sign-?in)|atypical travel|unfamiliar sign-?in' }
    @{ T='T1021.001'; N='Remote Desktop Protocol';             E=@();               P='logon ?type\W{0,3}10\b|\bmstsc\b|\brdp\b|(port|:)\W?3389\b' }
    @{ T='T1021.002'; N='SMB / admin shares';                  E=@(5140,5145);      P='\\(ADMIN|C|IPC)\$|\bpsexec|\bsmbexec' }
    @{ T='T1569.002'; N='Service execution';                   E=@(7045,4697);      P='psexesvc|\bsc(\.exe)?\s+(create|start)\b' }
    @{ T='T1543.003'; N='New Windows service';                 E=@(7045,4697);      P='service (was )?installed|new service' }
    @{ T='T1059.001'; N='Suspicious PowerShell';               E=@(4104);           P='powershell.*(\s-e(nc|ncodedcommand)?\s|iex\b|invoke-expression|downloadstring|frombase64string|-nop\b|bypass)' }
    @{ T='T1059.003'; N='Windows command shell';               E=@();               P='\bcmd(\.exe)?\s+/c\b' }
    @{ T='T1027';     N='Obfuscated command / payload';        E=@();               P='frombase64string|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}' }
    @{ T='T1105';     N='Ingress tool transfer';               E=@();               P='certutil.*-urlcache|bitsadmin.*/transfer|invoke-webrequest|\bwget\s+http|curl\s+.*-o\s' }
    @{ T='T1218';     N='Signed binary proxy execution';       E=@();               P='\b(rundll32|regsvr32|mshta)(\.exe)?\b|msiexec.*http' }
    @{ T='T1053.005'; N='Scheduled task';                      E=@(4698,106);       P='schtasks.*/create|register-scheduledtask' }
    @{ T='T1547.001'; N='Registry Run key persistence';        E=@();               P='currentversion\\run(once)?\b' }
    @{ T='T1136';     N='Account created';                     E=@(4720);           P='net\s+user\s+\S+.*/add|new-localuser|user account (was )?created' }
    @{ T='T1098';     N='Privileged group change';             E=@(4728,4732,4756); P='localgroup\s+administrators.*/add|added to (domain admins|administrators)' }
    @{ T='T1003.001'; N='LSASS credential dumping';            E=@();               P='mimikatz|sekurlsa|lsass.*(dump|minidump)|procdump.*lsass|comsvcs.*minidump' }
    @{ T='T1003.003'; N='NTDS.dit extraction';                 E=@();               P='ntdsutil|ntds\.dit' }
    @{ T='T1558.003'; N='Kerberoasting';                       E=@();               P='kerberoast|rubeus|invoke-kerberoast' }
    @{ T='T1070.001'; N='Event log cleared';                   E=@(1102,104);       P='wevtutil\s+cl\b|clear-eventlog|audit log (was )?cleared' }
    @{ T='T1562.001'; N='Security tooling disabled';           E=@(5001);           P='set-mppreference.*disabl|defender.*(disabled|tamper)|sc\s+stop\s+windefend|antivirus disabled' }
    @{ T='T1490';     N='Inhibit system recovery';             E=@();               P='vssadmin.*delete\s+shadows|wbadmin.*delete|bcdedit.*recoveryenabled\s+no|shadowcopy.*delete' }
    @{ T='T1486';     N='Data encrypted for impact';           E=@();               P='ransom|\.locked\b|files? encrypted|encryption of files' }
    @{ T='T1047';     N='WMI execution';                       E=@();               P='\bwmic(\.exe)?\s|win32_process|invoke-wmimethod' }
    @{ T='T1033';     N='User discovery';                      E=@();               P='\bwhoami\b|quser\b' }
    @{ T='T1087';     N='Account discovery';                   E=@();               P='net\s+(user|group)\b.*/domain|get-aduser|get-adgroupmember' }
    @{ T='T1482';     N='Domain trust discovery';              E=@();               P='nltest.*(domain_trusts|dclist)|get-adtrust' }
    @{ T='T1018';     N='Remote system discovery';             E=@();               P='net\s+view\b|\badfind\b|ping sweep' }
    @{ T='T1046';     N='Network service scanning';            E=@();               P='port ?scan|\bnmap\b|\bmasscan\b|syn scan' }
    @{ T='T1071.001'; N='C2 over web protocols';               E=@();               P='beacon(ing)?\b|cobalt ?strike|\bc2\b|command and control' }
    @{ T='T1071.004'; N='DNS tunneling / C2';                  E=@();               P='dns tunnel|dnscat|\biodine\b' }
    @{ T='T1048';     N='Exfiltration over alternate protocol';E=@();               P='exfil|\brclone\b|mega\.nz|large outbound transfer' }
    @{ T='T1566';     N='Phishing';                            E=@();               P='phish|malicious attachment|\.(docm|xlsm|iso|img|lnk|hta)\b' }
    @{ T='T1190';     N='Exploit public-facing application';   E=@();               P='sql injection|\bsqli\b|webshell|jndi:|log4j|exploit attempt|path traversal|\bcve-\d{4}-\d{4,}' }
    @{ T='T1505.003'; N='Web shell';                           E=@();               P='web ?shell|china ?chopper|cmd\.aspx' }
    @{ T='T1090.003'; N='Tor / multi-hop proxy';               E=@();               P='\btor exit\b|\.onion\b|tor network' }
    @{ T='T1068';     N='Privilege escalation exploit';        E=@();               P='printnightmare|juicypotato|printspoofer|privilege escalation exploit' }
)

# Containment / next-step playbook by tactic
$Playbook = @{
    'initial-access'       = 'Identify and close the entry point: patch or take offline the exposed service, purge phishing mail, block sender/URL.'
    'execution'            = 'Kill malicious processes; enforce PowerShell Constrained Language Mode + script block logging; enable ASR rules.'
    'persistence'          = 'Remove persistence (services, scheduled tasks, Run keys, new accounts) and confirm removal on the host.'
    'privilege-escalation' = 'Remove unauthorized privilege grants; review admin group membership; patch the escalation vector.'
    'stealth'              = 'Hunt for the hidden artifacts (masquerading binaries, proxy-executed payloads, cleared logs) and remove them.'
    'defense-impairment'   = 'Re-enable security tooling with tamper protection; confirm logs are forwarding to the SIEM again.'
    'defense-evasion'      = 'Re-enable security tooling with tamper protection; confirm logs are forwarding to the SIEM again.'
    'credential-access'    = 'Reset credentials of affected accounts; revoke sessions/tokens; if domain creds exposed, plan double krbtgt reset.'
    'discovery'            = 'Review for follow-on activity from the same host/user; restrict AD enumeration where possible.'
    'lateral-movement'     = 'Network-isolate affected hosts; block workstation-to-workstation SMB/RDP/WinRM at host and network firewalls.'
    'collection'           = 'Identify staged data and scope what was accessed.'
    'command-and-control'  = 'Block C2 IPs/domains at perimeter firewall, proxy and DNS; hunt for the same IOCs on other hosts.'
    'exfiltration'         = 'Block destinations; quantify data exposure; engage legal/privacy for notification review.'
    'impact'               = 'Invoke the incident response plan; isolate; verify offline backups before restoring.'
}

# ---------------------------------------------------------------------------
# Assignment (who each action is handed to). Each action is routed to the owner
# whose area it falls in - no tiers, just the responsible person.
# ---------------------------------------------------------------------------
$Owners = @{
    Devon     = @{ Name = 'Devon Brown';          Area = 'Network & Security Engineering' }
    Steven    = @{ Name = 'Steven Golden';         Area = 'System Administration' }
    Brian     = @{ Name = 'Brian Symanski';        Area = 'Server & Virtualization Administration' }
    Christian = @{ Name = 'Christian Perez-Waldo'; Area = 'Further Intervention / Major Incident' }
}
# Reference "who handles what" - shown in the report and used to route each action.
$AssignmentKey = [ordered]@{
    Devon = @('Network security & perimeter (firewall, IDS/IPS, VPN, proxy, DNS/DHCP)',
              'All security matters (EDR/AV policy, detection engineering, threat intel, IR coordination)',
              'Blocking IOCs, C2, malicious IPs/domains/URLs',
              'Active Directory & enterprise identity (AD, NPS/RADIUS, GPO, Kerberos, ADCS, domain trusts)',
              'Email/phishing security and web-facing exposure',
              'Emergency patching of internet-facing / actively-exploited services',
              'Business-breaking network & identity changes')
    Steven = @('Endpoint & workstation administration (OS config, hardening)',
               'Scheduled tasks, services, registry, local accounts on endpoints',
               'Application allowlisting / ASR / WDAC / AppLocker on endpoints',
               'Endpoint AV/Defender configuration and software deployment',
               'Workstation and general OS patching')
    Brian = @('Server administration (Windows/Linux server OS, roles, services)',
              'Virtualization - all VM matters (VMware / Hyper-V, hosts, snapshots)',
              'Backups, shadow copies and recovery infrastructure',
              'File servers and server-side storage',
              'Server patching and server-hosted applications')
    Christian = @('Confirmed active compromise / hands-on-keyboard intrusion',
                  'Ransomware and destructive attacks (impact)',
                  'Data exfiltration and suspected data loss',
                  'Domain-wide credential compromise (NTDS.dit, mass LSASS dumping)',
                  'Incidents needing leadership/legal or spanning multiple owners')
}
$AssignmentText = (($Owners.GetEnumerator() | ForEach-Object { $_.Value.Name }) -join ', ')

# What each detection tool is, and what it typically does BEFORE an analyst gets involved.
# The runner's own answer to "what was pre-done" is layered on top of this at runtime.
$DetectionSources = [ordered]@{
    'Blumira'     = @{ Kind = 'SIEM / detection & response';
        PreDone = 'Blumira detects and raises a finding with a guided workflow. With automated response it can isolate a host or disable an account, but it does not block by default, so most containment is analyst-driven from the finding.';
        Console = 'Blumira > Reporting > Findings'; FirstTier = 1 }
    'CrowdStrike' = @{ Kind = 'EDR (Falcon)';
        PreDone = 'Falcon usually kills and quarantines the malicious process/file automatically and can Network-Contain the host. Blocking only happens when the prevention policy is enabled - a detect-only sensor alerts without stopping the activity.';
        Console = 'Falcon > Endpoint security > Detections'; FirstTier = 2 }
    'ThreatLocker'= @{ Kind = 'Application allowlisting / ringfencing';
        PreDone = 'ThreatLocker default-denies unapproved software, so the binary was most likely blocked outright and ringfencing limited what approved apps could do. A learning/monitor policy or an existing Allow rule would have let it run.';
        Console = 'ThreatLocker > Unified Audit'; FirstTier = 2 }
    'Nessus'      = @{ Kind = 'Vulnerability scanner (Tenable)';
        PreDone = 'Nessus only identifies vulnerabilities and misconfigurations - it does NOT block anything. This is an exposure that is still open until it is patched or hardened.';
        Console = 'Tenable > Findings > Vulnerabilities'; FirstTier = 2 }
    'Barracuda'   = @{ Kind = 'Email security / WAF / firewall';
        PreDone = 'Depending on the product, Barracuda may have quarantined the email, stripped/blocked the attachment or URL, or blocked the request at the WAF/firewall. An allow-listed sender or a monitor-mode policy would have let it through.';
        Console = 'Barracuda console (Email Gateway Defense / WAF / CloudGen)'; FirstTier = 1 }
    'Other'       = @{ Kind = 'Other / manual'; PreDone = 'Not specified.'; Console = ''; FirstTier = 1 }
}

# ---------------------------------------------------------------------------
# Fix knowledge base: keyed by technique (exact, then base Txxxx). Each entry has
# the responsible tier, ordered fix steps, and authoritative reference links.
# Steps are written so a fix has a clear path, not just "harden the host".
# ---------------------------------------------------------------------------
$FixPaths = @{
    'T1190' = @{ Owner = 'Devon'; Steps = @(
        'Identify the exact public-facing service and version from the log (URL/host/port).',
        'Take it offline or put it behind the WAF in block mode while you patch.',
        'Apply the vendor patch for the exploited CVE; if none exists, apply the vendor mitigation/virtual patch.',
        'Hunt the host for web shells and new processes spawned by the web service account.',
        'Rescan with Nessus to confirm the exposure is closed.')
        Refs = @('https://attack.mitre.org/techniques/T1190/','https://www.cisa.gov/known-exploited-vulnerabilities-catalog') }
    'T1505.003' = @{ Owner = 'Devon'; Steps = @(
        'Locate and remove the web shell file identified in the log; preserve a copy for evidence first.',
        'Reset credentials used by the web application/service account.',
        'Patch the vulnerability that allowed the upload (usually T1190).',
        'Enable file-integrity monitoring on the web root and review IIS/Apache handler mappings.')
        Refs = @('https://attack.mitre.org/techniques/T1505/003/','https://www.cisa.gov/news-events/cybersecurity-advisories') }
    'T1566' = @{ Owner = 'Devon'; Steps = @(
        'Pull the message from all mailboxes (purge) using the mail platform''s search-and-delete.',
        'Block the sender, sending domain and any URLs/attachment hashes at the email gateway.',
        'Confirm whether any recipient clicked or opened the attachment; if so, treat that host as suspect.',
        'Tune the Barracuda/mail policy from monitor to block for that detection.',
        'Send a targeted awareness note to recipients.')
        Refs = @('https://attack.mitre.org/techniques/T1566/','https://www.cisa.gov/news-events/news/avoiding-social-engineering-and-phishing-attacks') }
    'T1110' = @{ Owner = 'Devon'; Steps = @(
        'Confirm whether any authentication succeeded from the source IP; if so, treat the account as compromised.',
        'Block the source IP at the firewall/VPN and enable account lockout thresholds.',
        'Require MFA on the exposed service (VPN, OWA, portal).',
        'Reset the password for any targeted account that succeeded.')
        Refs = @('https://attack.mitre.org/techniques/T1110/','https://www.cisa.gov/secure-our-world/turn-mfa') }
    'T1078' = @{ Owner = 'Devon'; Steps = @(
        'Verify the sign-in against the user (expected location/device?).',
        'If unauthorized: disable/reset the account and revoke active sessions and tokens.',
        'Enforce MFA and conditional-access location policies.',
        'Review what the account accessed during the session.')
        Refs = @('https://attack.mitre.org/techniques/T1078/') }
    'T1059.001' = @{ Owner = 'Steven'; Steps = @(
        'Capture and decode the PowerShell command (Base64/-enc) to understand intent.',
        'Kill the process and isolate the host if the command pulled or ran a payload.',
        'Enable Script Block Logging + Constrained Language Mode via GPO and turn on AMSI.',
        'Add an ASR rule to block obfuscated scripts.')
        Refs = @('https://attack.mitre.org/techniques/T1059/001/','https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_logging_windows') }
    'T1059.003' = @{ Owner = 'Steven'; Steps = @(
        'Review the full command line and parent process (a shell spawned by a web/office process is high-risk).',
        'Isolate the host and kill the process tree if it is malicious.',
        'Enable command-line auditing (4688) and ASR "block executable content from email/Office".')
        Refs = @('https://attack.mitre.org/techniques/T1059/003/') }
    'T1105' = @{ Owner = 'Devon'; Steps = @(
        'Block the download URL/IP at the firewall, proxy and DNS.',
        'Locate and quarantine the downloaded file on the host (path is in the log).',
        'Block the LOLBin abused (certutil/bitsadmin) via ASR / WDAC where feasible.',
        'Hunt for the same URL/hash across all endpoints.')
        Refs = @('https://attack.mitre.org/techniques/T1105/','https://lolbas-project.github.io/') }
    'T1218' = @{ Owner = 'Steven'; Steps = @(
        'Review the signed-binary command line (rundll32/regsvr32/mshta) and what it loaded.',
        'Isolate the host if it loaded a remote or temp payload.',
        'Deploy WDAC / AppLocker rules and ASR to constrain these LOLBins.')
        Refs = @('https://attack.mitre.org/techniques/T1218/','https://lolbas-project.github.io/') }
    'T1053.005' = @{ Owner = 'Steven'; Steps = @(
        'Inspect the scheduled task (name, trigger, action) named in the log; delete it if malicious.',
        'Check for other tasks created by the same account/time window.',
        'Restrict task creation and alert on Event ID 4698 going forward.')
        Refs = @('https://attack.mitre.org/techniques/T1053/005/') }
    'T1547.001' = @{ Owner = 'Steven'; Steps = @(
        'Remove the malicious Run/RunOnce registry value and the file it points to.',
        'Scan for other autoruns (use Autoruns/Sysinternals).',
        'Alert on new Run-key values via Sysmon config.')
        Refs = @('https://attack.mitre.org/techniques/T1547/001/') }
    'T1543.003' = @{ Owner = 'Steven'; Steps = @(
        'Stop and delete the malicious service (name in Event ID 7045); preserve the binary for evidence.',
        'Check which account created it and whether it persists after reboot.',
        'Restrict service-creation rights and alert on 7045/4697.')
        Refs = @('https://attack.mitre.org/techniques/T1543/003/') }
    'T1569.002' = @{ Owner = 'Devon'; Steps = @(
        'Confirm PsExec/service execution and the source host (lateral movement).',
        'Isolate both source and target hosts.',
        'Block workstation-to-workstation SMB (445) and restrict admin shares.')
        Refs = @('https://attack.mitre.org/techniques/T1569/002/') }
    'T1136' = @{ Owner = 'Devon'; Steps = @(
        'Verify the new account (Event 4720) was authorized; if not, disable it immediately.',
        'Review what the account was added to and what it accessed.',
        'Alert on account creation outside the provisioning process.')
        Refs = @('https://attack.mitre.org/techniques/T1136/') }
    'T1098' = @{ Owner = 'Devon'; Steps = @(
        'Review the privileged group change (4728/4732/4756); remove any unauthorized member.',
        'Confirm who made the change and whether their account is compromised.',
        'Enable alerting on changes to Domain Admins / Administrators.')
        Refs = @('https://attack.mitre.org/techniques/T1098/') }
    'T1003.001' = @{ Owner = 'Christian'; Steps = @(
        'Treat the host as fully compromised - isolate it now.',
        'Assume all credentials used on that host are exposed; force enterprise-wide reset of affected accounts.',
        'Enable Credential Guard and restrict debug/SeDebug rights.',
        'If domain credentials were exposed, plan a staged double krbtgt reset.')
        Refs = @('https://attack.mitre.org/techniques/T1003/001/','https://learn.microsoft.com/windows/security/identity-protection/credential-guard/') }
    'T1003.003' = @{ Owner = 'Christian'; Steps = @(
        'This targets the domain credential store (NTDS.dit) - treat as domain compromise.',
        'Engage incident response; isolate the domain controller involved.',
        'Plan a full domain credential reset including a double krbtgt reset.',
        'Restrict Volume Shadow Copy and ntdsutil usage on DCs.')
        Refs = @('https://attack.mitre.org/techniques/T1003/003/','https://www.cisa.gov/news-events/cybersecurity-advisories') }
    'T1558.003' = @{ Owner = 'Devon'; Steps = @(
        'Identify the targeted service account(s) and reset their passwords to long random values.',
        'Move service accounts to Group Managed Service Accounts (gMSA) where possible.',
        'Enable AES for Kerberos and alert on TGS requests with RC4 (4769).')
        Refs = @('https://attack.mitre.org/techniques/T1558/003/') }
    'T1070.001' = @{ Owner = 'Devon'; Steps = @(
        'Log clearing (1102/104) is an evasion signal - preserve remaining logs and treat the host as suspect.',
        'Confirm logs are forwarding to the SIEM so future clears do not blind you.',
        'Restrict who can clear the Security log and alert on 1102.')
        Refs = @('https://attack.mitre.org/techniques/T1070/001/') }
    'T1562.001' = @{ Owner = 'Devon'; Steps = @(
        'Re-enable the disabled security tool (Defender/AV) and turn on Tamper Protection.',
        'Investigate what ran while protection was off.',
        'Alert on Defender being disabled and lock the setting via GPO/Intune.')
        Refs = @('https://attack.mitre.org/techniques/T1562/001/','https://learn.microsoft.com/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection') }
    'T1490' = @{ Owner = 'Brian'; Steps = @(
        'Shadow-copy/backup deletion usually precedes ransomware - isolate the host now and alert IR.',
        'Verify offline/immutable backups are intact before anything else.',
        'Block vssadmin/wbadmin for non-admins and alert on shadow deletion.')
        Refs = @('https://attack.mitre.org/techniques/T1490/','https://www.cisa.gov/stopransomware') }
    'T1486' = @{ Owner = 'Christian'; Steps = @(
        'Declare a ransomware incident and invoke the IR plan; isolate affected hosts immediately.',
        'Do NOT power off - disconnect from network to preserve memory/keys.',
        'Identify patient zero and scope spread; verify backups.',
        'Engage leadership/legal per the IR plan.')
        Refs = @('https://attack.mitre.org/techniques/T1486/','https://www.cisa.gov/stopransomware') }
    'T1021.001' = @{ Owner = 'Devon'; Steps = @(
        'Confirm the RDP source and whether it is internal or external.',
        'Block RDP (3389) at the perimeter; require it only over VPN with MFA.',
        'Isolate the target if the session was unauthorized and check for follow-on activity.')
        Refs = @('https://attack.mitre.org/techniques/T1021/001/','https://www.cisa.gov/news-events/alerts/2020/09/30/cisa-and-msisac-release-joint-ransomware-guide') }
    'T1021.002' = @{ Owner = 'Devon'; Steps = @(
        'Confirm the SMB/admin-share access source and account.',
        'Isolate affected hosts and block workstation-to-workstation SMB (445).',
        'Disable unnecessary admin shares and enforce SMB signing.')
        Refs = @('https://attack.mitre.org/techniques/T1021/002/') }
    'T1071.001' = @{ Owner = 'Devon'; Steps = @(
        'Block the C2 IP/domain at the firewall, proxy and DNS.',
        'Isolate the beaconing host and identify the implant process.',
        'Hunt for the same C2 pattern across all endpoints via EDR.')
        Refs = @('https://attack.mitre.org/techniques/T1071/001/') }
    'T1071.004' = @{ Owner = 'Devon'; Steps = @(
        'Force internal clients to use approved DNS resolvers only; block direct outbound 53.',
        'Block the tunneling domain and inspect DNS for high-volume TXT/long subdomains.',
        'Isolate the host generating the tunnel.')
        Refs = @('https://attack.mitre.org/techniques/T1071/004/') }
    'T1048' = @{ Owner = 'Christian'; Steps = @(
        'Block the exfiltration destination and quantify how much data left.',
        'Identify the tool used (rclone, etc.) and remove it; isolate the host.',
        'Engage legal/privacy if regulated data may have been exposed.')
        Refs = @('https://attack.mitre.org/techniques/T1048/') }
    'T1090.003' = @{ Owner = 'Devon'; Steps = @(
        'Block Tor entry/exit nodes and .onion resolution at the perimeter.',
        'Isolate the host communicating with Tor and investigate the process.')
        Refs = @('https://attack.mitre.org/techniques/T1090/003/') }
    'T1068' = @{ Owner = 'Steven'; Steps = @(
        'Identify the exploited driver/service/CVE from the log.',
        'Patch it; if no patch, apply the vendor mitigation and restrict access.',
        'Assume local admin/SYSTEM was obtained - treat the host as compromised.')
        Refs = @('https://attack.mitre.org/techniques/T1068/') }
    'T1046' = @{ Owner = 'Devon'; Steps = @(
        'Identify the scanning host and block it if external.',
        'If internal, treat the source as compromised and investigate.',
        'Ensure network segmentation limits what a single host can reach.')
        Refs = @('https://attack.mitre.org/techniques/T1046/') }
    'T1047' = @{ Owner = 'Steven'; Steps = @(
        'Review the WMI command and its target; isolate if used for remote execution.',
        'Restrict remote WMI and alert on WmiPrvSE spawning shells.')
        Refs = @('https://attack.mitre.org/techniques/T1047/') }
    'T1018' = @{ Owner = 'Devon'; Steps = @('Correlate the discovery activity with the source host/account and look for follow-on lateral movement.') ; Refs = @('https://attack.mitre.org/techniques/T1018/') }
    'T1087' = @{ Owner = 'Devon'; Steps = @('Confirm whether the account enumeration was authorized; if not, treat the source as compromised and review for follow-on activity.') ; Refs = @('https://attack.mitre.org/techniques/T1087/') }
    'T1482' = @{ Owner = 'Devon'; Steps = @('Review the domain-trust enumeration source; watch for cross-domain movement attempts.') ; Refs = @('https://attack.mitre.org/techniques/T1482/') }
    'T1033' = @{ Owner = 'Steven'; Steps = @('Low-signal on its own; correlate with other activity from the same host to confirm hands-on-keyboard behaviour.') ; Refs = @('https://attack.mitre.org/techniques/T1033/') }
    'T1027' = @{ Owner = 'Steven'; Steps = @('Decode the obfuscated payload to determine intent; enable AMSI and script logging so future payloads are captured in clear text.') ; Refs = @('https://attack.mitre.org/techniques/T1027/') }
}

# ---------------------------------------------------------------------------
# MITRE ATT&CK (live from github.com/mitre/cti, cached)
# ---------------------------------------------------------------------------
function ConvertFrom-BigJson([string]$raw) {
    if ($PSVersionTable.PSVersion.Major -ge 6) { return ($raw | ConvertFrom-Json) }
    Add-Type -AssemblyName System.Web.Extensions
    $ser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $ser.MaxJsonLength = [int]::MaxValue
    return $ser.DeserializeObject($raw)
}
function Get-Prop($obj, $name) {
    if ($null -eq $obj) { return $null }
    if ($obj -is [System.Collections.IDictionary]) { if ($obj.Contains($name)) { return $obj[$name] } else { return $null } }
    $p = $obj.PSObject.Properties[$name]; if ($p) { return $p.Value } else { return $null }
}

function Get-MitreAttack {
    $compact = Join-Path $CacheDir 'mitre-enterprise-compact.json'
    $fresh = (Test-Path $compact) -and ((Get-Item $compact).LastWriteTime -gt (Get-Date).AddDays(-$MitreCacheDays))
    if (-not $fresh -and -not $Offline) {
        Write-Step 'Downloading MITRE ATT&CK Enterprise data (github.com/mitre/cti)...'
        $url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
        try {
            $raw = (Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 180).Content
            if ($raw -is [byte[]]) { $raw = [Text.Encoding]::UTF8.GetString($raw) }
            $bundle = ConvertFrom-BigJson $raw
            $objs = Get-Prop $bundle 'objects'
            $byStix = @{}; $mitig = @{}; $techs = @{}; $version = ''; $latest = ''; $tacticIds = @{}; $matrixRefs = @()
            foreach ($o in $objs) {
                $type = Get-Prop $o 'type'
                if ((Get-Prop $o 'revoked') -or (Get-Prop $o 'x_mitre_deprecated')) { continue }
                if ($type -eq 'x-mitre-collection') { $version = Get-Prop $o 'x_mitre_version' }
                if ($type -eq 'x-mitre-tactic') { $tacticIds[(Get-Prop $o 'id')] = Get-Prop $o 'x_mitre_shortname' }
                if ($type -eq 'x-mitre-matrix') { $matrixRefs = @(Get-Prop $o 'tactic_refs') }
                if ($type -ne 'attack-pattern' -and $type -ne 'course-of-action') { continue }
                $ref = @(Get-Prop $o 'external_references') | Where-Object { (Get-Prop $_ 'source_name') -eq 'mitre-attack' } | Select-Object -First 1
                if (-not $ref) { continue }
                $extId = Get-Prop $ref 'external_id'
                $desc = [string](Get-Prop $o 'description')
                $desc = ($desc -replace '\(Citation:[^)]*\)', '' -replace '\[([^\]]+)\]\([^)]+\)', '$1' -replace '<[^>]+>', '').Trim()
                $firstPara = ($desc -split "`n")[0]; if ($firstPara.Length -gt 400) { $firstPara = $firstPara.Substring(0, 400) + '...' }
                if ($type -eq 'attack-pattern') {
                    $tactics = @(@(Get-Prop $o 'kill_chain_phases') | Where-Object { (Get-Prop $_ 'kill_chain_name') -eq 'mitre-attack' } | ForEach-Object { Get-Prop $_ 'phase_name' })
                    $det = [string](Get-Prop $o 'x_mitre_detection')
                    $det = ($det -replace '\(Citation:[^)]*\)', '').Trim(); if ($det.Length -gt 500) { $det = $det.Substring(0, 500) + '...' }
                    $techs[$extId] = [ordered]@{ Id = $extId; Name = Get-Prop $o 'name'; Tactics = $tactics; Url = Get-Prop $ref 'url'; Description = $firstPara; Detection = $det; Mitigations = @() }
                    $byStix[(Get-Prop $o 'id')] = $extId
                    $mod = Get-Prop $o 'modified'; if ($mod -is [datetime]) { $mod = $mod.ToString('yyyy-MM-ddTHH:mm:ss') }; if ([string]$mod -gt $latest) { $latest = [string]$mod }
                } else {
                    $mitig[(Get-Prop $o 'id')] = [ordered]@{ Id = $extId; Name = Get-Prop $o 'name'; Description = $firstPara; Url = Get-Prop $ref 'url' }
                }
            }
            foreach ($o in $objs) {
                if ((Get-Prop $o 'type') -ne 'relationship' -or (Get-Prop $o 'relationship_type') -ne 'mitigates' -or (Get-Prop $o 'revoked')) { continue }
                $m = $mitig[(Get-Prop $o 'source_ref')]; $t = $byStix[(Get-Prop $o 'target_ref')]
                if ($m -and $t -and $techs.ContainsKey($t) -and $m.Id -match '^M\d{4}$') { $techs[$t].Mitigations += $m }
            }
            if (-not $version -and $latest) { $version = 'data ' + $latest.Substring(0, 10) }
            $order = @($matrixRefs | ForEach-Object { $tacticIds[$_] } | Where-Object { $_ })
            $out = [ordered]@{ Version = $version; TacticOrder = $order; Retrieved = (Get-Date).ToString('s'); Techniques = @($techs.Values) }
            $out | ConvertTo-Json -Depth 8 -Compress | Set-Content -Path $compact -Encoding UTF8
            $raw = $null; $bundle = $null; [GC]::Collect()
            Write-Good "MITRE ATT&CK ($version) loaded: $($techs.Count) techniques."
        } catch {
            Write-Warn "MITRE download/parse failed: $($_.Exception.Message)"
        }
    }
    if (-not (Test-Path $compact)) { Write-Warn 'No MITRE data available - technique names/mitigations will be limited.'; return @{ Version = 'n/a'; Lookup = @{} } }
    $data = Get-Content $compact -Raw | ConvertFrom-Json
    $lookup = @{}
    foreach ($t in $data.Techniques) { $lookup[$t.Id] = $t }
    if ($data.PSObject.Properties['TacticOrder'] -and @($data.TacticOrder).Count) {
        $extra = @($script:TacticOrder | Where-Object { @($data.TacticOrder) -notcontains $_ })
        $script:TacticOrder = @($data.TacticOrder) + $extra
    }
    if ($fresh) { Write-Good "MITRE ATT&CK ($($data.Version)) loaded from cache ($($lookup.Count) techniques)." }
    return @{ Version = $data.Version; Lookup = $lookup }
}

# ---------------------------------------------------------------------------
# Input: CSV / Excel
# ---------------------------------------------------------------------------
function Import-ExcelFile([string]$path) {
    if ($HasImportExcel) {
        Import-Module ImportExcel
        $rows = @()
        foreach ($sheet in (Get-ExcelSheetInfo -Path $path)) { $rows += @(Import-Excel -Path $path -WorksheetName $sheet.Name) }
        return $rows
    }
    if ($env:OS -eq 'Windows_NT') {
        Write-Warn 'ImportExcel module not found - using Excel COM (requires Excel installed).'
        $xl = New-Object -ComObject Excel.Application; $xl.Visible = $false; $xl.DisplayAlerts = $false
        $tmp = [IO.Path]::Combine([IO.Path]::GetTempPath(), [Guid]::NewGuid().ToString())
        $rows = @()
        try {
            $wb = $xl.Workbooks.Open((Resolve-Path $path).Path)
            $i = 0
            foreach ($ws in $wb.Worksheets) { $i++; $f = "$tmp-$i.csv"; $ws.SaveAs($f, 6); $rows += @(Import-Csv $f); Remove-Item $f -ErrorAction SilentlyContinue }
            $wb.Close($false)
        } finally { $xl.Quit(); [void][Runtime.InteropServices.Marshal]::ReleaseComObject($xl) }
        return $rows
    }
    throw "Cannot read $path - install the ImportExcel module (Install-Module ImportExcel -Scope CurrentUser) or export to CSV."
}

function Get-InputRows {
    $files = @()
    foreach ($p in @($InputPath)) {
        if (-not $p) { continue }
        if (Test-Path $p -PathType Container) { $files += Get-ChildItem $p -File | Where-Object { $_.Extension -match '^\.(csv|xlsx|xls)$' } }
        elseif (Test-Path $p) { $files += Get-Item $p }
        else { Write-Warn "Not found: $p" }
    }
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($f in $files) {
        Write-Step "Reading $($f.Name)"
        $rows = if ($f.Extension -eq '.csv') { @(Import-Csv $f.FullName) } else { @(Import-ExcelFile $f.FullName) }
        $n = 0
        foreach ($r in $rows) { $n++; $all.Add((ConvertTo-NormalizedEvent $r $f.Name $n)) }
        Write-Good "  $n rows"
    }
    return $all
}

function ConvertTo-NormalizedEvent($row, $file, $rowNum) {
    $props = @($row.PSObject.Properties | Where-Object { $_.MemberType -match 'Property' })
    $map = @{}
    foreach ($p in $props) { $map[($p.Name -replace '[\s\-\.]', '').ToLower()] = $p.Value }
    $ev = [ordered]@{ SourceFile = $file; Row = $rowNum }
    foreach ($field in $ColumnAliases.Keys) {
        $val = $null
        foreach ($a in $ColumnAliases[$field]) { $k = ($a -replace '[_\-\.@]', '').ToLower(); if ($map.ContainsKey($k) -and "$($map[$k])".Trim()) { $val = "$($map[$k])".Trim(); break } }
        $ev[$field] = $val
    }
    $dt = [datetime]::MinValue
    $ev['Time'] = if ($ev.Timestamp -and [datetime]::TryParse($ev.Timestamp, [ref]$dt)) { $dt } else { $null }
    $ev['Severity'] = Get-NormalizedSeverity $ev.Severity
    $ev['Text'] = (($props | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ' | ')
    $ev['RawLog'] = $ev.Text
    $ev['DetectionTool'] = $DetectionSource
    return [pscustomobject]$ev
}

# Parse pasted raw log line(s) into normalized events. Understands JSON, CEF, LEEF,
# key=value, and plain syslog; falls back to treating the whole line as alert text.
function ConvertFrom-RawLog([string]$raw, [string]$label, [string]$tool) {
    $events = New-Object System.Collections.Generic.List[object]
    if (-not "$raw".Trim()) { return $events }
    $n = 0
    foreach ($line in ($raw -split "`r?`n")) {
        if (-not $line.Trim()) { continue }
        $n++
        $fields = $null
        $t = $line.Trim()
        try {
            if ($t.StartsWith('{')) {
                $obj = $t | ConvertFrom-Json
                $fields = [ordered]@{}
                function Flatten($o, $prefix) {
                    foreach ($p in $o.PSObject.Properties) {
                        $key = if ($prefix) { "$prefix.$($p.Name)" } else { $p.Name }
                        if ($null -ne $p.Value -and $p.Value.PSObject -and $p.Value -isnot [string] -and $p.Value -isnot [ValueType] -and -not ($p.Value -is [Array]) -and $p.Value.PSObject.Properties.Name.Count) {
                            Flatten $p.Value $key
                        } else { $script:__ff[$key] = "$($p.Value)" }
                    }
                }
                $script:__ff = [ordered]@{}; Flatten $obj ''; $fields = $script:__ff
            } elseif ($t -match 'CEF:\d\|') {
                # CEF: header fields then key=value extension
                $ext = ($t -split 'CEF:\d\|', 2)[1]
                $parts = $ext -split '\|'
                $fields = [ordered]@{ Vendor = $parts[0]; Product = $parts[1]; AlertName = $parts[3]; Severity = $parts[5] }
                if ($parts.Count -ge 7) { foreach ($m in [regex]::Matches($parts[6..($parts.Count-1)] -join '|', '(\w+)=([^=]*?)(?=\s\w+=|$)')) { $fields[$m.Groups[1].Value] = $m.Groups[2].Value.Trim() } }
            } elseif ($t -match 'LEEF:\d') {
                $fields = [ordered]@{}
                foreach ($m in [regex]::Matches($t, '(\w+)=([^\t]*?)(?=\t\w+=|$)')) { $fields[$m.Groups[1].Value] = $m.Groups[2].Value.Trim() }
            } elseif ($t -match '\w+=') {
                $fields = [ordered]@{}
                foreach ($m in [regex]::Matches($t, '([\w\.\-]+)=("[^"]*"|\S+)')) { $fields[$m.Groups[1].Value] = $m.Groups[2].Value.Trim('"') }
            }
        } catch { $fields = $null }
        if (-not $fields -or -not $fields.Keys.Count) { $fields = [ordered]@{ message = $t } }
        # Always keep the whole original line so detection rules see the full text,
        # even when structured parsing only pulled a few fields out of a prose line.
        if (-not $fields.Contains('message')) { $fields['message'] = $t }
        $row = New-Object psobject
        foreach ($k in $fields.Keys) { $row | Add-Member -NotePropertyName $k -NotePropertyValue $fields[$k] -Force }
        $ev = ConvertTo-NormalizedEvent $row $label $n
        $ev.RawLog = $t
        if (-not $ev.DetectionTool) { $ev.DetectionTool = $tool }
        $events.Add($ev)
    }
    return $events
}

function Get-NormalizedSeverity($s) {
    if (-not $s) { return $null }
    switch -Regex ("$s".ToLower()) {
        '^(crit|p1|sev1|very high)|^(5|10|9)$' { return 'Critical' }
        '^(high|p2|sev2|major)|^(4|8|7)$'      { return 'High' }
        '^(med|moderate|p3|sev3|warn)|^(3|6|5)$' { return 'Medium' }
        '^(low|p4|sev4|minor)|^(2|1)$'         { return 'Low' }
        default                                { return 'Info' }
    }
}

# ---------------------------------------------------------------------------
# Mapping events -> ATT&CK
# ---------------------------------------------------------------------------
function Get-DefaultSeverity($tactics) {
    if ($tactics | Where-Object { $_ -in @('impact','exfiltration','credential-access') }) { return 'High' }
    if ($tactics | Where-Object { $_ -in @('lateral-movement','command-and-control','privilege-escalation','defense-evasion','defense-impairment','stealth','persistence') }) { return 'Medium' }
    return 'Low'
}

function Get-Findings($events, $mitre) {
    $findings = New-Object System.Collections.Generic.List[object]
    $i = 0
    foreach ($ev in $events) {
        $hits = @{}; $trig = @{}
        $evId = -1; [void][int]::TryParse(("$($ev.EventID)" -replace '\D', ''), [ref]$evId); if (-not "$($ev.EventID)") { $evId = -1 }
        # Explicit technique IDs already in the data (e.g. EDR/SIEM alerts)
        foreach ($m in [regex]::Matches($ev.Text, '\bT1\d{3}(?:\.\d{3})?\b')) { $hits[$m.Value] = 'Technique ID in source alert'; $trig[$m.Value] = $m.Value }
        foreach ($r in $Rules) {
            $idHit = ($evId -ge 0) -and ($r.E -contains $evId)
            $rx = [regex]::Match($ev.Text, "(?i)$($r.P)")
            if ($idHit -or $rx.Success) {
                if (-not $hits.ContainsKey($r.T)) {
                    $hits[$r.T] = $r.N
                    $trig[$r.T] = if ($rx.Success) { "log matched: '$($rx.Value)'" } elseif ($idHit) { "Event ID $evId" } else { $r.N }
                }
            }
        }
        foreach ($tid in $hits.Keys) {
            $i++
            $t = $mitre.Lookup[$tid]
            if (-not $t -and $tid -match '\.') { $t = $mitre.Lookup[($tid -split '\.')[0]] }
            $tactics = if ($t) { @($t.Tactics) } else { @() }
            $tactics = @($TacticOrder | Where-Object { $tactics -contains $_ })
            $sev = if ($ev.Severity -and $ev.Severity -ne 'Info') { $ev.Severity } else { Get-DefaultSeverity $tactics }
            $evidence = @($ev.AlertName, $ev.CommandLine, $ev.Process) | Where-Object { $_ } | Select-Object -First 2
            $evText = ($evidence -join ' :: '); if (-not $evText) { $evText = $ev.Text }
            if ($evText.Length -gt 300) { $evText = $evText.Substring(0, 300) + '...' }
            $findings.Add([pscustomobject][ordered]@{
                FindingId     = 'F{0:D4}' -f $i
                Time          = $ev.Time
                Host          = $ev.Host
                User          = $ev.User
                SourceIP      = $ev.SourceIP
                DestIP        = $ev.DestIP
                TechniqueId   = $tid
                TechniqueName = if ($t) { $t.Name } else { $hits[$tid] }
                Tactic        = if ($tactics) { $tactics[0] } else { 'unknown' }
                AllTactics    = ($tactics -join ', ')
                Severity      = $sev
                Detection     = $hits[$tid]
                Trigger       = $trig[$tid]
                RawLog        = (Short $ev.RawLog 400)
                DetectionTool = $ev.DetectionTool
                Evidence      = $evText
                Source        = "$($ev.SourceFile):$($ev.Row)"
                Url           = if ($t) { $t.Url } else { "https://attack.mitre.org/techniques/$($tid -replace '\.', '/')/" }
            })
        }
    }
    return $findings
}

# ---------------------------------------------------------------------------
# Open-source threat intel enrichment
# ---------------------------------------------------------------------------
function Test-PublicIP([string]$ip) {
    $a = $null
    if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$a)) { return $false }
    if ($a.AddressFamily -ne 'InterNetwork') { return -not ($ip -match '^(::1|fe80:|fc|fd)') }
    $b = $a.GetAddressBytes()
    if ($b[0] -eq 10 -or $b[0] -eq 127 -or $b[0] -eq 0 -or $b[0] -ge 224) { return $false }
    if ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) { return $false }
    if ($b[0] -eq 192 -and $b[1] -eq 168) { return $false }
    if ($b[0] -eq 169 -and $b[1] -eq 254) { return $false }
    if ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127) { return $false }
    return $true
}

function Get-Iocs($events) {
    $iocs = @{}
    foreach ($ev in $events) {
        foreach ($ip in @($ev.SourceIP, $ev.DestIP)) { if ($ip -and (Test-PublicIP $ip)) { $iocs["ip|$ip"] = @{ Type = 'IPv4'; Value = $ip } } }
        if ($ev.Hash -and $ev.Hash -match '^[a-fA-F0-9]{32,64}$') { $iocs["hash|$($ev.Hash)"] = @{ Type = 'FileHash'; Value = $ev.Hash.ToLower() } }
        if ($ev.Domain) {
            $d = ($ev.Domain -replace '^[a-z]+://', '' -split '[/:]')[0]
            if ($d -match '^[a-z0-9.-]+\.[a-z]{2,}$' -and -not (Test-PublicIP $d)) { $iocs["domain|$d"] = @{ Type = 'Domain'; Value = $d.ToLower() } }
        }
    }
    return @($iocs.Values)
}

function Invoke-Intel($iocs) {
    $results = New-Object System.Collections.Generic.List[object]
    if ($Offline) { return $results }
    if (-not ($OtxApiKey -or $AbuseIpDbKey -or $ThreatFoxKey)) { Write-Warn 'No intel API keys set (OTX/AbuseIPDB/ThreatFox) - IOC reputation lookups skipped. CISA KEV still checked.'; return $results }
    $count = 0
    foreach ($ioc in $iocs) {
        if ($count -ge $MaxIntelLookups) { Write-Warn "Reached MaxIntelLookups ($MaxIntelLookups)."; break }
        $count++
        $r = [ordered]@{ Type = $ioc.Type; Value = $ioc.Value; OTXPulses = $null; OTXAttackIds = ''; OTXTags = ''; AbuseScore = $null; AbuseReports = $null; Country = ''; ISP = ''; ThreatFox = ''; Verdict = 'Unknown' }
        if ($OtxApiKey) {
            $otxType = @{ IPv4 = 'IPv4'; Domain = 'domain'; FileHash = 'file' }[$ioc.Type]
            try {
                $o = Invoke-RestMethod -Uri "https://otx.alienvault.com/api/v1/indicators/$otxType/$($ioc.Value)/general" -Headers @{ 'X-OTX-API-KEY' = $OtxApiKey } -TimeoutSec 30
                $r.OTXPulses = [int]$o.pulse_info.count
                $pulses = @($o.pulse_info.pulses)
                $r.OTXAttackIds = (@($pulses | ForEach-Object { $_.attack_ids } | ForEach-Object { if ($_.id) { $_.id } else { $_ } }) | Select-Object -Unique -First 10) -join ', '
                $r.OTXTags = (@($pulses | ForEach-Object { $_.tags }) | Group-Object | Sort-Object Count -Descending | Select-Object -First 6 -ExpandProperty Name) -join ', '
            } catch { Write-Verbose "OTX $($ioc.Value): $($_.Exception.Message)" }
        }
        if ($AbuseIpDbKey -and $ioc.Type -eq 'IPv4') {
            try {
                $a = Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$($ioc.Value)&maxAgeInDays=90" -Headers @{ Key = $AbuseIpDbKey; Accept = 'application/json' } -TimeoutSec 30
                $r.AbuseScore = [int]$a.data.abuseConfidenceScore; $r.AbuseReports = [int]$a.data.totalReports
                $r.Country = $a.data.countryCode; $r.ISP = $a.data.isp
            } catch { Write-Verbose "AbuseIPDB $($ioc.Value): $($_.Exception.Message)" }
        }
        if ($ThreatFoxKey) {
            try {
                $body = @{ query = 'search_ioc'; search_term = $ioc.Value } | ConvertTo-Json
                $tf = Invoke-RestMethod -Method Post -Uri 'https://threatfox-api.abuse.ch/api/v1/' -Headers @{ 'Auth-Key' = $ThreatFoxKey } -Body $body -ContentType 'application/json' -TimeoutSec 30
                if ($tf.query_status -eq 'ok') { $r.ThreatFox = (@($tf.data | ForEach-Object { "$($_.malware_printable) ($($_.threat_type))" }) | Select-Object -Unique) -join '; ' }
            } catch { Write-Verbose "ThreatFox $($ioc.Value): $($_.Exception.Message)" }
        }
        $r.Verdict = if ($r.ThreatFox -or ($r.AbuseScore -ge 75) -or ($r.OTXPulses -ge 5)) { 'Malicious' }
                     elseif (($r.AbuseScore -ge 25) -or ($r.OTXPulses -ge 1)) { 'Suspicious' }
                     elseif ($null -ne $r.AbuseScore -or $null -ne $r.OTXPulses) { 'No hits' } else { 'Unknown' }
        $results.Add([pscustomobject]$r)
        Start-Sleep -Milliseconds 250
    }
    return $results
}

function Get-KevMatches($events) {
    $cves = @{}
    foreach ($ev in $events) { foreach ($m in [regex]::Matches($ev.Text, '(?i)\bCVE-\d{4}-\d{4,}\b')) { $cves[$m.Value.ToUpper()] = $ev.Host } }
    if (-not $cves.Count -or $Offline) { return @() }
    Write-Step "Checking $($cves.Count) CVE(s) against CISA Known Exploited Vulnerabilities..."
    try {
        $kev = Invoke-RestMethod -Uri 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json' -TimeoutSec 60
        $out = foreach ($v in $kev.vulnerabilities) {
            if ($cves.ContainsKey($v.cveID)) {
                [pscustomobject][ordered]@{ CVE = $v.cveID; Vendor = $v.vendorProject; Product = $v.product; Name = $v.vulnerabilityName
                    Ransomware = $v.knownRansomwareCampaignUse; RequiredAction = $v.requiredAction; SeenOnHost = $cves[$v.cveID] }
            }
        }
        return @($out)
    } catch { Write-Warn "CISA KEV lookup failed: $($_.Exception.Message)"; return @() }
}

# ---------------------------------------------------------------------------
# Link findings into attack chains
# ---------------------------------------------------------------------------
function Get-AttackChains($findings, $intel) {
    $bad = @{}; foreach ($i in $intel) { if ($i.Verdict -in 'Malicious', 'Suspicious') { $bad[$i.Value] = $i.Verdict } }
    $groups = $findings | Group-Object { if ($_.Host) { $_.Host } elseif ($_.SourceIP) { $_.SourceIP } elseif ($_.User) { $_.User } else { 'unattributed' } }
    $chains = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($g in $groups) {
        $sorted = @($g.Group | Sort-Object @{ Expression = { if ($_.Time) { $_.Time } else { [datetime]::MaxValue } } }, @{ Expression = { [array]::IndexOf($TacticOrder, $_.Tactic) } })
        $segments = @(); $cur = @(); $last = $null
        foreach ($f in $sorted) {
            if ($last -and $f.Time -and $last.Time -and (($f.Time - $last.Time).TotalMinutes -gt $ChainWindowMinutes)) { $segments += , $cur; $cur = @() }
            $cur += $f; $last = $f
        }
        if ($cur) { $segments += , $cur }
        foreach ($seg in $segments) {
            $n++
            $tactics = @($TacticOrder | Where-Object { $t = $_; $seg | Where-Object { $_.Tactic -eq $t } })
            $iocHits = @($seg | ForEach-Object { $_.SourceIP; $_.DestIP } | Where-Object { $_ -and $bad.ContainsKey($_) } | Select-Object -Unique)
            $score = ($seg | ForEach-Object { $SeverityWeight[$_.Severity] } | Measure-Object -Sum).Sum + (5 * $tactics.Count) + (10 * $iocHits.Count)
            $verdict = if ($tactics.Count -ge 3 -or $score -ge 40) { 'Linked attack chain' } elseif ($tactics.Count -eq 2) { 'Possible attack chain' } else { 'Isolated activity' }
            $maxSev = ($seg | Sort-Object { $SeverityWeight[$_.Severity] } -Descending | Select-Object -First 1).Severity
            $priority = if ($verdict -eq 'Linked attack chain' -and ($tactics -contains 'impact' -or $tactics -contains 'exfiltration' -or $tactics -contains 'credential-access' -or $iocHits)) { 'Critical' }
                        elseif ($verdict -eq 'Linked attack chain') { 'High' }
                        elseif ($verdict -eq 'Possible attack chain') { if ($maxSev -in 'Critical','High') { 'High' } else { 'Medium' } }
                        else { if ($maxSev -eq 'Critical') { 'High' } elseif ($maxSev -eq 'High') { 'Medium' } else { 'Low' } }
            $times = @($seg | Where-Object { $_.Time } | ForEach-Object { $_.Time })
            $chains.Add([pscustomobject][ordered]@{
                ChainId    = 'C{0:D3}' -f $n
                Entity     = $g.Name
                Start      = if ($times) { ($times | Measure-Object -Minimum).Minimum } else { $null }
                End        = if ($times) { ($times | Measure-Object -Maximum).Maximum } else { $null }
                Findings   = $seg.Count
                Tactics    = $tactics
                Flow       = ($tactics -join ' -> ')
                Techniques = (@($seg | ForEach-Object { $_.TechniqueId }) | Select-Object -Unique)
                Users      = (@($seg | ForEach-Object { $_.User } | Where-Object { $_ }) | Select-Object -Unique)
                IPs        = (@($seg | ForEach-Object { $_.SourceIP; $_.DestIP } | Where-Object { $_ }) | Select-Object -Unique)
                IntelHits  = $iocHits
                Score      = $score
                Verdict    = $verdict
                Priority   = $priority
                Related    = @()
                Items      = $seg
            })
        }
    }
    # Cross-link chains that share a user or public IP (lateral movement / same actor)
    foreach ($a in $chains) {
        foreach ($b in $chains) {
            if ($a.ChainId -eq $b.ChainId) { continue }
            $sharedU = @($a.Users | Where-Object { $b.Users -contains $_ })
            $sharedI = @($a.IPs | Where-Object { $b.IPs -contains $_ -or $b.Entity -eq $_ })
            if ($sharedU -or $sharedI -or ($a.IPs -contains $b.Entity)) { $a.Related += "$($b.ChainId) ($($b.Entity))" }
        }
    }
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    return @($chains | Sort-Object @{ Expression = { $rank[$_.Priority] } }, @{ Expression = { $_.Score }; Descending = $true })
}

# ---------------------------------------------------------------------------
# Remediation / next steps plan (closing the loop)
# ---------------------------------------------------------------------------
function New-RemediationPlan($chains, $findings, $intel, $kev, $mitre) {
    $items = New-Object System.Collections.Generic.List[object]
    $today = Get-Date
    $add = {
        param($priority, $category, $action, $scope, $tech, $ref, $tactic)
        $items.Add([pscustomobject][ordered]@{
            ItemId = ''; Priority = $priority; Owner = ''; AssignedTo = ''
            Category = $category; Technique = $tech; Tactic = $tactic; Action = $action
            FixPath = ''; FixReference = ''; Scope = $scope; Reference = $ref
            DueDate = $today.AddDays($DueDays[$priority]).ToString('yyyy-MM-dd'); Status = 'Open'; Notes = ''
        })
    }
    # 1. Containment per chain (tactic-driven, with the detailed fix path per technique)
    foreach ($c in $chains | Where-Object { $_.Verdict -ne 'Isolated activity' -or $_.Priority -in 'Critical','High' }) {
        foreach ($t in $c.Tactics) {
            if ($Playbook.ContainsKey($t)) {
                $techs = (($c.Items | Where-Object { $_.Tactic -eq $t } | ForEach-Object { $_.TechniqueId } | Select-Object -Unique) -join ', ')
                & $add $c.Priority "Containment ($t)" $Playbook[$t] "$($c.Entity) [$($c.ChainId)]" $techs 'IR playbook' $t
            }
        }
    }
    # 2. Block malicious IOCs
    foreach ($i in $intel | Where-Object { $_.Verdict -in 'Malicious', 'Suspicious' }) {
        $p = if ($i.Verdict -eq 'Malicious') { 'Critical' } else { 'High' }
        & $add $p 'Block IOC' "Block $($i.Type) $($i.Value) at firewall/proxy/DNS/EDR; search for it across all hosts." $i.Value $i.OTXAttackIds 'OTX / AbuseIPDB / ThreatFox' 'command-and-control'
    }
    # 3. Known exploited vulnerabilities
    foreach ($k in $kev) { & $add 'Critical' 'Patch (CISA KEV)' "$($k.RequiredAction) [$($k.Vendor) $($k.Product)]" $k.SeenOnHost 'T1190' "https://nvd.nist.gov/vuln/detail/$($k.CVE)" 'initial-access' }
    # 4. Hardening from MITRE mitigations, per technique observed
    foreach ($tg in $findings | Group-Object TechniqueId) {
        $sev = ($tg.Group | Sort-Object { $SeverityWeight[$_.Severity] } -Descending | Select-Object -First 1).Severity
        $p = if ($sev -in 'Critical','High') { 'Medium' } else { 'Low' }
        $t = $mitre.Lookup[$tg.Name]; if (-not $t -and $tg.Name -match '\.') { $t = $mitre.Lookup[($tg.Name -split '\.')[0]] }
        $tactic0 = $tg.Group[0].Tactic
        $hosts = (@($tg.Group | ForEach-Object { $_.Host } | Where-Object { $_ }) | Select-Object -Unique) -join ', '
        if ($t -and $t.Mitigations) {
            foreach ($m in @($t.Mitigations) | Select-Object -First 3) { & $add $p 'Harden (MITRE mitigation)' "$($m.Id) $($m.Name): $($m.Description)" $hosts $tg.Name $m.Url $tactic0 }
        }
        # 5. Detection engineering - verify / tune
        & $add $p 'Detection' "Confirm a SIEM/EDR rule covers $($tg.Name) ($($tg.Group[0].TechniqueName)) and alerts at the right severity; tune false positives." 'SIEM/EDR' $tg.Name $tg.Group[0].Url $tactic0
    }
    # 6. Close the loop
    & $add 'Medium' 'Validate' 'After remediation, re-export logs and re-run this hunt with -PreviousPlan to verify nothing recurred.' 'All' '' 'Invoke-AttackHunt.ps1' ''
    & $add 'Low' 'Lessons learned' 'Hold a post-incident review; update IR playbooks, firewall policy and detections from these findings.' 'Security team' '' 'NIST SP 800-61' ''

    # De-duplicate & number
    $plan = @($items | Group-Object { "$($_.Category)|$($_.Action)|$($_.Scope)" } | ForEach-Object { $_.Group[0] })
    $rank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
    $plan = @($plan | Sort-Object { $rank[$_.Priority] }, Category)

    # Merge with previous plan (carry owner/status; reopen recurrences)
    if ($PreviousPlan -and (Test-Path $PreviousPlan)) {
        Write-Step "Merging with previous plan $PreviousPlan"
        $prev = @{}; foreach ($p in Import-Csv $PreviousPlan) { $prev["$($p.Category)|$($p.Action)|$($p.Scope)"] = $p }
        $seen = @{}
        foreach ($i in $plan) {
            $k = "$($i.Category)|$($i.Action)|$($i.Scope)"; $seen[$k] = $true
            if ($prev.ContainsKey($k)) {
                $o = $prev[$k]; $i.Owner = $o.Owner; $i.Notes = $o.Notes; $i.DueDate = $o.DueDate
                $i.Status = if ($o.Status -match '^(Closed|Done|Resolved|Complete)') { 'Reopened - recurred' } else { $o.Status }
            }
        }
        foreach ($k in $prev.Keys) {
            if (-not $seen.ContainsKey($k) -and $prev[$k].Status -notmatch '^(Closed|Done|Resolved|Complete)') {
                $o = $prev[$k]; $o.Notes = (("$($o.Notes) | Not observed in latest run - verify and close").Trim(' |'))
                $plan += $o
            }
        }
    }
    # Assign each action to the owner whose area it falls in, and attach the fix path
    foreach ($i in $plan) {
        $ownerKey = Get-Owner $i.Category $i.Tactic $i.Technique $i.Priority
        $i.Owner = $Owners[$ownerKey].Name
        $i.AssignedTo = "$($Owners[$ownerKey].Name) - $($Owners[$ownerKey].Area)"
        if (-not $i.FixPath) {
            $fix = Get-FixText $i.Technique $i.Tactic $i.Reference
            if ($i.Category -match 'Containment|Detection|Harden' -or -not $i.FixPath) { $i.FixPath = $fix.Path }
            if (-not $i.FixReference) { $i.FixReference = $fix.Ref }
        }
        if (-not $i.FixReference) { $i.FixReference = $i.Reference }
    }
    $n = 0; foreach ($i in $plan) { $n++; $i.ItemId = 'R{0:D3}' -f $n }
    return $plan
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------
function Export-NavigatorLayer($findings, $mitre, $path) {
    $techs = foreach ($g in $findings | Group-Object TechniqueId) {
        [ordered]@{ techniqueID = $g.Name; score = $g.Count; color = ''; comment = "Seen $($g.Count)x on: " + ((@($g.Group | ForEach-Object { $_.Host } | Where-Object { $_ }) | Select-Object -Unique) -join ', '); enabled = $true }
    }
    $max = [math]::Max(1, (@($findings | Group-Object TechniqueId | ForEach-Object { $_.Count }) | Measure-Object -Maximum).Maximum)
    $layer = [ordered]@{
        name = "Attack Hunt $(Get-Date -Format 'yyyy-MM-dd')"; domain = 'enterprise-attack'
        versions = [ordered]@{ attack = '18'; navigator = '5.1.0'; layer = '4.5' }
        description = 'Techniques observed in hunted alerts/logs'
        gradient = [ordered]@{ colors = @('#fff3b0', '#e85d04', '#9d0208'); minValue = 1; maxValue = $max }
        techniques = @($techs)
    }
    $layer | ConvertTo-Json -Depth 6 | Set-Content -Path $path -Encoding UTF8
}

function Get-ReportAuthor {
    # Explicit -AuthorName (or ATTACKHUNT_AUTHOR env var) wins; otherwise the person running the script.
    if ($AuthorName) { return $AuthorName }
    if ($env:OS -eq 'Windows_NT') {
        try { Add-Type -AssemblyName System.DirectoryServices.AccountManagement; $n = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current.DisplayName; if ($n) { return $n } } catch {}
        try { $n = ([adsi]"WinNT://$env:USERDOMAIN/$env:USERNAME,user").FullName; if ("$n".Trim()) { return "$n".Trim() } } catch {}
    } else {
        try { $n = ((getent passwd $env:USER 2>$null) -split ':')[4] -replace ',.*$', ''; if ("$n".Trim()) { return "$n".Trim() } } catch {}
        try { $n = (id -F 2>$null); if ("$n".Trim()) { return "$n".Trim() } } catch {}
    }
    if ($env:USERNAME) { return $env:USERNAME } elseif ($env:USER) { return $env:USER } else { return 'Unknown analyst' }
}

function Ensure-DefaultPngLogo {
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    foreach ($name in @('TMS_logo.png', 'logo.png')) {
        $path = Join-Path $here $name
        if (Test-Path $path) { return $path }
    }

    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
    } catch {
        return $null
    }

    $pngPath = Join-Path $here 'TMS_logo.png'
    $bmp = New-Object System.Drawing.Bitmap(1200, 320)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.Clear([System.Drawing.Color]::White)
    $black = [System.Drawing.Color]::FromArgb(17, 17, 17)
    $white = [System.Drawing.Color]::FromArgb(255, 255, 255)

    $g.FillRectangle([System.Drawing.SolidBrush]::new($black), 20, 20, 240, 240)
    $fontBold = New-Object System.Drawing.Font('Arial Black', 80, [System.Drawing.FontStyle]::Bold)
    $g.DrawString('T', $fontBold, [System.Drawing.SolidBrush]::new($white), 50, 48)
    $g.DrawString('M', $fontBold, [System.Drawing.SolidBrush]::new($white), 110, 48)
    $g.DrawString('S', $fontBold, [System.Drawing.SolidBrush]::new($white), 188, 48)

    $g.DrawLine(([System.Drawing.Pen]::new($white, 8)), 48, 170, 210, 170)
    $g.DrawLine(([System.Drawing.Pen]::new($white, 8)), 75, 170, 75, 220)
    $g.DrawLine(([System.Drawing.Pen]::new($white, 8)), 120, 170, 120, 220)
    $g.DrawLine(([System.Drawing.Pen]::new($white, 8)), 185, 170, 185, 220)
    $g.DrawLine(([System.Drawing.Pen]::new($white, 8)), 95, 195, 170, 195)
    $g.DrawLine(([System.Drawing.Pen]::new($white, 8)), 120, 170, 150, 210)
    $g.DrawLine(([System.Drawing.Pen]::new($white, 8)), 150, 210, 182, 170)

    $titleFont = New-Object System.Drawing.Font('Arial', 82, [System.Drawing.FontStyle]::Bold)
    $smallFont = New-Object System.Drawing.Font('Arial', 28, [System.Drawing.FontStyle]::Bold)
    $g.DrawString('TIMES', $titleFont, [System.Drawing.SolidBrush]::new($black), 315, 70)
    $g.DrawString('MICROWAVE SYSTEMS', $smallFont, [System.Drawing.SolidBrush]::new($black), 323, 146)
    $g.DrawLine(([System.Drawing.Pen]::new($black, 5)), 323, 175, 860, 175)
    $g.DrawString('AN AMPHENOL COMPANY', $smallFont, [System.Drawing.SolidBrush]::new($black), 323, 190)

    $g.Dispose()
    $bmp.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
    return $pngPath
}

function Get-LogoDataUri {
    $candidates = @()
    if ($LogoPath) { $candidates += $LogoPath }
    $here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    foreach ($n in 'TMS_logo', 'TMS-logo', 'tms_logo', 'TMSLogo', 'logo') { foreach ($e in 'png', 'jpg', 'jpeg', 'svg') { $candidates += (Join-Path $here "$n.$e") } }
    $defaultPng = Ensure-DefaultPngLogo
    if ($defaultPng) { $candidates += $defaultPng }
    foreach ($c in $candidates) {
        if ($c -and (Test-Path $c)) {
            $ext = [IO.Path]::GetExtension($c).TrimStart('.').ToLower()
            $mime = @{ png = 'image/png'; jpg = 'image/jpeg'; jpeg = 'image/jpeg'; svg = 'image/svg+xml' }[$ext]
            if ($mime) { return "data:$mime;base64," + [Convert]::ToBase64String([IO.File]::ReadAllBytes((Resolve-Path $c).Path)) }
        }
    }
    Write-Warn "No logo found. Put TMS_logo.png next to the script or pass -LogoPath. Using a text wordmark."
    return $null
}

function CssStr($s) { '"' + ("$s" -replace '\\', '\\' -replace '"', '\"' -replace "[\r\n]+", ' ') + '"' }
function Short($s, [int]$n) { $s = "$s"; if ($s.Length -gt $n) { $s.Substring(0, $n).TrimEnd() + '...' } else { $s } }

function Export-HtmlReport($events, $findings, $chains, $intel, $kev, $plan, $mitre, $intake, $explain, $path) {
    $sb = New-Object System.Text.StringBuilder
    $sevClass = @{ Critical = 'crit'; High = 'high'; Medium = 'med'; Low = 'low'; Info = 'low' }
    $author = Get-ReportAuthor
    $logo = Get-LogoDataUri
    $now = Get-Date
    $reportId = "$Organization-AH-" + $now.ToString('yyyyMMdd-HHmm')
    $linked = @($chains | Where-Object { $_.Verdict -eq 'Linked attack chain' })
    $critOpen = @($plan | Where-Object { $_.Priority -eq 'Critical' -and $_.Status -notmatch '^Closed' })
    $malicious = @($intel | Where-Object { $_.Verdict -eq 'Malicious' })
    $techCount = @($findings | Select-Object -ExpandProperty TechniqueId -Unique).Count
    $times = @($events | Where-Object { $_.Time } | ForEach-Object { $_.Time })
    $period = if ($times) { '{0:MMM d, yyyy HH:mm} to {1:MMM d, yyyy HH:mm}' -f ($times | Measure-Object -Minimum).Minimum, ($times | Measure-Object -Maximum).Maximum } else { 'Not specified in source data' }
    $sources = (@($events | ForEach-Object { $_.SourceFile }) | Select-Object -Unique) -join ', '
    $overall = if (@($chains | Where-Object Priority -eq 'Critical').Count) { 'Critical' } elseif (@($chains | Where-Object Priority -eq 'High').Count) { 'High' } elseif (@($chains | Where-Object Priority -eq 'Medium').Count) { 'Medium' } else { 'Low' }

    $logoBg = if ($logo) { "background: url(`"$logo`") no-repeat left center; background-size: contain;" } else { '' }
    $logoTxt = if ($logo) { '""' } else { CssStr $Organization }
    $pageLogoUrl = if ($logo) { "url('$logo')" } else { 'none' }
    $coverLogo = if ($logo) { "<img class='cover-logo' src='$logo' alt='$(HtmlEnc $Organization) logo'>" } else { "<div class='wordmark'>$(HtmlEnc $Organization)</div>" }

    [void]$sb.Append(@"
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>$(HtmlEnc $ReportTitle) - $reportId</title><style>
@page { size: Letter; margin: 0.95in 0.6in 0.8in;
  @top-left { content: none; }
  @top-right { content: $pageLogoUrl; width: 2.1in; height: 0.55in; margin-top: 0.12in; margin-right: 0.18in; }
  @bottom-left { content: $(CssStr "Prepared by $author, $AuthorTitle | $reportId"); font: 7.5pt Arial, sans-serif; color: #5b6475; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 7.5pt Arial, sans-serif; color: #5b6475; }
}
@page :first { @top-left { content: none; background: none; } @top-right { content: none; } @bottom-left { content: none; } @bottom-right { content: none; } }
*{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}
body{margin:0;color:#1c2230;font:9.5pt/1.45 "Segoe UI",Calibri,Arial,sans-serif}
h1{font-size:18pt;margin:0 0 6pt;color:#12305c}
h2{font-size:13.5pt;color:#12305c;margin:18pt 0 8pt;padding-bottom:4pt;border-bottom:1.5pt solid #12305c;break-after:avoid}
h3{font-size:11pt;margin:12pt 0 6pt;break-after:avoid}
p{margin:0 0 7pt}.sub{color:#5b6475}.page{break-before:page}
table{width:100%;border-collapse:collapse;font-size:8pt;margin:4pt 0 10pt}
th,td{padding:4pt 5pt;border:0.5pt solid #d5dae3;text-align:left;vertical-align:top}
th{background:#12305c;color:#fff;font-weight:600}tr:nth-child(even) td{background:#f5f7fa}tr{break-inside:avoid}
thead{display:table-header-group}
.tag{display:inline-block;padding:0 5pt;border-radius:6pt;font-size:7.5pt;font-weight:700;color:#fff;white-space:nowrap}
.crit{background:#b00020}.high{background:#d9480f}.med{background:#a07800}.low{background:#2b8a3e}
a{color:#1d4ed8;text-decoration:none}code{font:7.5pt Consolas,monospace;word-break:break-all}
.cover{height:9.2in;display:flex;flex-direction:column}
.cover-logo{max-width:3in;max-height:1.3in;object-fit:contain;margin-top:0.3in}
.wordmark{font:800 40pt Arial,sans-serif;color:#12305c;letter-spacing:2pt;margin-top:0.3in}
.cover .band{margin-top:1.4in;border-left:6pt solid #12305c;padding-left:16pt}
.cover .title{font-size:26pt;font-weight:700;color:#12305c;line-height:1.15}
.cover .subtitle{font-size:13pt;color:#5b6475;margin-top:6pt}
.cover .meta{margin-top:auto;font-size:10pt}
.cover .meta td{border:none;padding:3pt 10pt 3pt 0;background:none!important}.cover .meta td:first-child{color:#5b6475;width:1.6in}
.class{display:inline-block;border:1.5pt solid #b00020;color:#b00020;font-weight:700;padding:2pt 10pt;letter-spacing:1pt;margin-top:14pt}
.kpis{display:flex;gap:6pt;margin:8pt 0 12pt}.kpi{flex:1;border:0.5pt solid #d5dae3;border-top:3pt solid #12305c;padding:6pt}
.kpi b{display:block;font-size:17pt;color:#12305c}.kpi span{font-size:7.5pt;color:#5b6475}
.risk{padding:8pt 10pt;border-radius:4pt;color:#fff;font-weight:700;margin:6pt 0 10pt}
.chain{border:0.5pt solid #d5dae3;border-left:4pt solid #12305c;padding:7pt 9pt;margin:0 0 10pt}
.flow{margin:4pt 0}.flow span{display:inline-block;background:#e8eefc;color:#1e3a8a;border-radius:3pt;padding:1pt 5pt;font-size:7.5pt;margin:1pt 0}
.flow span+span:before{content:"\2192  ";color:#5b6475}
.sign td{height:0.45in;vertical-align:bottom}
</style></head><body>
<section class="cover">
$coverLogo
<div class="band"><div class="title">$(HtmlEnc $ReportTitle)</div><div class="subtitle">MITRE ATT&amp;CK-mapped threat hunt of alerts, logs and events</div><div class="class">$(HtmlEnc $Classification)</div></div>
<table class="meta">
<tr><td>Prepared for</td><td>$(HtmlEnc $Organization)</td></tr>
<tr><td>Prepared by</td><td><b>$(HtmlEnc $author)</b>, $(HtmlEnc $AuthorTitle)</td></tr>
<tr><td>Report date</td><td>$($now.ToString('MMMM d, yyyy'))</td></tr>
<tr><td>Report ID</td><td>$reportId</td></tr>
<tr><td>Period analyzed</td><td>$period</td></tr>
<tr><td>Data sources</td><td>$(HtmlEnc $sources)</td></tr>
<tr><td>Framework</td><td>MITRE ATT&amp;CK Enterprise ($(HtmlEnc $mitre.Version))</td></tr>
</table>
</section>
"@)

    # ---- 1. Executive summary (narrative written from the engineer's perspective)
    $riskColor = @{ Critical = '#b00020'; High = '#d9480f'; Medium = '#a07800'; Low = '#2b8a3e' }[$overall]
    [void]$sb.Append("<section class='page'><h1>1. Executive Summary</h1>")
    [void]$sb.Append("<div class='risk' style='background:$riskColor'>Overall risk rating: $overall</div>")
    $para1 = "As $AuthorTitle for $Organization, I reviewed $($events.Count) alerts, log entries and events ($period) and mapped them to the MITRE ATT&CK framework. The review produced $($findings.Count) findings across $techCount distinct attack techniques, which I grouped into $($chains.Count) activity clusters by host, source and time."
    [void]$sb.Append("<p>$(HtmlEnc $para1)</p>")
    if ($linked.Count) {
        $top = $linked[0]
        $para2 = "Of these, $($linked.Count) show a linked attack chain, meaning the activity moves through multiple stages of an attack rather than appearing as isolated alerts. The most severe is $($top.ChainId) on $($top.Entity), which progressed through: $($top.Tactics -join ' > ')."
        if ($top.Related) { $para2 += " It shares accounts or IP addresses with $($top.Related -join ', '), which indicates the same actor moved between systems." }
        [void]$sb.Append("<p>$(HtmlEnc $para2)</p>")
    } else {
        [void]$sb.Append("<p>No multi-stage attack chain was identified; the activity found appears isolated and should be validated and tuned.</p>")
    }
    $para3 = @()
    if ($malicious.Count) { $para3 += "$($malicious.Count) indicator(s) were confirmed malicious by open-source threat intelligence" }
    if ($kev.Count) { $para3 += "$($kev.Count) vulnerability reference(s) appear on the CISA Known Exploited Vulnerabilities list" }
    if ($para3) { [void]$sb.Append("<p>$(HtmlEnc (($para3 -join ', and ') + '.'))</p>") }
    [void]$sb.Append("<p>$(HtmlEnc "I have built a remediation plan of $($plan.Count) actions, $($critOpen.Count) of them critical and due within 24 hours. The plan is tracked item by item and will be re-validated by re-running this hunt after remediation to confirm the issues are closed.")</p>")
    [void]$sb.Append(@"
<div class="kpis">
<div class="kpi"><b>$($events.Count)</b><span>events analyzed</span></div>
<div class="kpi"><b>$($findings.Count)</b><span>ATT&amp;CK findings</span></div>
<div class="kpi"><b>$techCount</b><span>techniques</span></div>
<div class="kpi"><b>$($linked.Count)</b><span>linked attack chains</span></div>
<div class="kpi"><b>$($malicious.Count)</b><span>malicious IOCs</span></div>
<div class="kpi"><b>$($critOpen.Count)</b><span>critical actions</span></div>
</div>
"@)
    [void]$sb.Append("<h3>Immediate priorities</h3><table><thead><tr><th>ID</th><th>Priority</th><th>Action</th><th style='width:13%'>Scope</th><th style='width:11%'>Due</th></tr></thead>")
    foreach ($p in @($plan | Where-Object { $_.Priority -in 'Critical', 'High' } | Select-Object -First 8)) {
        [void]$sb.Append("<tr><td>$($p.ItemId)</td><td><span class='tag $($sevClass[$p.Priority])'>$($p.Priority)</span></td><td>$(HtmlEnc (Short $p.Action 180))</td><td>$(HtmlEnc $p.Scope)</td><td style='white-space:nowrap'>$($p.DueDate)</td></tr>")
    }
    [void]$sb.Append('</table></section>')

    # ---- 2. Detection & response context (from intake)
    [void]$sb.Append("<section class='page'><h1>2. Detection &amp; Response Context</h1>")
    [void]$sb.Append("<p class='sub'>How this activity was detected, and what had already been done before this investigation.</p>")
    [void]$sb.Append("<table><thead><tr><th style='width:24%'>Item</th><th>Detail</th></tr></thead>")
    [void]$sb.Append("<tr><td>Detection source</td><td><b>$(HtmlEnc $intake.Source)</b> &ndash; $(HtmlEnc $intake.SourceKind)</td></tr>")
    [void]$sb.Append("<tr><td>How it was detected / pre-done controls</td><td>$(HtmlEnc $intake.PreDone)</td></tr>")
    if ($intake.SourceConsole) { [void]$sb.Append("<tr><td>Where to verify</td><td>$(HtmlEnc $intake.SourceConsole)</td></tr>") }
    if ($intake.Manual) { [void]$sb.Append("<tr><td>Manual actions already taken</td><td>$(HtmlEnc $intake.Manual)</td></tr>") }
    [void]$sb.Append('</table>')
    if ($intake.TriggerLog) {
        [void]$sb.Append("<h3>Log parse that triggered the alert</h3><pre style='background:#f5f7fa;border:0.5pt solid #d5dae3;padding:6pt;font:7.5pt Consolas,monospace;white-space:pre-wrap;word-break:break-all'>$(HtmlEnc $intake.TriggerLog)</pre>")
    }
    if ($intake.Correlated) {
        [void]$sb.Append("<h3>Correlated logs supplied</h3><pre style='background:#f5f7fa;border:0.5pt solid #d5dae3;padding:6pt;font:7.5pt Consolas,monospace;white-space:pre-wrap;word-break:break-all'>$(HtmlEnc (Short $intake.Correlated 4000))</pre>")
    }
    [void]$sb.Append("<h3>Assignment key (who handles what)</h3><table><thead><tr><th style='width:26%'>Owner</th><th>Handles</th></tr></thead>")
    foreach ($ok in $AssignmentKey.Keys) {
        $bullets = ($AssignmentKey[$ok] | ForEach-Object { "&bull; $(HtmlEnc $_)" }) -join '<br>'
        [void]$sb.Append("<tr><td><b>$(HtmlEnc $Owners[$ok].Name)</b><br><span class='sub'>$(HtmlEnc $Owners[$ok].Area)</span></td><td>$bullets</td></tr>")
    }
    [void]$sb.Append('</table></section>')

    # ---- 3. Threat explanation (narrative deep-dive)
    [void]$sb.Append("<section class='page'><h1>3. Threat Explanation</h1><p class='sub'>A step-by-step account of each significant chain: what the attacker did, the log that revealed it, and why it matters.</p>")
    if (-not $explain -or -not @($explain).Count) { [void]$sb.Append('<p>No significant multi-stage activity to narrate; see the isolated findings in the following sections.</p>') }
    foreach ($e in $explain) {
        $c = $e.Chain
        [void]$sb.Append("<h3><span class='tag $($sevClass[$c.Priority])'>$($c.Priority)</span> $($c.ChainId) &middot; $(HtmlEnc $c.Entity) &middot; $($c.Verdict)</h3>")
        [void]$sb.Append("<p class='sub'>Kill chain: $(HtmlEnc ($c.Tactics -join ' -> '))</p>")
        [void]$sb.Append("<table><thead><tr><th style='width:13%'>Stage</th><th style='width:20%'>Technique</th><th>What happened &amp; the evidence</th></tr></thead>")
        foreach ($s in $e.Steps) {
            $ev = "<b>What:</b> $(HtmlEnc $s.What)"
            if ($s.Trigger) { $ev += "<br><b>Detected by:</b> <code>$(HtmlEnc $s.Trigger)</code>" }
            if ($s.RawLog)  { $ev += "<br><b>Log:</b> <code>$(HtmlEnc $s.RawLog)</code>" }
            if ($s.When)    { $ev += "<br><span class='sub'>$($s.When)</span>" }
            [void]$sb.Append("<tr><td>$(HtmlEnc $s.Tactic)</td><td><a href='$($s.Url)'>$($s.TechniqueId)</a> $(HtmlEnc $s.TechniqueName)</td><td>$ev</td></tr>")
        }
        [void]$sb.Append('</table>')
        $chainFixes = @($plan | Where-Object { $_.Scope -match [regex]::Escape($c.ChainId) } | Select-Object -First 8)
        if ($chainFixes) {
            [void]$sb.Append("<p><b>How to fix this chain (with the assigned owner):</b></p><table><thead><tr><th style='width:7%'>ID</th><th style='width:18%'>Owner</th><th>Fix path</th></tr></thead>")
            foreach ($p in $chainFixes) { [void]$sb.Append("<tr><td>$($p.ItemId)</td><td>$(HtmlEnc $p.Owner)</td><td>$(HtmlEnc (Short $p.FixPath 320))</td></tr>") }
            [void]$sb.Append('</table>')
        }
    }
    [void]$sb.Append('</section>')

    # ---- 4. Attack chains
    [void]$sb.Append("<section class='page'><h1>4. Attack Chains</h1><p class='sub'>Findings are grouped per host (or source IP/user), split after $ChainWindowMinutes minutes of inactivity, and ordered along the ATT&amp;CK kill chain. Clusters that share a user or IP are cross-referenced.</p>")
    foreach ($c in $chains) {
        $timeTxt = if ($c.Start) { "$($c.Start.ToString('yyyy-MM-dd HH:mm')) to $($c.End.ToString('HH:mm'))" } else { 'time unknown' }
        [void]$sb.Append("<div class='chain'><span class='tag $($sevClass[$c.Priority])'>$($c.Priority)</span> <b>$($c.ChainId) &middot; $(HtmlEnc $c.Entity)</b> &middot; $($c.Verdict) &middot; score $($c.Score) &middot; $timeTxt")
        [void]$sb.Append("<div class='flow'>" + (($c.Tactics | ForEach-Object { "<span>$_</span>" }) -join '') + '</div>')
        $meta = @()
        if ($c.Users) { $meta += "Accounts: $($c.Users -join ', ')" }
        if ($c.IntelHits) { $meta += "Threat-intel hits: $($c.IntelHits -join ', ')" }
        if ($c.Related) { $meta += "Related: $($c.Related -join ', ')" }
        if ($meta) { [void]$sb.Append("<div class='sub'>$(HtmlEnc ($meta -join '  |  '))</div>") }
        [void]$sb.Append("<table><thead><tr><th style='width:10%'>Time</th><th style='width:13%'>Tactic</th><th style='width:22%'>Technique</th><th style='width:7%'>Sev</th><th>Evidence / triggering log</th></tr></thead>")
        foreach ($f in $c.Items) {
            $tt = if ($f.Time) { $f.Time.ToString('MM-dd HH:mm:ss') } else { '' }
            $ev = "<code>$(HtmlEnc $f.Evidence)</code>"
            if ($f.Trigger) { $ev += "<br><span class='sub'>$(HtmlEnc (Short $f.Trigger 160))</span>" }
            [void]$sb.Append("<tr><td>$tt</td><td>$($f.Tactic)</td><td><a href='$($f.Url)'>$($f.TechniqueId)</a> $(HtmlEnc $f.TechniqueName)</td><td><span class='tag $($sevClass[$f.Severity])'>$($f.Severity)</span></td><td>$ev</td></tr>")
        }
        [void]$sb.Append('</table></div>')
    }
    if (-not $chains) { [void]$sb.Append('<p>No ATT&amp;CK-mapped activity was found in the supplied data.</p>') }
    [void]$sb.Append('</section>')

    # ---- 3. Attack vectors
    [void]$sb.Append("<section class='page'><h1>6. Attack Vectors (Techniques Observed)</h1><table><thead><tr><th style='width:17%'>Technique</th><th style='width:12%'>Tactic(s)</th><th style='width:5%'>Count</th><th style='width:12%'>Hosts</th><th>Description (MITRE ATT&amp;CK)</th></tr></thead>")
    foreach ($g in $findings | Group-Object TechniqueId | Sort-Object Count -Descending) {
        $f = $g.Group[0]; $t = $mitre.Lookup[$g.Name]
        $desc = if ($t) { $t.Description } else { $f.Detection }
        $hosts = (@($g.Group | ForEach-Object { $_.Host } | Where-Object { $_ }) | Select-Object -Unique) -join ', '
        [void]$sb.Append("<tr><td><a href='$($f.Url)'>$($g.Name)</a><br>$(HtmlEnc $f.TechniqueName)</td><td>$(HtmlEnc $f.AllTactics)</td><td>$($g.Count)</td><td>$(HtmlEnc $hosts)</td><td>$(HtmlEnc (Short $desc 380))</td></tr>")
    }
    [void]$sb.Append('</table>')

    # ---- 4. Threat intel
    [void]$sb.Append("<h1 style='margin-top:18pt'>7. Open-Source Threat Intelligence</h1>")
    if ($intel.Count) {
        [void]$sb.Append("<table><thead><tr><th>Indicator</th><th>Verdict</th><th>OTX pulses</th><th>OTX ATT&amp;CK IDs</th><th>AbuseIPDB</th><th>ThreatFox</th><th>Geo / ISP</th></tr></thead>")
        foreach ($i in $intel | Sort-Object { @{ Malicious = 0; Suspicious = 1; Unknown = 2; 'No hits' = 3 }[$_.Verdict] }) {
            $vc = @{ Malicious = 'crit'; Suspicious = 'high'; Unknown = 'med'; 'No hits' = 'low' }[$i.Verdict]
            $ab = if ($null -ne $i.AbuseScore) { "$($i.AbuseScore)% ($($i.AbuseReports) reports)" } else { '' }
            [void]$sb.Append("<tr><td><code>$(HtmlEnc $i.Value)</code><br><span class='sub'>$($i.Type)</span></td><td><span class='tag $vc'>$($i.Verdict)</span></td><td>$($i.OTXPulses)</td><td>$(HtmlEnc $i.OTXAttackIds)</td><td>$ab</td><td>$(HtmlEnc $i.ThreatFox)</td><td>$(HtmlEnc "$($i.Country) $($i.ISP)")</td></tr>")
        }
        [void]$sb.Append('</table>')
    } else { [void]$sb.Append("<p class='sub'>IOC reputation lookups were not run for this report (no API keys supplied, offline mode, or no public indicators in the data).</p>") }
    if ($kev.Count) {
        [void]$sb.Append("<h3>CISA Known Exploited Vulnerabilities referenced in the data</h3><table><thead><tr><th>CVE</th><th>Product</th><th>Ransomware use</th><th>Required action</th><th>Host</th></tr></thead>")
        foreach ($k in $kev) { [void]$sb.Append("<tr><td>$($k.CVE)</td><td>$(HtmlEnc "$($k.Vendor) $($k.Product)")</td><td>$($k.Ransomware)</td><td>$(HtmlEnc $k.RequiredAction)</td><td>$(HtmlEnc $k.SeenOnHost)</td></tr>") }
        [void]$sb.Append('</table>')
    }
    [void]$sb.Append('</section>')

    # ---- 5. Remediation plan
    [void]$sb.Append("<section class='page'><h1>8. Action Plan &amp; Fix Paths</h1><p class='sub'>The full plan is in Action_Plan.csv (also Remediation_Plan.csv for the re-run loop). Each item is assigned to its owner ($(HtmlEnc $AssignmentText)), has a step-by-step fix path and a reference link. Owners and status carry forward when re-run with -PreviousPlan; a closed item that recurs is reopened.</p>")
    foreach ($p in $plan) {
        [void]$sb.Append("<div style='border:0.5pt solid #d5dae3;border-left:3pt solid #12305c;padding:6pt 8pt;margin:0 0 7pt'>")
        [void]$sb.Append("<b>$($p.ItemId)</b> <span class='tag $($sevClass[$p.Priority])'>$($p.Priority)</span> &middot; $(HtmlEnc $p.Category) &middot; <b>Assigned to:</b> $(HtmlEnc $p.AssignedTo) &middot; <b>Due</b> $($p.DueDate) &middot; <b>Status</b> $(HtmlEnc $p.Status)")
        [void]$sb.Append("<div style='margin-top:3pt'><b>Action:</b> $(HtmlEnc $p.Action)</div>")
        if ($p.Scope) { [void]$sb.Append("<div class='sub'>Scope: $(HtmlEnc $p.Scope)" + $(if ($p.Technique) { " &middot; Technique: $(HtmlEnc $p.Technique)" } else { '' }) + "</div>") }
        if ($p.FixPath) { [void]$sb.Append("<div style='margin-top:3pt'><b>Fix path:</b> $(HtmlEnc $p.FixPath)</div>") }
        if ($p.FixReference) {
            $refs = @($p.FixReference -split '\s*\|\s*' | Where-Object { $_ -match '^https?://' })
            if ($refs) { [void]$sb.Append("<div class='sub'>Reference: " + (($refs | ForEach-Object { "<a href='$_'>$(HtmlEnc $_)</a>" }) -join ' &middot; ') + "</div>") }
        }
        [void]$sb.Append('</div>')
    }
    [void]$sb.Append('</section>')

    # ---- 6. Method + sign-off
    [void]$sb.Append(@"
<section class="page"><h1>9. Methodology &amp; Sources</h1>
<p>The detection source and the triggering / correlated logs were captured at intake ($(HtmlEnc $intake.Source)). Log lines were parsed (JSON, CEF, LEEF, key=value or syslog), normalized, and matched to ATT&amp;CK techniques using Windows event IDs, command-line and alert-text rules, and any technique IDs already present in the source alerts. Rule matches are investigative leads and were reviewed in context. Related findings were linked into chains by host, account, IP address and time. Each fix path is drawn from the ATT&amp;CK mitigations and a curated remediation knowledge base, and assigned to its owner ($(HtmlEnc $AssignmentText)).</p>
<table><thead><tr><th>Source</th><th>Use in this report</th></tr></thead>
<tr><td>MITRE ATT&amp;CK Enterprise (github.com/mitre/cti)</td><td>Technique, tactic and mitigation data ($(HtmlEnc $mitre.Version))</td></tr>
<tr><td>CISA Known Exploited Vulnerabilities</td><td>Checks CVEs referenced in the data</td></tr>
<tr><td>CISA StopRansomware / advisories, LOLBAS, Microsoft Learn</td><td>Fix-path references for containment and hardening</td></tr>
<tr><td>AlienVault OTX, AbuseIPDB, abuse.ch ThreatFox</td><td>IP, domain and file-hash reputation (when API keys are configured)</td></tr>
</table>
<p>A heatmap of the observed techniques is provided in ATTACK_Navigator_Layer.json for use in the MITRE ATT&amp;CK Navigator.</p>
<h2>Report Sign-off</h2>
<table class="sign"><thead><tr><th style="width:22%">Role</th><th style="width:30%">Name</th><th style="width:28%">Signature</th><th>Date</th></tr></thead>
<tr><td>Prepared by<br><span class="sub">$(HtmlEnc $AuthorTitle)</span></td><td>$(HtmlEnc $author)</td><td></td><td>$($now.ToString('yyyy-MM-dd'))</td></tr>
<tr><td>Reviewed by</td><td></td><td></td><td></td></tr>
<tr><td>Approved by</td><td></td><td></td><td></td></tr>
</table>
</section></body></html>
"@)
    [IO.File]::WriteAllText($path, $sb.ToString(), (New-Object Text.UTF8Encoding($false)))
    return $author
}

function Find-PdfEngine {
    $paths = @()
    if ($BrowserPath) { $paths += $BrowserPath }
    $pf86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    foreach ($root in @($pf86, $env:ProgramFiles, $env:LOCALAPPDATA)) {
        if (-not $root) { continue }
        $paths += (Join-Path $root 'Microsoft\Edge\Application\msedge.exe')
        $paths += (Join-Path $root 'Google\Chrome\Application\chrome.exe')
    }
    $paths += '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge', '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    foreach ($p in $paths) { if ($p -and (Test-Path $p)) { return @{ Type = 'chromium'; Path = $p } } }
    foreach ($n in 'msedge', 'microsoft-edge', 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser', 'chrome') {
        $c = Get-Command $n -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($c) { return @{ Type = 'chromium'; Path = $c.Source } }
    }
    $w = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($w) { return @{ Type = 'wkhtmltopdf'; Path = $w.Source } }
    return $null
}

function Convert-HtmlToPdf([string]$html, [string]$pdf) {
    $engine = Find-PdfEngine
    if (-not $engine) { Write-Warn 'No Edge/Chrome/wkhtmltopdf found - cannot create PDF. Use -BrowserPath to point at msedge.exe or chrome.exe.'; return $false }
    $htmlFull = (Resolve-Path $html).Path
    $pdfFull = [IO.Path]::GetFullPath($pdf)
    if (Test-Path $pdfFull) { Remove-Item $pdfFull -Force }
    Write-Step "Rendering PDF with $([IO.Path]::GetFileName($engine.Path))..."
    if ($engine.Type -eq 'chromium') {
        $profile = Join-Path ([IO.Path]::GetTempPath()) ('ah-pdf-' + [Guid]::NewGuid().ToString('N'))
        $ub = New-Object System.UriBuilder; $ub.Scheme = 'file'; $ub.Host = ''; $ub.Path = ($htmlFull -replace '\\', '/'); $uri = $ub.Uri.AbsoluteUri
        $base = '--headless=new --disable-gpu --no-first-run --no-default-browser-check --disable-extensions --disable-background-networking --disable-component-update --disable-sync --no-pdf-header-footer'
        if ($env:OS -ne 'Windows_NT') { $base = '--no-sandbox ' + $base }
        # Attempt 1 uses a throw-away profile so an already-open Edge/Chrome window isn't disturbed;
        # attempt 2 falls back to the default profile if the first one stalls.
        $attempts = @(
            "$base --user-data-dir=`"$profile`" --print-to-pdf=`"$pdfFull`" `"$uri`"",
            "$base --print-to-pdf=`"$pdfFull`" `"$uri`""
        )
        foreach ($argString in $attempts) {
            $spArgs = @{ FilePath = $engine.Path; ArgumentList = $argString; PassThru = $true }
            if ($env:OS -eq 'Windows_NT') { $spArgs.WindowStyle = 'Hidden' }
            else { $spArgs.RedirectStandardError = (Join-Path ([IO.Path]::GetTempPath()) 'ah-pdf-stderr.txt') }
            $proc = Start-Process @spArgs
            $deadline = (Get-Date).AddSeconds(45)
            while (-not $proc.HasExited -and (Get-Date) -lt $deadline) {
                if ((Test-Path $pdfFull) -and (Get-Item $pdfFull).Length -gt 1000) { Start-Sleep -Seconds 1; break }
                Start-Sleep -Milliseconds 400
            }
            if (-not $proc.HasExited) { try { $proc.Kill($true) } catch { try { $proc.Kill() } catch {} } }
            if ((Test-Path $pdfFull) -and (Get-Item $pdfFull).Length -gt 1000) { break }
            Write-Verbose 'PDF attempt stalled - retrying with the default browser profile.'
        }
        Remove-Item $profile -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        & $engine.Path --quiet --enable-local-file-access --page-size Letter --margin-top 15mm --margin-bottom 15mm --footer-font-size 7 --footer-right 'Page [page] of [topage]' $htmlFull $pdfFull 2>$null | Out-Null
    }
    if ((Test-Path $pdfFull) -and (Get-Item $pdfFull).Length -gt 1000) { return $true }
    Write-Warn 'PDF rendering failed - the HTML version has been kept instead.'
    return $false
}

Show-StartupBanner

# ---------------------------------------------------------------------------
# Interactive intake
# ---------------------------------------------------------------------------
function Read-MultiLine($prompt) {
    Write-Host $prompt -ForegroundColor Yellow
    Write-Host "    (paste one or more lines; finish with a single '.' on its own line. Press Enter on a blank line to skip.)" -ForegroundColor DarkGray
    $lines = @()
    while ($true) {
        try { $l = Read-Host } catch { break }   # break on EOF / non-interactive console
        if ($null -eq $l) { break }
        if ($l -eq '.') { break }
        if ($l -eq '' -and $lines.Count -eq 0) { break }
        $lines += $l
    }
    return ($lines -join "`n")
}
function Read-Menu($prompt, $options) {
    Write-Host $prompt -ForegroundColor Yellow
    for ($i = 0; $i -lt $options.Count; $i++) { Write-Host ("    {0}) {1}" -f ($i + 1), $options[$i]) }
    $tries = 0
    while ($true) {
        try { $a = Read-Host '    Enter number' } catch { return $options[-1] }
        if ($a -match '^\d+$' -and [int]$a -ge 1 -and [int]$a -le $options.Count) { return $options[[int]$a - 1] }
        if ($null -eq $a -or (++$tries -ge 5)) { return $options[-1] }
        Write-Warn "    Please enter 1-$($options.Count)."
    }
}

function Invoke-Intake {
    $noConsole = $NoIntake
    try { $null = [Console]::WindowWidth } catch { $noConsole = $true }   # non-interactive host
    $src = $DetectionSource
    if (-not $src) {
        if ($noConsole) { $src = 'Other' }
        else {
            Write-Host ''
            Write-Host '=== Attack Hunt intake ===' -ForegroundColor Cyan
            $src = Read-Menu 'Where did the report come from? (how the attack was detected, and what was already done)' @('Blumira','CrowdStrike','ThreatLocker','Nessus','Barracuda','Other')
        }
    }
    $known = $DetectionSources[$src]; if (-not $known) { $known = $DetectionSources['Other'] }
    Write-Host ("    -> {0}: {1}" -f $src, $known.Kind) -ForegroundColor DarkGray
    Write-Host ("    Typically pre-done: {0}" -f $known.PreDone) -ForegroundColor DarkGray

    $pre = $PreDoneActions
    if (-not $pre -and -not $noConsole) { $pre = Read-MultiLine 'How was this detected, and what did the tool already do? (Enter to accept the typical behaviour above)' }
    if (-not $pre) { $pre = $known.PreDone }

    $trigger = $TriggerLog
    if (-not $trigger -and -not $noConsole) { $trigger = Read-MultiLine 'Paste the log line / parse that TRIGGERED the alert:' }

    $correlated = ''
    if (-not $noConsole) { $correlated = Read-MultiLine 'Paste any CORRELATED logs (the rest of the log string, related events). Or leave blank if you will point to files:' }
    $corrFromFiles = ''
    foreach ($cf in @($CorrelatedLogFiles)) { if ($cf -and (Test-Path $cf)) { $corrFromFiles += "`n" + (Get-Content $cf -Raw) } }

    $manual = $ManualActions
    if (-not $manual -and -not $noConsole) { $manual = Read-MultiLine 'Any MANUAL actions already taken? (isolation, disabled account, blocked IP...)' }

    return [ordered]@{
        Source        = $src
        SourceKind    = $known.Kind
        SourceConsole = $known.Console
        FirstTier     = $known.FirstTier
        PreDone       = $pre
        TriggerLog    = $trigger
        Correlated    = ($correlated + $corrFromFiles).Trim()
        Manual        = $manual
    }
}

# ---------------------------------------------------------------------------
# Ownership / escalation + fix-path lookup
# ---------------------------------------------------------------------------
function Get-Owner($category, $tactic, $technique, $priority) {
    # Christian - further intervention for confirmed active compromise / major incident:
    # ransomware, exfiltration, domain-wide credential compromise, and the active impact response.
    if ($tactic -eq 'exfiltration') { return 'Christian' }
    if ($technique -match '^T1486' -or $technique -match '^T1003\.003' -or $technique -match '^T1003\.001') { return 'Christian' }
    if ($category -match 'Containment \(impact\)|impact') { return 'Christian' }
    # Brian - server / virtualization / backup / recovery work (incl. hardening backups after shadow-copy
    # deletion; the active ransomware response above still goes to Christian).
    if ($technique -match '^T1490' -or $category -match 'backup|recovery|shadow|hypervisor|virtual|\bVM\b|snapshot|server') { return 'Brian' }
    # Explicit owner from the fix knowledge base when we have one for this technique
    $fx = Get-FixEntry $technique
    if ($fx -and $fx.Owner) { return $fx.Owner }
    # Devon - network, perimeter, all security matters, AD / enterprise identity
    if ($tactic -in 'command-and-control','lateral-movement','initial-access' -or $category -match 'IOC|C2|Block|Network|Patch|Detection') { return 'Devon' }
    if ($tactic -eq 'credential-access' -or ($tactic -eq 'discovery' -and $technique -match 'T1087|T1482|T1018') -or $technique -match 'T1558|T1110|T1078|T1098|T1136') { return 'Devon' }
    # Steven - endpoint / host administration
    if ($tactic -in 'execution','persistence','privilege-escalation','stealth','defense-impairment','collection','discovery') { return 'Steven' }
    return 'Devon'
}
function Get-FixEntry($technique) {
    if (-not $technique) { return $null }
    foreach ($tid in @($technique -split '[,\s]+' | Where-Object { $_ })) {
        if ($FixPaths.ContainsKey($tid)) { return $FixPaths[$tid] }
        $base = ($tid -split '\.')[0]
        if ($FixPaths.ContainsKey($base)) { return $FixPaths[$base] }
    }
    return $null
}
function Get-FixText($technique, $tactic, $fallbackRef) {
    $fx = Get-FixEntry $technique
    if ($fx) {
        $steps = @(); $i = 0; foreach ($s in $fx.Steps) { $i++; $steps += "$i. $s" }
        return @{ Path = ($steps -join '  '); Ref = (@($fx.Refs) -join '  |  ') }
    }
    $p = if ($Playbook.ContainsKey($tactic)) { $Playbook[$tactic] } else { 'Investigate, contain the affected asset, then apply the vendor/ATT&CK mitigation and confirm.' }
    return @{ Path = $p; Ref = $fallbackRef }
}

# ---------------------------------------------------------------------------
# Narrative threat explanation (per significant chain)
# ---------------------------------------------------------------------------
function Get-ThreatExplanation($chains, $mitre, $intake) {
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($c in $chains | Where-Object { $_.Verdict -ne 'Isolated activity' -or $_.Priority -in 'Critical','High' }) {
        $steps = @()
        foreach ($f in $c.Items) {
            $t = $mitre.Lookup[$f.TechniqueId]; if (-not $t -and $f.TechniqueId -match '\.') { $t = $mitre.Lookup[($f.TechniqueId -split '\.')[0]] }
            $what = if ($t) { $t.Description } else { $f.TechniqueName }
            $steps += [pscustomobject]@{
                Tactic = $f.Tactic; TechniqueId = $f.TechniqueId; TechniqueName = $f.TechniqueName
                When = if ($f.Time) { $f.Time.ToString('yyyy-MM-dd HH:mm:ss') } else { '' }
                Trigger = $f.Trigger; RawLog = $f.RawLog; What = (Short $what 300); Url = $f.Url
            }
        }
        $out.Add([pscustomobject]@{ Chain = $c; Steps = $steps })
    }
    return $out
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
$intake   = Invoke-Intake
$mitre    = Get-MitreAttack
$events   = New-Object System.Collections.Generic.List[object]
foreach ($e in @(Get-InputRows)) { $events.Add($e) }
# Ingest the pasted trigger log and correlated logs from the intake as events too
foreach ($e in @(ConvertFrom-RawLog $intake.TriggerLog 'triggering-log' $intake.Source)) { $events.Add($e) }
foreach ($e in @(ConvertFrom-RawLog $intake.Correlated 'correlated-log' $intake.Source)) { $events.Add($e) }
if (-not $events.Count) { throw 'No events to analyze. Provide -InputPath, or paste a log at the intake prompt.' }
Write-Step "Mapping $($events.Count) events to ATT&CK ($($intake.Source) source)..."
$findings = @(Get-Findings $events $mitre)
Write-Good "$($findings.Count) findings across $(@($findings | Select-Object -ExpandProperty TechniqueId -Unique).Count) techniques."

$iocs = @(Get-Iocs $events)
Write-Step "$($iocs.Count) public IOCs extracted."
$intel = @(Invoke-Intel $iocs)
$kev   = @(Get-KevMatches $events)

Write-Step 'Linking findings into attack chains...'
$chains = @(Get-AttackChains $findings $intel)
Write-Good "$($chains.Count) chains ($(@($chains | Where-Object Verdict -eq 'Linked attack chain').Count) linked attack chains)."

$plan = @(New-RemediationPlan $chains $findings $intel $kev $mitre)

# Write outputs
$findingsOut = $findings | Select-Object FindingId, @{ n = 'Time'; e = { if ($_.Time) { $_.Time.ToString('s') } } }, Host, User, SourceIP, DestIP, TechniqueId, TechniqueName, Tactic, Severity, Detection, Trigger, DetectionTool, RawLog, Evidence, Source, Url
$planOut     = $plan | Select-Object ItemId, Priority, Owner, AssignedTo, Category, Technique, Tactic, Action, FixPath, FixReference, Scope, DueDate, Status, Notes
$chainsOut   = $chains | Select-Object ChainId, Entity, Priority, Verdict, Score, @{ n = 'Start'; e = { if ($_.Start) { $_.Start.ToString('s') } } }, @{ n = 'End'; e = { if ($_.End) { $_.End.ToString('s') } } }, Findings, Flow, @{ n = 'Techniques'; e = { $_.Techniques -join ', ' } }, @{ n = 'Users'; e = { $_.Users -join ', ' } }, @{ n = 'IntelHits'; e = { $_.IntelHits -join ', ' } }, @{ n = 'Related'; e = { $_.Related -join '; ' } }

$explain = Get-ThreatExplanation $chains $mitre $intake
$htmlPath = Join-Path $OutputDir 'AttackHunt_Report.html'
$pdfPath  = Join-Path $OutputDir ("{0}_AttackHunt_Report_{1}.pdf" -f ($Organization -replace '[^\w-]', ''), (Get-Date -Format 'yyyyMMdd_HHmm'))
$author = Export-HtmlReport $events $findings $chains $intel $kev $plan $mitre $intake $explain $htmlPath
$reportPath = $htmlPath
if (Convert-HtmlToPdf $htmlPath $pdfPath) {
    $reportPath = $pdfPath
    if (-not $KeepHtml) { Remove-Item $htmlPath -Force -ErrorAction SilentlyContinue }
}
Export-NavigatorLayer $findings $mitre (Join-Path $OutputDir 'ATTACK_Navigator_Layer.json')
$findingsOut | Export-Csv (Join-Path $OutputDir 'Findings.csv') -NoTypeInformation -Encoding UTF8
$chainsOut   | Export-Csv (Join-Path $OutputDir 'Attack_Chains.csv') -NoTypeInformation -Encoding UTF8
$planOut     | Export-Csv (Join-Path $OutputDir 'Action_Plan.csv') -NoTypeInformation -Encoding UTF8
$planOut     | Export-Csv (Join-Path $OutputDir 'Remediation_Plan.csv') -NoTypeInformation -Encoding UTF8
if ($intel.Count) { $intel | Export-Csv (Join-Path $OutputDir 'Threat_Intel.csv') -NoTypeInformation -Encoding UTF8 }
if ($kev.Count)   { $kev   | Export-Csv (Join-Path $OutputDir 'CISA_KEV_Matches.csv') -NoTypeInformation -Encoding UTF8 }

if ($HasImportExcel) {
    Import-Module ImportExcel
    $xl = Join-Path $OutputDir 'AttackHunt_Workbook.xlsx'
    $planOut     | Export-Excel $xl -WorksheetName 'Action Plan' -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter
    $chainsOut   | Export-Excel $xl -WorksheetName 'Attack Chains' -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter
    $findingsOut | Export-Excel $xl -WorksheetName 'Findings' -AutoSize -FreezeTopRow -BoldTopRow -AutoFilter
    if ($intel.Count) { $intel | Export-Excel $xl -WorksheetName 'Threat Intel' -AutoSize -FreezeTopRow -BoldTopRow }
    Write-Good "Excel workbook: $xl"
}

Write-Host ''
Write-Good "Report:           $reportPath  (prepared by $author, $AuthorTitle)"
Write-Good "Action plan CSV:  $(Join-Path $OutputDir 'Action_Plan.csv')"
Write-Good "Navigator layer:  $(Join-Path $OutputDir 'ATTACK_Navigator_Layer.json')"
$top = $chains | Select-Object -First 5
if ($top) {
    Write-Host "`nTop chains:" -ForegroundColor White
    foreach ($c in $top) { Write-Host ("  {0} {1,-9} {2,-12} {3,-22} {4}" -f $c.ChainId, $c.Priority, $c.Entity, $c.Verdict, $c.Flow) }
}
if ($env:OS -eq 'Windows_NT') { try { Invoke-Item $reportPath } catch {} }
