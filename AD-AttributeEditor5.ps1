<#
.SYNOPSIS
    M365admintools.com - Author Charles Arconi - updated 7/7/2026
    AD Attribute Editor 5.0 - forest-aware bulk attribute editor with what-if preview.

.DESCRIPTION
    Successor to "AD Attribute Editor 4.0.0" (Arconi SoftTools, WinBatch 2009B).

    Workflow:
      1. Resolve the forest root and enumerate every domain partition in the forest.
      2. Pick the target domain (root or any child).
      3. Pick the object class to work on: User, Group, Organizational Unit,
         Computer or Contact.
      4. Pick the attribute from that class's schema.
      5. Choose an action: Set, Clear, Add value, Remove value, or Set if empty.
      6. Choose scope: one object, a list from file, a container, or the whole domain.
      7. Run WHAT-IF. Nothing is written. Every matched object is listed with its
         current value, the proposed value, and whether it would actually change.
      8. Review, then Apply. Live mode is locked until a what-if plan exists, and
         the plan is invalidated the moment any input changes.

    Uses System.DirectoryServices directly. No RSAT and no ActiveDirectory module.

.PARAMETER Server
    Optional domain controller or DNS domain name to bind to for the initial connect.

.EXAMPLE
    .\AD-AttributeEditor5.ps1

.EXAMPLE
    .\AD-AttributeEditor5.ps1 -Server dc01.corp.contoso.com

.NOTES
    Requires Windows PowerShell 5.1 on Windows.
    Run as an account with write permission on the target attribute for live mode.
    Always run what-if against production before applying.
#>

[CmdletBinding()]
param(
    [string]$Server
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.DirectoryServices
[System.Windows.Forms.Application]::EnableVisualStyles()

# ===========================================================================
# State
# ===========================================================================

$script:Ctx = [pscustomobject]@{
    BindServer   = $null      # server or DNS name used for the current bind
    ForestRootNC = $null
    ConfigNC     = $null
    Credential   = $null
    Domains      = @()        # { DnsRoot, NCName, IsRoot }
    CurrentDomain= $null
}

$script:Attributes = @()      # schema attributes for the selected class
$script:Containers = @()      # OU / container DNs in the current domain
$script:Objects    = @()      # loaded objects for single-object mode
$script:Groups     = @()      # loaded groups for group-members mode
$script:Plan       = @()      # what-if plan rows
$script:PlanStamp  = $null

# Attributes that cannot be written through LDAP at all. Hard blocked.
$script:ReadOnlyAttrs = @(
    'objectguid','objectsid','distinguishedname','whencreated','whenchanged',
    'usncreated','usnchanged','memberof','tokengroups','primarygrouptoken',
    'canonicalname','objectcategory','objectclass','samaccounttype',
    'badpasswordtime','badpwdcount','lastlogon','lastlogontimestamp','logoncount',
    'lastlogoff','pwdlastset','ntsecuritydescriptor','instancetype','ncname',
    'createtimestamp','modifytimestamp','subrefs','allowedattributes',
    'allowedattributeseffective','structuralobjectclass','msds-user-account-control-computed'
)

# Attributes that are writable but carry real blast radius. Extra confirmation.
$script:DangerAttrs = @(
    'useraccountcontrol','samaccountname','userprincipalname','unicodepwd',
    'member','primarygroupid','grouptype','accountexpires','msds-supportedencryptiontypes',
    'serviceprincipalname','msds-allowedtodelegateto','admincount','ou','cn','name'
)

# Object class definitions
$script:ClassMap = @{
    'User' = @{
        Schema = 'user'
        Filter = '(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))'
        Naming = 'sAMAccountName'
        Extra  = @('displayName','userPrincipalName')
    }
    'Group' = @{
        Schema = 'group'
        Filter = '(objectCategory=group)'
        Naming = 'sAMAccountName'
        Extra  = @('displayName','description')
    }
    'Organizational Unit' = @{
        Schema = 'organizationalUnit'
        Filter = '(objectCategory=organizationalUnit)'
        Naming = 'ou'
        Extra  = @('description')
    }
    'Computer' = @{
        Schema = 'computer'
        Filter = '(objectCategory=computer)'
        Naming = 'sAMAccountName'
        Extra  = @('dNSHostName','operatingSystem')
    }
    'Contact' = @{
        Schema = 'contact'
        Filter = '(&(objectCategory=person)(objectClass=contact))'
        Naming = 'cn'
        Extra  = @('displayName','mail')
    }
}

# ===========================================================================
# Directory layer
# ===========================================================================

function New-DirEntry {
    param([Parameter(Mandatory)][string]$Path)
    if ($script:Ctx.Credential) {
        $u = $script:Ctx.Credential.UserName
        $p = $script:Ctx.Credential.GetNetworkCredential().Password
        return New-Object System.DirectoryServices.DirectoryEntry(
            $Path, $u, $p, [System.DirectoryServices.AuthenticationTypes]::Secure)
    }
    return New-Object System.DirectoryServices.DirectoryEntry($Path)
}

function Get-BindPath {
    <# Builds LDAP://<server>/<dn>. Server defaults to the selected domain's DNS root. #>
    param([string]$DN)
    $target = if ($script:Ctx.CurrentDomain)  { $script:Ctx.CurrentDomain.DnsRoot }
              elseif ($script:Ctx.BindServer) { $script:Ctx.BindServer }
              else { $null }
    if ($target) { return "LDAP://$target/$DN" }
    return "LDAP://$DN"
}

function Get-RootPath {
    param([string]$DN)
    if ($script:Ctx.BindServer) { return "LDAP://$($script:Ctx.BindServer)/$DN" }
    return "LDAP://$DN"
}

function Get-FirstValue {
    param($Entry, [string]$Name)
    try {
        $c = $Entry.Properties[$Name]
        if ($c -and $c.Count -gt 0) { return [string]$c[0] }
    } catch { }
    return $null
}

function Connect-Forest {
    <#
        Resolves the forest root and every domain partition, by reading crossRef
        objects out of CN=Partitions in the configuration NC. This is the reliable
        way to enumerate child domains without relying on the Forest class, and it
        honours alternate credentials.
    #>
    param([string]$TargetServer)

    $script:Ctx.BindServer = $TargetServer
    $rootPath = if ($TargetServer) { "LDAP://$TargetServer/RootDSE" } else { 'LDAP://RootDSE' }
    $root = New-DirEntry $rootPath

    $script:Ctx.ForestRootNC = Get-FirstValue $root 'rootDomainNamingContext'
    $script:Ctx.ConfigNC     = Get-FirstValue $root 'configurationNamingContext'
    $defaultNC               = Get-FirstValue $root 'defaultNamingContext'

    if (-not $script:Ctx.ConfigNC) {
        throw 'RootDSE did not return configurationNamingContext. Check connectivity and credentials.'
    }

    $partPath = Get-RootPath "CN=Partitions,$($script:Ctx.ConfigNC)"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher((New-DirEntry $partPath))
    # systemFlags bit 2 (FLAG_CR_NTDS_DOMAIN) marks a real domain partition,
    # which excludes the configuration and schema NCs and any app partitions.
    $searcher.Filter = '(&(objectCategory=crossRef)(systemFlags:1.2.840.113556.1.4.803:=2))'
    $searcher.PageSize = 500
    foreach ($p in 'nCName','dnsRoot') { $null = $searcher.PropertiesToLoad.Add($p) }

    $domains = New-Object System.Collections.Generic.List[object]
    $res = $searcher.FindAll()
    try {
        foreach ($r in $res) {
            if (-not $r.Properties.Contains('ncname')) { continue }
            $nc  = [string]$r.Properties['ncname'][0]
            $dns = if ($r.Properties.Contains('dnsroot')) { [string]$r.Properties['dnsroot'][0] } else { $nc }
            $domains.Add([pscustomobject]@{
                DnsRoot = $dns
                NCName  = $nc
                IsRoot  = ($nc -eq $script:Ctx.ForestRootNC)
            })
        }
    } finally { $res.Dispose(); $searcher.Dispose() }

    # Root first, then children alphabetically
    $script:Ctx.Domains = @($domains | Sort-Object @{E={-not $_.IsRoot}}, DnsRoot)

    # Preselect whichever domain we actually bound to
    $sel = $script:Ctx.Domains | Where-Object { $_.NCName -eq $defaultNC } | Select-Object -First 1
    if (-not $sel) { $sel = $script:Ctx.Domains | Select-Object -First 1 }
    $script:Ctx.CurrentDomain = $sel

    return $script:Ctx.Domains
}

function Get-ClassAttribute {
    <# Full schema attribute set for a class, with mandatory / multi-valued flags. #>
    param([Parameter(Mandatory)][string]$ClassName)

    $list = New-Object System.Collections.Generic.List[object]
    try {
        if ($script:Ctx.BindServer) {
            $dc = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::DirectoryServer,
                $script:Ctx.BindServer)
            $schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetSchema($dc)
        } else {
            $schema = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySchema]::GetCurrentSchema()
        }
        $cls = $schema.FindClass($ClassName)

        $mand = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($p in $cls.MandatoryProperties) { $null = $mand.Add($p.Name) }

        foreach ($p in $cls.GetAllProperties()) {
            $n = [string]$p.Name
            $list.Add([pscustomobject]@{
                Name        = $n
                Mandatory   = $mand.Contains($n)
                MultiValued = (-not $p.IsSingleValued)
                Syntax      = [string]$p.Syntax
                Writable    = ($script:ReadOnlyAttrs -notcontains $n.ToLowerInvariant())
                Dangerous   = ($script:DangerAttrs   -contains $n.ToLowerInvariant())
            })
        }
    } catch {
        Write-Verbose "Schema lookup failed for '$ClassName': $($_.Exception.Message)"
        throw "Could not read the schema for class '$ClassName'. $($_.Exception.Message)"
    }

    return @($list | Sort-Object Name -Unique)
}

function Get-Container {
    <# Every OU and container in the current domain, for the container scope picker. #>
    $nc = $script:Ctx.CurrentDomain.NCName
    $searcher = New-Object System.DirectoryServices.DirectorySearcher((New-DirEntry (Get-BindPath $nc)))
    $searcher.Filter      = '(|(objectCategory=organizationalUnit)(objectCategory=container))'
    $searcher.PageSize    = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    $null = $searcher.PropertiesToLoad.Add('distinguishedName')

    $out = New-Object System.Collections.Generic.List[string]
    $out.Add($nc)   # domain root itself
    $res = $searcher.FindAll()
    try {
        foreach ($r in $res) {
            if ($r.Properties.Contains('distinguishedname')) {
                $out.Add([string]$r.Properties['distinguishedname'][0])
            }
        }
    } finally { $res.Dispose(); $searcher.Dispose() }

    return @($out | Sort-Object { ($_ -split ',').Count }, { $_ })
}

function Search-Object {
    <# Generic paged search returning naming attribute plus DN. #>
    param(
        [Parameter(Mandatory)][string]$SearchBase,
        [Parameter(Mandatory)][string]$Filter,
        [Parameter(Mandatory)][string]$NamingAttr,
        [string[]]$Extra = @(),
        [ValidateSet('Base','OneLevel','Subtree')][string]$Scope = 'Subtree',
        [int]$Limit = 0
    )

    $searcher = New-Object System.DirectoryServices.DirectorySearcher((New-DirEntry (Get-BindPath $SearchBase)))
    $searcher.Filter      = $Filter
    $searcher.PageSize    = 1000
    $searcher.SearchScope = [System.DirectoryServices.SearchScope]$Scope
    $searcher.SizeLimit   = 0
    foreach ($p in (@($NamingAttr,'distinguishedName') + $Extra | Select-Object -Unique)) {
        $null = $searcher.PropertiesToLoad.Add($p)
    }

    $out = New-Object System.Collections.Generic.List[object]
    $res = $searcher.FindAll()
    try {
        foreach ($r in $res) {
            if (-not $r.Properties.Contains('distinguishedname')) { continue }
            $dn = [string]$r.Properties['distinguishedname'][0]
            $nk = $NamingAttr.ToLowerInvariant()
            $nm = if ($r.Properties.Contains($nk)) { [string]$r.Properties[$nk][0] } else { ($dn -split ',')[0] -replace '^\w+=','' }
            $out.Add([pscustomobject]@{ Name = $nm; DistinguishedName = $dn })
            if ($Limit -gt 0 -and $out.Count -ge $Limit) { break }
        }
    } finally { $res.Dispose(); $searcher.Dispose() }

    return @($out | Sort-Object Name)
}

function Format-AttrValue {
    param($Values, [string]$Attribute)
    if (-not $Values -or $Values.Count -eq 0) { return '' }
    $r = foreach ($v in $Values) {
        if ($v -is [byte[]]) {
            if     ($Attribute -match 'objectGUID') { ([guid][byte[]]$v).ToString() }
            elseif ($Attribute -match 'objectSid')  { (New-Object System.Security.Principal.SecurityIdentifier([byte[]]$v,0)).Value }
            else { ([System.BitConverter]::ToString([byte[]]$v) -replace '-','') }
        }
        elseif ($v -is [datetime]) { $v.ToString('yyyy-MM-dd HH:mm:ss') }
        else { [string]$v }
    }
    return ($r -join ' | ')
}

function Get-AttrValue {
    param([Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][string]$Attribute)
    try { $null = $Entry.RefreshCache([string[]]@($Attribute)) } catch { }
    return (Format-AttrValue $Entry.Properties[$Attribute] $Attribute)
}

function Expand-Token {
    <#
        Lets the new value reference other attributes of the same object.
        Example:  %sAMAccountName%@contoso.com
                  %givenName%.%sn%
        Unknown tokens resolve to empty.
    #>
    param([string]$Template, [Parameter(Mandatory)]$Entry)

    if (-not $Template -or $Template -notmatch '%') { return $Template }

    $out = $Template
    $seen = @{}
    foreach ($m in [regex]::Matches($Template, '%([A-Za-z0-9\-]+)%')) {
        $a = $m.Groups[1].Value
        if ($seen.ContainsKey($a)) { continue }
        $rep = ''
        try {
            $null = $Entry.RefreshCache([string[]]@($a))
            $v = $Entry.Properties[$a]
            if ($v -and $v.Count -gt 0) { $rep = Format-AttrValue $v $a }
        } catch { }
        $seen[$a] = $rep
        $out = $out.Replace("%$a%", $rep)
    }
    return $out
}

function Set-AttrValue {
    param(
        [Parameter(Mandatory)]$Entry,
        [Parameter(Mandatory)][string]$Attribute,
        [AllowEmptyString()][string]$Value,
        [Parameter(Mandatory)][ValidateSet('Set','Clear','Add','Remove','SetIfEmpty')][string]$Action
    )

    switch ($Action) {
        'Clear' {
            if ($Entry.Properties[$Attribute].Count -gt 0) { $Entry.Properties[$Attribute].Clear() }
        }
        'Add' {
            foreach ($p in ($Value -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $null = $Entry.Properties[$Attribute].Add($p)
            }
        }
        'Remove' {
            foreach ($p in ($Value -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                $idx = -1
                for ($i = 0; $i -lt $Entry.Properties[$Attribute].Count; $i++) {
                    if ([string]$Entry.Properties[$Attribute][$i] -eq $p) { $idx = $i; break }
                }
                if ($idx -ge 0) { $Entry.Properties[$Attribute].RemoveAt($idx) }
            }
        }
        default {
            # Set and SetIfEmpty. SetIfEmpty is filtered out during planning, so
            # anything reaching here is intended to be written.
            if ([string]::IsNullOrEmpty($Value)) {
                if ($Entry.Properties[$Attribute].Count -gt 0) { $Entry.Properties[$Attribute].Clear() }
            }
            elseif ($Value.Contains('|')) {
                $Entry.Properties[$Attribute].Clear()
                foreach ($p in ($Value -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                    $null = $Entry.Properties[$Attribute].Add($p)
                }
            }
            else { $Entry.Properties[$Attribute].Value = $Value }
        }
    }

    $Entry.CommitChanges()
}

function Get-ProposedValue {
    <# Computes what the value would become, without touching the directory. #>
    param([string]$Current, [string]$Proposed, [string]$Action)

    switch ($Action) {
        'Clear'      { return '' }
        'SetIfEmpty' { if ([string]::IsNullOrEmpty($Current)) { return $Proposed } else { return $Current } }
        'Add' {
            $cur = if ($Current) { @($Current -split ' \| ') } else { @() }
            $new = @($Proposed -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            return (@($cur + ($new | Where-Object { $cur -notcontains $_ })) -join ' | ')
        }
        'Remove' {
            $cur = if ($Current) { @($Current -split ' \| ') } else { @() }
            $rm  = @($Proposed -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            return (@($cur | Where-Object { $rm -notcontains $_ }) -join ' | ')
        }
        default {
            if ($Proposed -and $Proposed.Contains('|')) {
                return (@($Proposed -split '\|' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ' | ')
            }
            return $Proposed
        }
    }
}

function Write-AuditLog {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][ValidateSet('WHATIF','CHANGE')][string]$Kind,
        [Parameter(Mandatory)][string]$Name,
        [string]$DN, [string]$Attribute, [string]$OldValue, [string]$NewValue,
        [string]$Action, [string]$Status
    )
    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("**$Kind--$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $sb.AppendLine("Object=$Name")
    $null = $sb.AppendLine("ObjectPath=$DN")
    $null = $sb.AppendLine("Attribute=$Attribute")
    $null = $sb.AppendLine("Action=$Action")
    $null = $sb.AppendLine("OldValue=$OldValue")
    $null = $sb.AppendLine("NewValue=$NewValue")
    $null = $sb.AppendLine("Status=$Status")
    $null = $sb.AppendLine("RunAs=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")
    try { Add-Content -LiteralPath $Path -Value $sb.ToString() -Encoding UTF8 }
    catch { Write-Warning "Log write failed: $($_.Exception.Message)" }
}

function Write-ErrorLog {
    <#
        Appends a full error record to the log file. Used by every catch block
        that reports a failure, so anything shown in a dialog is also captured
        on disk with its type, message, source position and stack trace.
        Falls back to the TEMP folder if the log field is blank, so an error is
        never lost. Never throws.
    #>
    param(
        [Parameter(Mandatory)][string]$Context,
        $ErrorRecord,
        [string]$Message
    )

    $path = ''
    try { $path = $txtLog.Text.Trim() } catch { }
    if (-not $path) { $path = Join-Path ([System.IO.Path]::GetTempPath()) 'ADAttributeEditor.log' }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine("**ERROR--$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $null = $sb.AppendLine("Context=$Context")
    if ($Message) { $null = $sb.AppendLine("Message=$Message") }
    if ($ErrorRecord) {
        $ex = $ErrorRecord.Exception
        if ($ex) {
            $null = $sb.AppendLine("Type=$($ex.GetType().FullName)")
            if (-not $Message) { $null = $sb.AppendLine("Message=$($ex.Message)") }
        }
        if ($ErrorRecord.InvocationInfo -and $ErrorRecord.InvocationInfo.PositionMessage) {
            $null = $sb.AppendLine("Position=$($ErrorRecord.InvocationInfo.PositionMessage)")
        }
        if ($ErrorRecord.ScriptStackTrace) {
            $null = $sb.AppendLine("StackTrace=$($ErrorRecord.ScriptStackTrace)")
        }
    }
    $null = $sb.AppendLine("RunAs=$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)")

    try { Add-Content -LiteralPath $path -Value $sb.ToString() -Encoding UTF8 }
    catch { Write-Warning "Error-log write failed: $($_.Exception.Message)" }
}

# ===========================================================================
# UI
#
# Layout notes:
#   Designed at 936 pixels of content width, which fits a 1024x768 console or
#   a small RDP session. The content sits in a scrolling panel; the action bar
#   sits in a fixed table row, so RUN WHAT-IF, APPLY LIVE, Export CSV and
#   Close are reachable at any window size. Startup size is clamped to the
#   working area of the monitor the form lands on.
# ===========================================================================

$form               = New-Object System.Windows.Forms.Form
$form.Text          = 'AD Attribute Editor 5.0'
$form.StartPosition = 'CenterScreen'
$form.Font          = New-Object System.Drawing.Font('Segoe UI', 9)
$form.MinimumSize   = New-Object System.Drawing.Size(560, 300)
$form.FormBorderStyle = 'Sizable'
$form.MaximizeBox   = $true
$form.KeyPreview    = $true
# No automatic rescaling. Absolute coordinates stay where they are put, which
# keeps the layout predictable on consoles running at 125 or 150 percent DPI.
$form.AutoScaleMode = 'None'

$fTitle = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
$fBold  = New-Object System.Drawing.Font('Segoe UI', 9,  [System.Drawing.FontStyle]::Bold)
$fSmall = New-Object System.Drawing.Font('Segoe UI', 8)
$fMono  = New-Object System.Drawing.Font('Consolas', 10, [System.Drawing.FontStyle]::Bold)
$cBlue  = [System.Drawing.Color]::FromArgb(0,0,190)
$cRed   = [System.Drawing.Color]::FromArgb(190,0,0)
$cGreen = [System.Drawing.Color]::FromArgb(0,120,0)
$cGray  = [System.Drawing.Color]::FromArgb(110,110,110)

function New-Lbl {
    param($Text,$X,$Y,$W=120,$H=18,$Font=$null,$Color=$null)
    $l = New-Object System.Windows.Forms.Label
    $l.Text = $Text
    $l.Location = New-Object System.Drawing.Point($X,$Y)
    $l.Size = New-Object System.Drawing.Size($W,$H)
    if ($Font)  { $l.Font = $Font }
    if ($Color) { $l.ForeColor = $Color }
    return $l
}

# --- Explicit two row layout.
# Row 0 takes all remaining height and holds the scrolling content.
# Row 1 is a fixed 108 pixel strip and holds the log path and the action bar.
# A TableLayoutPanel is used instead of Dock=Fill plus Dock=Bottom because
# dock ordering between siblings depends on z-order, which is easy to get
# wrong. Rows are unambiguous: the action bar cannot be pushed off screen.
$tbl = New-Object System.Windows.Forms.TableLayoutPanel
$tbl.Dock = 'Fill'
$tbl.ColumnCount = 1
$tbl.RowCount = 2
$null = $tbl.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$null = $tbl.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
$null = $tbl.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 108)))
$form.Controls.Add($tbl)

$pnlMain = New-Object System.Windows.Forms.Panel
$pnlMain.Dock = 'Fill'
$pnlMain.AutoScroll = $true
$tbl.Controls.Add($pnlMain, 0, 0)

$pnlBottom = New-Object System.Windows.Forms.Panel
$pnlBottom.Dock = 'Fill'
$tbl.Controls.Add($pnlBottom, 0, 1)

# --- Header ---
$pnlMain.Controls.Add((New-Lbl 'M365 Admin Tools' 40 6 250 24 $fTitle $cBlue))
$pnlMain.Controls.Add((New-Lbl 'Active Directory Attribute Editor' 590 6 358 24 $fTitle))
#$pnlMain.Controls.Add((New-Lbl 'Charles Arconi  |  m365admintools.com' 590 31 358 15 $fSmall $cGray))
$lnkSite = New-Object System.Windows.Forms.LinkLabel
$lnkSite.Text             = 'Charles Arconi  |  m365admintools.com'
$lnkSite.Location         = New-Object System.Drawing.Point(590,31)
$lnkSite.Size             = New-Object System.Drawing.Size(358,15)
$lnkSite.Font             = $fSmall
$lnkSite.ForeColor        = $cGray
$lnkSite.LinkColor        = $cBlue
$lnkSite.ActiveLinkColor  = $cBlue
$lnkSite.VisitedLinkColor = $cBlue
$lnkSite.LinkBehavior     = [System.Windows.Forms.LinkBehavior]::HoverUnderline
$lnkSite.AutoSize         = $false

$siteLinkText = 'm365admintools.com'
$lnkSite.LinkArea = New-Object System.Windows.Forms.LinkArea(
    $lnkSite.Text.IndexOf($siteLinkText), $siteLinkText.Length)

$lnkSite.Add_LinkClicked({
    try {
        $lnkSite.LinkVisited = $true
        Start-Process 'https://m365admintools.com'
    } catch {
        Write-ErrorLog -Context 'Open m365admintools.com link' -ErrorRecord $_
        Set-Status "Could not open browser: $($_.Exception.Message)"
    }
})
$pnlMain.Controls.Add($lnkSite)

# --- 1. Target ---
$grpTarget = New-Object System.Windows.Forms.GroupBox
$grpTarget.Text = ' 1. Target '
$grpTarget.ForeColor = $cBlue
$grpTarget.Location = New-Object System.Drawing.Point(12,52)
$grpTarget.Size = New-Object System.Drawing.Size(936,92)
$pnlMain.Controls.Add($grpTarget)

$grpTarget.Controls.Add((New-Lbl 'Forest root' 12 25 70))
$txtForest = New-Object System.Windows.Forms.TextBox
$txtForest.Location = New-Object System.Drawing.Point(86,22)
$txtForest.Size = New-Object System.Drawing.Size(230,22)
$txtForest.ReadOnly = $true
$txtForest.ForeColor = $cBlue
$grpTarget.Controls.Add($txtForest)

$grpTarget.Controls.Add((New-Lbl 'Domain' 326 25 50))
$cmbDomain = New-Object System.Windows.Forms.ComboBox
$cmbDomain.Location = New-Object System.Drawing.Point(380,22)
$cmbDomain.Size = New-Object System.Drawing.Size(200,22)
$cmbDomain.DropDownStyle = 'DropDownList'
$grpTarget.Controls.Add($cmbDomain)

$btnCreds = New-Object System.Windows.Forms.Button
$btnCreds.Text = 'Credentials...'
$btnCreds.Location = New-Object System.Drawing.Point(590,21)
$btnCreds.Size = New-Object System.Drawing.Size(88,24)
$grpTarget.Controls.Add($btnCreds)

$btnConnect = New-Object System.Windows.Forms.Button
$btnConnect.Text = 'Reconnect'
$btnConnect.Location = New-Object System.Drawing.Point(682,21)
$btnConnect.Size = New-Object System.Drawing.Size(82,24)
$grpTarget.Controls.Add($btnConnect)

$grpTarget.Controls.Add((New-Lbl 'Object class' 12 57 74))
$cmbClass = New-Object System.Windows.Forms.ComboBox
$cmbClass.Location = New-Object System.Drawing.Point(86,54)
$cmbClass.Size = New-Object System.Drawing.Size(230,22)
$cmbClass.DropDownStyle = 'DropDownList'
foreach ($k in 'User','Group','Organizational Unit','Computer','Contact') { $null = $cmbClass.Items.Add($k) }
$grpTarget.Controls.Add($cmbClass)

$lblDomainInfo = New-Lbl '' 326 57 600 16 $fSmall $cGray
$grpTarget.Controls.Add($lblDomainInfo)

# --- 2. Attribute ---
$grpAttr = New-Object System.Windows.Forms.GroupBox
$grpAttr.Text = ' 2. Attribute '
$grpAttr.ForeColor = $cBlue
$grpAttr.Location = New-Object System.Drawing.Point(12,152)
$grpAttr.Size = New-Object System.Drawing.Size(330,382)
$pnlMain.Controls.Add($grpAttr)

$txtAttrFilter = New-Object System.Windows.Forms.TextBox
$txtAttrFilter.Location = New-Object System.Drawing.Point(10,22)
$txtAttrFilter.Size = New-Object System.Drawing.Size(200,22)
$grpAttr.Controls.Add($txtAttrFilter)

$chkWritableOnly = New-Object System.Windows.Forms.CheckBox
$chkWritableOnly.Text = 'Writable'
$chkWritableOnly.Location = New-Object System.Drawing.Point(216,22)
$chkWritableOnly.Size = New-Object System.Drawing.Size(98,22)
$chkWritableOnly.Checked = $true
$grpAttr.Controls.Add($chkWritableOnly)

$lstAttr = New-Object System.Windows.Forms.ListBox
$lstAttr.Location = New-Object System.Drawing.Point(10,50)
$lstAttr.Size = New-Object System.Drawing.Size(304,276)
$lstAttr.IntegralHeight = $false
$grpAttr.Controls.Add($lstAttr)

$lblAttrMeta = New-Lbl '' 10 332 304 30 $fSmall
$grpAttr.Controls.Add($lblAttrMeta)

# --- 3. Change ---
$grpChange = New-Object System.Windows.Forms.GroupBox
$grpChange.Text = ' 3. Change '
$grpChange.ForeColor = $cBlue
$grpChange.Location = New-Object System.Drawing.Point(352,152)
$grpChange.Size = New-Object System.Drawing.Size(596,150)
$pnlMain.Controls.Add($grpChange)

$grpChange.Controls.Add((New-Lbl 'Selected' 12 25 58))
$txtSelAttr = New-Object System.Windows.Forms.TextBox
$txtSelAttr.Location = New-Object System.Drawing.Point(74,22)
$txtSelAttr.Size = New-Object System.Drawing.Size(250,24)
$txtSelAttr.ReadOnly = $true
$txtSelAttr.Font = $fMono
$txtSelAttr.ForeColor = $cBlue
$grpChange.Controls.Add($txtSelAttr)

$grpChange.Controls.Add((New-Lbl 'Action' 334 25 44))
$cmbAction = New-Object System.Windows.Forms.ComboBox
$cmbAction.Location = New-Object System.Drawing.Point(382,22)
$cmbAction.Size = New-Object System.Drawing.Size(140,22)
$cmbAction.DropDownStyle = 'DropDownList'
foreach ($a in 'Set','Clear','Add value','Remove value','Set if empty') { $null = $cmbAction.Items.Add($a) }
$cmbAction.SelectedIndex = 0
$grpChange.Controls.Add($cmbAction)

$grpChange.Controls.Add((New-Lbl 'Current' 12 53 64))
$txtCurrent = New-Object System.Windows.Forms.TextBox
$txtCurrent.Location = New-Object System.Drawing.Point(74,50)
$txtCurrent.Size = New-Object System.Drawing.Size(510,22)
$txtCurrent.ReadOnly = $true
$txtCurrent.BackColor = [System.Drawing.Color]::FromArgb(240,240,240)
$txtCurrent.ForeColor = $cGray
$grpChange.Controls.Add($txtCurrent)

$grpChange.Controls.Add((New-Lbl 'New value' 12 85 64))
$txtValue = New-Object System.Windows.Forms.TextBox
$txtValue.Location = New-Object System.Drawing.Point(74,82)
$txtValue.Size = New-Object System.Drawing.Size(510,22)
$grpChange.Controls.Add($txtValue)

$grpChange.Controls.Add((New-Lbl 'Pipe separates multiple values. %attributeName% pulls another attribute from the same object, for example %sAMAccountName%@contoso.com' 74 108 510 30 $fSmall $cBlue))

# --- 4. Scope ---
$grpScope = New-Object System.Windows.Forms.GroupBox
$grpScope.Text = ' 4. Scope '
$grpScope.ForeColor = $cBlue
$grpScope.Location = New-Object System.Drawing.Point(352,308)
$grpScope.Size = New-Object System.Drawing.Size(596,226)
$pnlMain.Controls.Add($grpScope)

$rbOne = New-Object System.Windows.Forms.RadioButton
$rbOne.Text = 'Single object'
$rbOne.Location = New-Object System.Drawing.Point(12,22)
$rbOne.Size = New-Object System.Drawing.Size(118,22)
$rbOne.Checked = $true
$grpScope.Controls.Add($rbOne)

$cmbObject = New-Object System.Windows.Forms.ComboBox
$cmbObject.Location = New-Object System.Drawing.Point(134,21)
$cmbObject.Size = New-Object System.Drawing.Size(290,22)
$cmbObject.DropDownStyle = 'DropDown'
$cmbObject.AutoCompleteMode = 'SuggestAppend'
$cmbObject.AutoCompleteSource = 'ListItems'
$grpScope.Controls.Add($cmbObject)

$btnLoadObjects = New-Object System.Windows.Forms.Button
$btnLoadObjects.Text = 'Load'
$btnLoadObjects.Location = New-Object System.Drawing.Point(430,20)
$btnLoadObjects.Size = New-Object System.Drawing.Size(62,24)
$grpScope.Controls.Add($btnLoadObjects)

$lblObjCount = New-Lbl '' 498 25 88 16 $fSmall $cGray
$grpScope.Controls.Add($lblObjCount)

$rbFile = New-Object System.Windows.Forms.RadioButton
$rbFile.Text = 'List from file'
$rbFile.Location = New-Object System.Drawing.Point(12,50)
$rbFile.Size = New-Object System.Drawing.Size(118,22)
$grpScope.Controls.Add($rbFile)

$txtFile = New-Object System.Windows.Forms.TextBox
$txtFile.Location = New-Object System.Drawing.Point(134,49)
$txtFile.Size = New-Object System.Drawing.Size(290,22)
$txtFile.Enabled = $false
$grpScope.Controls.Add($txtFile)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = 'Browse'
$btnBrowse.Location = New-Object System.Drawing.Point(430,48)
$btnBrowse.Size = New-Object System.Drawing.Size(62,24)
$btnBrowse.Enabled = $false
$grpScope.Controls.Add($btnBrowse)

$chkPerLine = New-Object System.Windows.Forms.CheckBox
$chkPerLine.Text = 'Value per line'
$chkPerLine.Location = New-Object System.Drawing.Point(498,50)
$chkPerLine.Size = New-Object System.Drawing.Size(92,22)
$chkPerLine.Enabled = $false
$grpScope.Controls.Add($chkPerLine)

$rbOU = New-Object System.Windows.Forms.RadioButton
$rbOU.Text = 'Container'
$rbOU.Location = New-Object System.Drawing.Point(12,78)
$rbOU.Size = New-Object System.Drawing.Size(118,22)
$grpScope.Controls.Add($rbOU)

$cmbOU = New-Object System.Windows.Forms.ComboBox
$cmbOU.Location = New-Object System.Drawing.Point(134,77)
$cmbOU.Size = New-Object System.Drawing.Size(290,22)
$cmbOU.DropDownStyle = 'DropDown'
$cmbOU.AutoCompleteMode = 'SuggestAppend'
$cmbOU.AutoCompleteSource = 'ListItems'
$cmbOU.Enabled = $false
$grpScope.Controls.Add($cmbOU)

$chkSubtree = New-Object System.Windows.Forms.CheckBox
$chkSubtree.Text = 'Include child containers'
$chkSubtree.Location = New-Object System.Drawing.Point(430,78)
$chkSubtree.Size = New-Object System.Drawing.Size(158,22)
$chkSubtree.Checked = $true
$chkSubtree.Enabled = $false
$grpScope.Controls.Add($chkSubtree)

$rbGroup = New-Object System.Windows.Forms.RadioButton
$rbGroup.Text = 'Members of group'
$rbGroup.Location = New-Object System.Drawing.Point(12,106)
$rbGroup.Size = New-Object System.Drawing.Size(126,22)
$grpScope.Controls.Add($rbGroup)

$cmbGroup = New-Object System.Windows.Forms.ComboBox
$cmbGroup.Location = New-Object System.Drawing.Point(134,105)
$cmbGroup.Size = New-Object System.Drawing.Size(250,22)
$cmbGroup.DropDownStyle = 'DropDown'
$cmbGroup.AutoCompleteMode = 'SuggestAppend'
$cmbGroup.AutoCompleteSource = 'ListItems'
$cmbGroup.Enabled = $false
$grpScope.Controls.Add($cmbGroup)

$btnLoadGroups = New-Object System.Windows.Forms.Button
$btnLoadGroups.Text = 'Load'
$btnLoadGroups.Location = New-Object System.Drawing.Point(390,104)
$btnLoadGroups.Size = New-Object System.Drawing.Size(52,24)
$btnLoadGroups.Enabled = $false
$grpScope.Controls.Add($btnLoadGroups)

$lblMemberCount = New-Lbl '' 448 109 140 16 $fSmall $cGray
$grpScope.Controls.Add($lblMemberCount)

$chkNested = New-Object System.Windows.Forms.CheckBox
$chkNested.Text = 'Include members of nested groups'
$chkNested.Location = New-Object System.Drawing.Point(134,129)
$chkNested.Size = New-Object System.Drawing.Size(238,20)
$chkNested.Font = $fSmall
$chkNested.Enabled = $false
$grpScope.Controls.Add($chkNested)

$grpScope.Controls.Add((New-Lbl 'Members are matched to the object class chosen in section 2.' 380 131 210 16 $fSmall $cBlue))

$rbDomain = New-Object System.Windows.Forms.RadioButton
$rbDomain.Text = 'Entire domain'
$rbDomain.Location = New-Object System.Drawing.Point(12,154)
$rbDomain.Size = New-Object System.Drawing.Size(118,22)
$rbDomain.ForeColor = $cRed
$grpScope.Controls.Add($rbDomain)

$grpScope.Controls.Add((New-Lbl 'Every matching object in the domain. What-if is mandatory before this can be applied.' 134 156 450 16 $fSmall $cRed))

$grpScope.Controls.Add((New-Lbl 'With "Value per line" ticked, each line of the file is: name<space>value. Otherwise one name per line and the New value box applies to all.' 12 180 574 32 $fSmall $cGray))

# --- 5. Plan and results ---
$grpRes = New-Object System.Windows.Forms.GroupBox
$grpRes.Text = ' 5. Plan and results '
$grpRes.ForeColor = $cBlue
$grpRes.Location = New-Object System.Drawing.Point(12,542)
$grpRes.Size = New-Object System.Drawing.Size(936,158)
$pnlMain.Controls.Add($grpRes)

$lvPlan = New-Object System.Windows.Forms.ListView
$lvPlan.Location = New-Object System.Drawing.Point(10,20)
$lvPlan.Size = New-Object System.Drawing.Size(916,104)
$lvPlan.View = 'Details'
$lvPlan.FullRowSelect = $true
$lvPlan.GridLines = $true
$null = $lvPlan.Columns.Add('Object',    140)
$null = $lvPlan.Columns.Add('Attribute', 110)
$null = $lvPlan.Columns.Add('Current',   190)
$null = $lvPlan.Columns.Add('Proposed',  190)
$null = $lvPlan.Columns.Add('Effect',     90)
$null = $lvPlan.Columns.Add('Status',     80)
$null = $lvPlan.Columns.Add('DN',        360)
$grpRes.Controls.Add($lvPlan)

$lblSummary = New-Lbl '' 10 130 916 20 $fBold
$grpRes.Controls.Add($lblSummary)

# --- Action bar contents ---
$progress = New-Object System.Windows.Forms.ProgressBar
$progress.Location = New-Object System.Drawing.Point(12,4)
$progress.Size = New-Object System.Drawing.Size(936,12)
$progress.Anchor = 'Top,Left,Right'
$pnlBottom.Controls.Add($progress)

$pnlBottom.Controls.Add((New-Lbl 'Log' 12 24 26 16 $fSmall))
$txtLog = New-Object System.Windows.Forms.TextBox
$txtLog.Location = New-Object System.Drawing.Point(42,21)
$txtLog.Size = New-Object System.Drawing.Size(380,22)
$txtLog.Anchor = 'Top,Left'
$txtLog.Text = Join-Path $env:USERPROFILE 'Documents\ADAttributeEditor.log'
$pnlBottom.Controls.Add($txtLog)

$btnOpenLog = New-Object System.Windows.Forms.Button
$btnOpenLog.Text = 'Open'
$btnOpenLog.Location = New-Object System.Drawing.Point(428,20)
$btnOpenLog.Size = New-Object System.Drawing.Size(58,24)
$btnOpenLog.Anchor = 'Top,Left'
$pnlBottom.Controls.Add($btnOpenLog)

$lblStatus = New-Lbl 'Ready' 12 48 700 16 $fSmall
$lblStatus.Anchor = 'Top,Left,Right'
$pnlBottom.Controls.Add($lblStatus)

# Buttons flow from the right edge inward, so no absolute X coordinate can
# put them out of reach at any window width.
$flowBtn = New-Object System.Windows.Forms.FlowLayoutPanel
$flowBtn.Dock = 'Bottom'
$flowBtn.Height = 44
$flowBtn.FlowDirection = 'RightToLeft'
$flowBtn.WrapContents = $false
$flowBtn.Padding = New-Object System.Windows.Forms.Padding(8,6,10,6)
$pnlBottom.Controls.Add($flowBtn)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = 'Close'
$btnClose.Size = New-Object System.Drawing.Size(86,28)
$flowBtn.Controls.Add($btnClose)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Text = 'Export CSV'
$btnExport.Size = New-Object System.Drawing.Size(96,28)
$flowBtn.Controls.Add($btnExport)

$btnApply = New-Object System.Windows.Forms.Button
$btnApply.Text = 'APPLY LIVE  (F6)'
$btnApply.Size = New-Object System.Drawing.Size(136,28)
$btnApply.Font = $fBold
$btnApply.ForeColor = $cRed
$btnApply.Enabled = $false
$flowBtn.Controls.Add($btnApply)

$btnWhatIf = New-Object System.Windows.Forms.Button
$btnWhatIf.Text = 'RUN WHAT-IF  (F5)'
$btnWhatIf.Size = New-Object System.Drawing.Size(144,28)
$btnWhatIf.Font = $fBold
$flowBtn.Controls.Add($btnWhatIf)

# --- Section captions: bold the group box caption only ---
# A GroupBox caption is painted with the control's own Font, so setting the box
# to bold also bolds every child that has no font of its own. Each child's
# current font is captured first and reassigned afterwards, which pins it and
# leaves only the caption bold. Children with an explicit font (small hint
# labels, the monospace grid) keep theirs.
foreach ($g in @($grpTarget, $grpAttr, $grpChange, $grpScope, $grpRes)) {
    $kids  = @($g.Controls)
    $fonts = @($kids | ForEach-Object { $_.Font })
    $g.Font = $fBold
    for ($i = 0; $i -lt $kids.Count; $i++) { $kids[$i].Font = $fonts[$i] }
}

# --- Size the window to fit the screen it opens on ---
$designW = 976
$designH = 824
try {
    $wa = [System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea
    $w = [Math]::Min($designW, [Math]::Max(560, $wa.Width  - 40))
    $h = [Math]::Min($designH, [Math]::Max(300, $wa.Height - 40))
} catch {
    $w = $designW; $h = $designH
}
$form.Size = New-Object System.Drawing.Size($w, $h)

# Re-clamp once the form is on screen, against the monitor it actually landed
# on rather than the primary one.
$form.Add_Shown({
    try {
        $sc = [System.Windows.Forms.Screen]::FromControl($form).WorkingArea
        $nw = [Math]::Min($form.Width,  [Math]::Max(560, $sc.Width  - 40))
        $nh = [Math]::Min($form.Height, [Math]::Max(300, $sc.Height - 40))
        if ($nw -ne $form.Width -or $nh -ne $form.Height) {
            $form.Size = New-Object System.Drawing.Size($nw, $nh)
        }
        if ($form.Left -lt $sc.Left) { $form.Left = $sc.Left + 10 }
        if ($form.Top  -lt $sc.Top)  { $form.Top  = $sc.Top  + 10 }
    } catch { }
})

# ===========================================================================
# UI helpers
# ===========================================================================

function Set-Status {
    param([string]$Text)
    $lblStatus.Text = $Text
    [System.Windows.Forms.Application]::DoEvents()
}

function Invalidate-Plan {
    param([string]$Reason = '')
    $script:Plan = @()
    $script:PlanStamp = $null
    $btnApply.Enabled = $false
    if ($Reason) { $lblSummary.Text = "Plan cleared: $Reason. Run what-if again."; $lblSummary.ForeColor = $cGray }
}

function Get-LdapFilterEscape {
    <#
        Escapes a value for use inside an LDAP search filter, per RFC 4515.
        Hex escapes are used rather than backslash doubling, because a literal
        backslash is legal in a distinguished name (for example
        CN=Smith\, John,OU=...) and only the \5c form is valid in a filter.
    #>
    param([string]$Value)
    if ($null -eq $Value) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Value.ToCharArray()) {
        switch ($ch) {
            '\'     { $null = $sb.Append('\5c') }
            '('     { $null = $sb.Append('\28') }
            ')'     { $null = $sb.Append('\29') }
            '*'     { $null = $sb.Append('\2a') }
            "`0"    { $null = $sb.Append('\00') }
            default { $null = $sb.Append($ch) }
        }
    }
    return $sb.ToString()
}

function Get-SelectedGroupDN {
    <# Resolves the group named in the group box to its distinguished name. #>
    if (-not $script:Ctx.CurrentDomain) { return $null }
    $name = $cmbGroup.Text.Trim()
    if (-not $name) { return $null }

    $hit = $script:Groups | Where-Object { $_.Name -eq $name } | Select-Object -First 1
    if ($hit) { return $hit.DistinguishedName }

    # Not in the cached list, so look it up. Accept a full DN typed directly.
    if ($name -match '^\s*(CN|OU)=') { return $name }
    $esc = Get-LdapFilterEscape $name
    $f = "(&(objectCategory=group)(|(sAMAccountName=$esc)(cn=$esc)))"
    $g = (Search-Object -SearchBase $script:Ctx.CurrentDomain.NCName -Filter $f `
                        -NamingAttr 'sAMAccountName' -Limit 1) | Select-Object -First 1
    if ($g) { return $g.DistinguishedName }
    return $null
}

function Get-GroupMemberFilter {
    <#
        Builds an LDAP filter selecting members of $GroupDN that also match the
        object class chosen in section 2.

        A memberOf search is used rather than reading the group's member
        attribute, because the server does the work: it pages normally, needs no
        range retrieval on groups over 1500 members, and filters to the wanted
        class in the same query. With -Nested the matching-rule-in-chain OID
        1.2.840.113556.1.4.1941 walks nested groups on the server as well.

        Caveat: memberOf does not include members whose PRIMARY group is this
        group (typically Domain Users). Those are reported separately.
    #>
    param(
        [Parameter(Mandatory)][string]$GroupDN,
        [Parameter(Mandatory)][string]$ClassFilter,
        [switch]$Nested
    )
    $esc = Get-LdapFilterEscape $GroupDN
    $rule = if ($Nested) { "memberOf:1.2.840.113556.1.4.1941:=$esc" } else { "memberOf=$esc" }
    return "(&$ClassFilter($rule))"
}

function Update-MemberCount {
    <# Shows how many members of the selected class are in the chosen group. #>
    if (-not $lblMemberCount) { return }
    $lblMemberCount.ForeColor = $cGray

    if (-not $rbGroup.Checked)          { $lblMemberCount.Text = ''; return }
    if (-not $script:Ctx.CurrentDomain) { $lblMemberCount.Text = '(not connected)'; return }
    if (-not $cmbClass.SelectedItem)    { $lblMemberCount.Text = ''; return }
    if (-not $cmbGroup.Text.Trim())     { $lblMemberCount.Text = '(select a group)'; return }

    try {
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        Set-Status 'Counting group members ...'
        $dn = Get-SelectedGroupDN
        if (-not $dn) { $lblMemberCount.Text = '(group not found)'; return }

        $def = $script:ClassMap[[string]$cmbClass.SelectedItem]
        $f = Get-GroupMemberFilter -GroupDN $dn -ClassFilter $def.Filter -Nested:$chkNested.Checked
        $m = Search-Object -SearchBase $script:Ctx.CurrentDomain.NCName -Filter $f -NamingAttr $def.Naming

        $n = @($m).Count
        $lblMemberCount.Text = "$n $([string]$cmbClass.SelectedItem) member(s)"
        if ($n -gt 0) { $lblMemberCount.ForeColor = $cBlue }
        Set-Status "$n matching member(s) in the selected group."
    } catch {
        $lblMemberCount.Text = '(count failed)'
        Write-ErrorLog -Context "Update-MemberCount ($($cmbGroup.Text.Trim()))" -ErrorRecord $_
        Set-Status $_.Exception.Message
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

function Update-CurrentValue {
    # Fills the read-only Current box with the selected object's existing value
    # for the selected attribute. Only meaningful in single-object scope, since
    # the other scopes act on many objects with no single current value.
    if (-not $txtCurrent) { return }
    $txtCurrent.ForeColor = $cGray

    if (-not $rbOne.Checked)             { $txtCurrent.Text = '(single-object scope only)'; return }
    $attr = $txtSelAttr.Text.Trim()
    if (-not $attr)                      { $txtCurrent.Text = ''; return }
    if (-not $script:Ctx.CurrentDomain)  { $txtCurrent.Text = '(not connected)'; return }
    if (-not $cmbClass.SelectedItem)     { $txtCurrent.Text = ''; return }
    $name = $cmbObject.Text.Trim()
    if (-not $name)                      { $txtCurrent.Text = '(select an object)'; return }

    $def = $script:ClassMap[[string]$cmbClass.SelectedItem]
    $nc  = $script:Ctx.CurrentDomain.NCName

    try {
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $hit = $script:Objects | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $hit) {
            $esc = $name -replace '([\\\*\(\)\0])','\$1'
            $f = "(&$($def.Filter)($($def.Naming)=$esc))"
            $hit = (Search-Object -SearchBase $nc -Filter $f -NamingAttr $def.Naming -Limit 1) | Select-Object -First 1
        }
        if (-not $hit) { $txtCurrent.Text = '(object not found)'; return }

        $de  = New-DirEntry (Get-BindPath $hit.DistinguishedName)
        $val = Get-AttrValue -Entry $de -Attribute $attr
        $de.Close()

        if ([string]::IsNullOrEmpty($val)) {
            $txtCurrent.Text = '(empty)'
        } else {
            $txtCurrent.Text = $val
            $txtCurrent.ForeColor = [System.Drawing.Color]::Black
        }
    } catch {
        $txtCurrent.Text = "(unable to read: $($_.Exception.Message))"
        Write-ErrorLog -Context "Update-CurrentValue ($name / $attr)" -ErrorRecord $_
    } finally {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
    }
}

function Get-ActionKey {
    switch ($cmbAction.Text) {
        'Clear'        { 'Clear' }
        'Add value'    { 'Add' }
        'Remove value' { 'Remove' }
        'Set if empty' { 'SetIfEmpty' }
        default        { 'Set' }
    }
}

function Update-AttrList {
    $f = $txtAttrFilter.Text.Trim()
    $lstAttr.BeginUpdate()
    $lstAttr.Items.Clear()
    foreach ($a in $script:Attributes) {
        if ($chkWritableOnly.Checked -and -not $a.Writable) { continue }
        if ($f -and $a.Name -notlike "*$f*") { continue }
        $null = $lstAttr.Items.Add($a.Name)
    }
    $lstAttr.EndUpdate()
}

function Load-Class {
    if (-not $script:Ctx.CurrentDomain) { return }
    if (-not $cmbClass.SelectedItem) { return }
    $def = $script:ClassMap[[string]$cmbClass.SelectedItem]
    try {
        Set-Status "Reading schema for class '$($def.Schema)' ..."
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $script:Attributes = Get-ClassAttribute -ClassName $def.Schema
        $txtSelAttr.Text = ''
        $lblAttrMeta.Text = ''
        if ($txtCurrent) { $txtCurrent.Text = ''; $txtCurrent.ForeColor = $cGray }
        Update-AttrList
        Set-Status "$($script:Attributes.Count) attributes on '$($def.Schema)'."
    } catch {
        Set-Status $_.Exception.Message
        Write-ErrorLog -Context 'Load-Class (schema read)' -ErrorRecord $_
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Schema','OK','Error') | Out-Null
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
    Invalidate-Plan
}

function Load-Domain {
    if (-not $script:Ctx.CurrentDomain) { return }
    try {
        Set-Status "Loading containers in $($script:Ctx.CurrentDomain.DnsRoot) ..."
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $script:Containers = Get-Container
        $cmbOU.BeginUpdate(); $cmbOU.Items.Clear()
        foreach ($c in $script:Containers) { $null = $cmbOU.Items.Add($c) }
        $cmbOU.EndUpdate()
        if ($cmbOU.Items.Count) { $cmbOU.SelectedIndex = 0 }
        $lblDomainInfo.Text = "$($script:Ctx.CurrentDomain.NCName)   ($($script:Containers.Count) containers)"
        $cmbObject.Items.Clear(); $lblObjCount.Text = ''
        Set-Status "Domain ready: $($script:Ctx.CurrentDomain.DnsRoot)"
    } catch {
        Set-Status $_.Exception.Message
        Write-ErrorLog -Context 'Load-Domain (containers)' -ErrorRecord $_
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
    Load-Class
}

function Initialize-Session {
    try {
        Set-Status 'Connecting to forest ...'
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $null = Connect-Forest -TargetServer $script:Ctx.BindServer

        $txtForest.Text = $script:Ctx.ForestRootNC
        $cmbDomain.BeginUpdate(); $cmbDomain.Items.Clear()
        foreach ($d in $script:Ctx.Domains) {
            $tag = if ($d.IsRoot) { "$($d.DnsRoot)   [forest root]" } else { $d.DnsRoot }
            $null = $cmbDomain.Items.Add($tag)
        }
        $cmbDomain.EndUpdate()

        $idx = [array]::IndexOf(@($script:Ctx.Domains | ForEach-Object { $_.NCName }),
                                $script:Ctx.CurrentDomain.NCName)
        $cmbDomain.SelectedIndex = [Math]::Max($idx, 0)

        if (-not $cmbClass.SelectedItem) { $cmbClass.SelectedIndex = 0 }
        Set-Status "Forest connected. $($script:Ctx.Domains.Count) domain(s) found."
    } catch {
        Set-Status "Connect failed: $($_.Exception.Message)"
        Write-ErrorLog -Context 'Initialize-Session (forest connect)' -ErrorRecord $_
        [System.Windows.Forms.MessageBox]::Show(
            "Could not enumerate the forest.`r`n`r`n$($_.Exception.Message)",
            'Not connected','OK','Warning') | Out-Null
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
}

function Get-TargetList {
    <# Resolves the chosen scope into a list of { Name, DistinguishedName, Value }. #>
    $def = $script:ClassMap[[string]$cmbClass.SelectedItem]
    $nc  = $script:Ctx.CurrentDomain.NCName
    $out = New-Object System.Collections.Generic.List[object]

    if ($rbOne.Checked) {
        $name = $cmbObject.Text.Trim()
        if (-not $name) { throw 'No object selected. Pick one from the dropdown or type its name.' }
        $hit = $script:Objects | Where-Object { $_.Name -eq $name } | Select-Object -First 1
        if (-not $hit) {
            $esc = $name -replace '([\\\*\(\)\0])','\$1'
            $f = "(&$($def.Filter)($($def.Naming)=$esc))"
            $hit = (Search-Object -SearchBase $nc -Filter $f -NamingAttr $def.Naming -Limit 1) | Select-Object -First 1
        }
        if (-not $hit) { throw "Object '$name' was not found in $($script:Ctx.CurrentDomain.DnsRoot)." }
        $out.Add([pscustomobject]@{ Name=$hit.Name; DistinguishedName=$hit.DistinguishedName; Value=$txtValue.Text })
    }
    elseif ($rbFile.Checked) {
        $p = $txtFile.Text.Trim()
        if (-not (Test-Path -LiteralPath $p)) { throw "List file not found: $p" }
        foreach ($line in (Get-Content -LiteralPath $p)) {
            $t = $line.Trim()
            if (-not $t -or $t.StartsWith('#') -or $t.StartsWith(';')) { continue }
            if ($chkPerLine.Checked) {
                $i = $t.IndexOfAny(@(' ',"`t",','))
                $nm = if ($i -lt 0) { $t } else { $t.Substring(0,$i).Trim() }
                $vv = if ($i -lt 0) { '' } else { $t.Substring($i+1).Trim() }
            } else {
                $nm = ($t -split '[\s,]+')[0]; $vv = $txtValue.Text
            }
            $esc = $nm -replace '([\\\*\(\)\0])','\$1'
            $f = "(&$($def.Filter)($($def.Naming)=$esc))"
            $hit = (Search-Object -SearchBase $nc -Filter $f -NamingAttr $def.Naming -Limit 1) | Select-Object -First 1
            if ($hit) {
                $out.Add([pscustomobject]@{ Name=$hit.Name; DistinguishedName=$hit.DistinguishedName; Value=$vv })
            } else {
                $out.Add([pscustomobject]@{ Name=$nm; DistinguishedName=$null; Value=$vv })
            }
        }
    }
    elseif ($rbGroup.Checked) {
        $gname = $cmbGroup.Text.Trim()
        if (-not $gname) { throw 'No group selected. Pick a group or type its name.' }
        $gdn = Get-SelectedGroupDN
        if (-not $gdn) { throw "Group '$gname' was not found in $($script:Ctx.CurrentDomain.DnsRoot)." }

        $f = Get-GroupMemberFilter -GroupDN $gdn -ClassFilter $def.Filter -Nested:$chkNested.Checked
        foreach ($o in (Search-Object -SearchBase $nc -Filter $f -NamingAttr $def.Naming -Scope 'Subtree')) {
            $out.Add([pscustomobject]@{ Name=$o.Name; DistinguishedName=$o.DistinguishedName; Value=$txtValue.Text })
        }

        if (-not $out.Count) {
            throw ("Group '$gname' has no members of class '$([string]$cmbClass.SelectedItem)'. " +
                   "Note that members whose PRIMARY group is this group (usually Domain Users) " +
                   "are not returned by a memberOf search.")
        }
    }
    elseif ($rbOU.Checked) {
        $base = $cmbOU.Text.Trim()
        if (-not $base) { throw 'No container selected.' }
        $scope = if ($chkSubtree.Checked) { 'Subtree' } else { 'OneLevel' }
        foreach ($o in (Search-Object -SearchBase $base -Filter $def.Filter -NamingAttr $def.Naming -Scope $scope)) {
            $out.Add([pscustomobject]@{ Name=$o.Name; DistinguishedName=$o.DistinguishedName; Value=$txtValue.Text })
        }
    }
    else {
        foreach ($o in (Search-Object -SearchBase $nc -Filter $def.Filter -NamingAttr $def.Naming -Scope 'Subtree')) {
            $out.Add([pscustomobject]@{ Name=$o.Name; DistinguishedName=$o.DistinguishedName; Value=$txtValue.Text })
        }
    }

    # ToArray() is used instead of @($out). Converting a List[object] created by
    # New-Object directly with the array subexpression throws
    # "Argument types do not match" on the PSObject-wrapped instance.
    return ,$out.ToArray()
}

function Show-Plan {
    param([array]$Rows)
    $lvPlan.BeginUpdate()
    $lvPlan.Items.Clear()
    foreach ($r in $Rows) {
        $it = New-Object System.Windows.Forms.ListViewItem($r.Name)
        $null = $it.SubItems.Add($r.Attribute)
        $null = $it.SubItems.Add($r.Current)
        $null = $it.SubItems.Add($r.Proposed)
        $null = $it.SubItems.Add($r.Effect)
        $null = $it.SubItems.Add($r.Status)
        $null = $it.SubItems.Add([string]$r.DistinguishedName)
        switch ($r.Status) {
            'ERROR'   { $it.ForeColor = $cRed }
            'APPLIED' { $it.ForeColor = $cGreen }
            default   { if ($r.Effect -eq 'no change') { $it.ForeColor = $cGray } }
        }
        $null = $lvPlan.Items.Add($it)
    }
    $lvPlan.EndUpdate()
}

# ===========================================================================
# Events
# ===========================================================================

$txtAttrFilter.Add_TextChanged({ Update-AttrList })
$chkWritableOnly.Add_CheckedChanged({ Update-AttrList })

$lstAttr.Add_SelectedIndexChanged({
    if (-not $lstAttr.SelectedItem) { return }
    $n = [string]$lstAttr.SelectedItem
    $txtSelAttr.Text = $n
    $m = $script:Attributes | Where-Object { $_.Name -eq $n } | Select-Object -First 1
    if ($m) {
        $f = @()
        if ($m.Mandatory)   { $f += 'mandatory' }
        if ($m.MultiValued) { $f += 'multi-valued' } else { $f += 'single-valued' }
        if (-not $m.Writable) { $f += 'READ ONLY' }
        if ($m.Dangerous)     { $f += 'HIGH IMPACT' }
        $lblAttrMeta.Text = "$($m.Syntax)   [$($f -join ', ')]"
        $lblAttrMeta.ForeColor = if (-not $m.Writable) { $cRed } elseif ($m.Dangerous) { $cRed } else { $cGray }
    }
    Update-CurrentValue
    Invalidate-Plan
})

$cmbDomain.Add_SelectedIndexChanged({
    if ($cmbDomain.SelectedIndex -lt 0) { return }
    $script:Ctx.CurrentDomain = $script:Ctx.Domains[$cmbDomain.SelectedIndex]
    Invalidate-Plan
    Load-Domain
})

$cmbClass.Add_SelectedIndexChanged({ Load-Class; $cmbObject.Items.Clear(); $lblObjCount.Text = ''; Update-MemberCount })
$cmbAction.Add_SelectedIndexChanged({
    $txtValue.Enabled = ($cmbAction.Text -ne 'Clear')
    Invalidate-Plan
})
$txtValue.Add_TextChanged({ Invalidate-Plan })
$cmbObject.Add_SelectedIndexChanged({ Update-CurrentValue })
$cmbObject.Add_Leave({ Update-CurrentValue })

foreach ($rb in @($rbOne,$rbFile,$rbGroup,$rbOU,$rbDomain)) {
    $rb.Add_CheckedChanged({
        $cmbObject.Enabled      = $rbOne.Checked
        $btnLoadObjects.Enabled = $rbOne.Checked
        $txtFile.Enabled        = $rbFile.Checked
        $btnBrowse.Enabled      = $rbFile.Checked
        $chkPerLine.Enabled     = $rbFile.Checked
        $cmbGroup.Enabled       = $rbGroup.Checked
        $btnLoadGroups.Enabled  = $rbGroup.Checked
        $chkNested.Enabled      = $rbGroup.Checked
        $cmbOU.Enabled          = $rbOU.Checked
        $chkSubtree.Enabled     = $rbOU.Checked
        Update-CurrentValue
        Update-MemberCount
        Invalidate-Plan
    })
}

$btnBrowse.Add_Click({
    $d = New-Object System.Windows.Forms.OpenFileDialog
    $d.Filter = 'Text or CSV (*.txt;*.csv)|*.txt;*.csv|All files (*.*)|*.*'
    if ($d.ShowDialog() -eq 'OK') { $txtFile.Text = $d.FileName; Invalidate-Plan }
})

$btnLoadObjects.Add_Click({
    if (-not $script:Ctx.CurrentDomain) { return }
    $def = $script:ClassMap[[string]$cmbClass.SelectedItem]
    try {
        Set-Status "Enumerating $($cmbClass.SelectedItem) objects ..."
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $script:Objects = Search-Object -SearchBase $script:Ctx.CurrentDomain.NCName `
                                        -Filter $def.Filter -NamingAttr $def.Naming
        $cmbObject.BeginUpdate(); $cmbObject.Items.Clear()
        foreach ($o in $script:Objects) { $null = $cmbObject.Items.Add($o.Name) }
        $cmbObject.EndUpdate()
        if ($cmbObject.Items.Count) { $cmbObject.SelectedIndex = 0 }
        $lblObjCount.Text = "$($script:Objects.Count) found"
        Set-Status "Loaded $($script:Objects.Count) objects."
    } catch {
        Set-Status $_.Exception.Message
        Write-ErrorLog -Context 'Load objects (enumeration)' -ErrorRecord $_
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Enumeration','OK','Error') | Out-Null
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$btnLoadGroups.Add_Click({
    if (-not $script:Ctx.CurrentDomain) { return }
    try {
        Set-Status 'Enumerating groups ...'
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $script:Groups = Search-Object -SearchBase $script:Ctx.CurrentDomain.NCName `
                                       -Filter '(objectCategory=group)' -NamingAttr 'sAMAccountName'
        $cmbGroup.BeginUpdate(); $cmbGroup.Items.Clear()
        foreach ($g in $script:Groups) { $null = $cmbGroup.Items.Add($g.Name) }
        $cmbGroup.EndUpdate()
        if ($cmbGroup.Items.Count) { $cmbGroup.SelectedIndex = 0 }
        Set-Status "Loaded $(@($script:Groups).Count) group(s)."
        Update-MemberCount
    } catch {
        Set-Status $_.Exception.Message
        Write-ErrorLog -Context 'Load groups (enumeration)' -ErrorRecord $_
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message,'Enumeration','OK','Error') | Out-Null
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }
})

$cmbGroup.Add_SelectedIndexChanged({ Update-MemberCount; Invalidate-Plan })
$cmbGroup.Add_Leave({ Update-MemberCount })
$chkNested.Add_CheckedChanged({ Update-MemberCount; Invalidate-Plan })

$btnCreds.Add_Click({
    $c = Get-Credential -Message 'Credentials for the target forest'
    if ($c) { $script:Ctx.Credential = $c; Set-Status "Alternate credentials: $($c.UserName)"; Invalidate-Plan }
})

$btnConnect.Add_Click({
    $s = [Microsoft.VisualBasic.Interaction]::InputBox(
        'Domain controller or DNS domain name (blank = current domain):','Connect',
        [string]$script:Ctx.BindServer)
    $script:Ctx.BindServer = $s.Trim()
    Invalidate-Plan
    Initialize-Session
})

$btnOpenLog.Add_Click({
    $p = $txtLog.Text
    if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType File -Path $p -Force | Out-Null }
    Start-Process notepad.exe -ArgumentList $p
})

$btnClose.Add_Click({ $form.Close() })

# Keyboard fallback. Every action reachable without a visible button.
$form.Add_KeyDown({
    switch ($_.KeyCode) {
        'F5'     { if ($btnWhatIf.Enabled) { $btnWhatIf.PerformClick() }; $_.Handled = $true }
        'F6'     { if ($btnApply.Enabled)  { $btnApply.PerformClick() };  $_.Handled = $true }
        'F7'     { if ($btnExport.Enabled) { $btnExport.PerformClick() }; $_.Handled = $true }
        'Escape' { $form.Close(); $_.Handled = $true }
    }
})

$btnExport.Add_Click({
    if (-not $script:Plan.Count) {
        [System.Windows.Forms.MessageBox]::Show('No plan to export. Run what-if first.','Export','OK','Information') | Out-Null
        return
    }
    $d = New-Object System.Windows.Forms.SaveFileDialog
    $d.Filter = 'CSV (*.csv)|*.csv'
    $d.FileName = "ADAttrPlan-$(Get-Date -Format yyyyMMdd-HHmmss).csv"
    if ($d.ShowDialog() -eq 'OK') {
        $script:Plan | Select-Object Name,Attribute,Action,Current,Proposed,Effect,Status,DistinguishedName |
            Export-Csv -LiteralPath $d.FileName -NoTypeInformation -Encoding UTF8
        Set-Status "Exported $($script:Plan.Count) rows."
    }
})

# --- WHAT-IF ---
$btnWhatIf.Add_Click({
  try {
    $attr = $txtSelAttr.Text.Trim()
    if (-not $attr) {
        [System.Windows.Forms.MessageBox]::Show('Select an attribute first.','What-if','OK','Warning') | Out-Null
        return
    }
    $meta = $script:Attributes | Where-Object { $_.Name -eq $attr } | Select-Object -First 1
    if ($meta -and -not $meta.Writable) {
        [System.Windows.Forms.MessageBox]::Show(
            "'$attr' is not writable through LDAP. Pick a different attribute.",'Read only','OK','Error') | Out-Null
        return
    }

    $action = Get-ActionKey
    $logPath = $txtLog.Text.Trim()

    try {
        Set-Status 'Resolving scope ...'
        $form.Cursor = [System.Windows.Forms.Cursors]::WaitCursor
        $targets = Get-TargetList
    } catch {
        $form.Cursor = [System.Windows.Forms.Cursors]::Default
        Write-ErrorLog -Context 'What-if: scope resolution' -ErrorRecord $_
        $m = $_.Exception.Message + "`n`n" + $_.InvocationInfo.PositionMessage + "`n`n" + $_.ScriptStackTrace
        [System.Windows.Forms.MessageBox]::Show($m,'Scope','OK','Error') | Out-Null
        return
    } finally { $form.Cursor = [System.Windows.Forms.Cursors]::Default }

    if (-not $targets.Count) {
        [System.Windows.Forms.MessageBox]::Show('Scope matched zero objects.','What-if','OK','Information') | Out-Null
        Invalidate-Plan; return
    }

    $rows = New-Object System.Collections.Generic.List[object]
    $progress.Minimum = 0; $progress.Maximum = $targets.Count; $progress.Value = 0
    $btnWhatIf.Enabled = $false

    try {
        foreach ($t in $targets) {
            $progress.Value = [Math]::Min($progress.Value+1, $progress.Maximum)
            if (($progress.Value % 25) -eq 0 -or $targets.Count -lt 50) {
                Set-Status "What-if $($progress.Value) of $($targets.Count) ..."
            }

            $cur=''; $prop=''; $eff='no change'; $st='PLANNED'
            if (-not $t.DistinguishedName) {
                $st = 'ERROR'; $eff = 'not found'
            } else {
                try {
                    $de   = New-DirEntry (Get-BindPath $t.DistinguishedName)
                    $cur  = Get-AttrValue -Entry $de -Attribute $attr
                    $inp  = Expand-Token -Template $t.Value -Entry $de
                    $prop = Get-ProposedValue -Current $cur -Proposed $inp -Action $action
                    $eff  = if ($prop -ceq $cur) { 'no change' }
                            elseif (-not $cur)   { 'set' }
                            elseif (-not $prop)  { 'cleared' }
                            else                 { 'modified' }
                    $de.Close()
                } catch {
                    $st='ERROR'; $eff='read failed'; $prop=$_.Exception.Message
                    Write-ErrorLog -Context "What-if read: $($t.Name)" -ErrorRecord $_
                }
            }

            $rows.Add([pscustomobject]@{
                Name=$t.Name; Attribute=$attr; Action=$cmbAction.Text
                Current=$cur; Proposed=$prop; Effect=$eff; Status=$st
                DistinguishedName=[string]$t.DistinguishedName
            })
        }
    } finally {
        $btnWhatIf.Enabled = $true; $progress.Value = 0
    }

    $script:Plan = $rows.ToArray()
    $script:PlanStamp = Get-Date
    Show-Plan $script:Plan

    $chg = @($script:Plan | Where-Object { $_.Effect -notin @('no change','not found','read failed') }).Count
    $nc  = @($script:Plan | Where-Object { $_.Effect -eq 'no change' }).Count
    $er  = @($script:Plan | Where-Object { $_.Status -eq 'ERROR' }).Count

    $lblSummary.Text = "WHAT-IF: $($script:Plan.Count) object(s) matched.  $chg would change.  $nc already correct.  $er error(s).  Nothing has been written."
    $lblSummary.ForeColor = $cBlue
    Set-Status 'What-if complete. Review the plan, then Apply.'
    $btnApply.Enabled = ($chg -gt 0)

    if ($logPath) {
        Write-AuditLog -Path $logPath -Kind 'WHATIF' -Name "(scope)" -DN $script:Ctx.CurrentDomain.NCName `
            -Attribute $attr -Action $cmbAction.Text -OldValue "matched=$($script:Plan.Count)" `
            -NewValue "wouldChange=$chg" -Status 'PLANNED'
    }
  }
  catch {
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $btnWhatIf.Enabled = $true
    $progress.Value = 0
    Write-ErrorLog -Context 'What-if handler (unhandled)' -ErrorRecord $_
    $m = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message + `
         "`n`n" + $_.InvocationInfo.PositionMessage + "`n`n" + $_.ScriptStackTrace
    [System.Windows.Forms.MessageBox]::Show($m,'What-if failed (diagnostic)','OK','Error') | Out-Null
  }
})

# --- APPLY ---
$btnApply.Add_Click({
  try {
    if (-not $script:Plan.Count) {
        [System.Windows.Forms.MessageBox]::Show('Run what-if first.','Apply','OK','Warning') | Out-Null
        return
    }

    $attr    = $txtSelAttr.Text.Trim()
    $action  = Get-ActionKey
    $logPath = $txtLog.Text.Trim()
    $meta    = $script:Attributes | Where-Object { $_.Name -eq $attr } | Select-Object -First 1

    $work = @($script:Plan | Where-Object { $_.Status -eq 'PLANNED' -and $_.Effect -notin @('no change','not found','read failed') })
    if (-not $work.Count) {
        [System.Windows.Forms.MessageBox]::Show('Nothing in the plan would change.','Apply','OK','Information') | Out-Null
        return
    }

    $sample = ($work | Select-Object -First 5 | ForEach-Object {
        $c = if ($_.Current)  { $_.Current }  else { '<empty>' }
        $p = if ($_.Proposed) { $_.Proposed } else { '<empty>' }
        "  $($_.Name):  $c  ->  $p"
    }) -join "`r`n"
    $more = if ($work.Count -gt 5) { "`r`n  ... and $($work.Count - 5) more" } else { '' }

    $scopeName = if ($rbDomain.Checked) { "ENTIRE DOMAIN $($script:Ctx.CurrentDomain.DnsRoot)" }
                 elseif ($rbOU.Checked) { "container $($cmbOU.Text)" }
                 elseif ($rbGroup.Checked) {
                     $nst = if ($chkNested.Checked) { ' including nested' } else { '' }
                     "members of group $($cmbGroup.Text)$nst"
                 }
                 elseif ($rbFile.Checked) { 'file list' } else { 'single object' }

    $msg = "LIVE WRITE`r`n`r`n" +
           "Domain    : $($script:Ctx.CurrentDomain.DnsRoot)`r`n" +
           "Class     : $($cmbClass.SelectedItem)`r`n" +
           "Attribute : $attr`r`n" +
           "Action    : $($cmbAction.Text)`r`n" +
           "Scope     : $scopeName`r`n" +
           "Objects   : $($work.Count)`r`n`r`n$sample$more`r`n`r`nProceed?"

    if ([System.Windows.Forms.MessageBox]::Show($msg,'Confirm live change','YesNo','Warning','Button2') -ne 'Yes') {
        Set-Status 'Apply cancelled.'; return
    }

    # Second gate for high-impact attributes or domain-wide scope
    if (($meta -and $meta.Dangerous) -or $rbDomain.Checked -or $work.Count -ge 50) {
        $typed = [Microsoft.VisualBasic.Interaction]::InputBox(
            "This is a high impact change affecting $($work.Count) object(s).`r`n" +
            "Type the object count to confirm:", 'Second confirmation', '')
        if ($typed.Trim() -ne [string]$work.Count) {
            Set-Status 'Apply cancelled at second confirmation.'
            return
        }
    }

    $progress.Minimum = 0; $progress.Maximum = $work.Count; $progress.Value = 0
    $btnApply.Enabled = $false; $btnWhatIf.Enabled = $false
    $ok = 0; $fail = 0

    try {
        foreach ($r in $work) {
            $progress.Value = [Math]::Min($progress.Value+1, $progress.Maximum)
            if (($progress.Value % 25) -eq 0 -or $work.Count -lt 50) {
                Set-Status "Applying $($progress.Value) of $($work.Count) ..."
            }
            try {
                $de  = New-DirEntry (Get-BindPath $r.DistinguishedName)
                $inp = Expand-Token -Template $txtValue.Text -Entry $de
                Set-AttrValue -Entry $de -Attribute $attr -Value $inp -Action $action
                $r.Proposed = Get-AttrValue -Entry $de -Attribute $attr
                $r.Status = 'APPLIED'
                $de.Close()
                $ok++
            } catch {
                $r.Status = 'ERROR'
                $r.Proposed = $_.Exception.Message
                $fail++
                Write-ErrorLog -Context "Apply write: $($r.Name)" -ErrorRecord $_
            }
            if ($logPath) {
                Write-AuditLog -Path $logPath -Kind 'CHANGE' -Name $r.Name -DN $r.DistinguishedName `
                    -Attribute $attr -Action $cmbAction.Text -OldValue $r.Current `
                    -NewValue $r.Proposed -Status $r.Status
            }
        }
    } finally {
        $btnWhatIf.Enabled = $true; $progress.Value = 0
    }

    Show-Plan $script:Plan
    $lblSummary.Text = "APPLIED: $ok succeeded, $fail failed, out of $($work.Count) planned changes."
    $lblSummary.ForeColor = if ($fail) { $cRed } else { $cGreen }
    Set-Status 'Apply complete.'

    [System.Windows.Forms.MessageBox]::Show(
        "Applied $ok change(s). $fail failure(s).",
        'Apply complete','OK', $(if ($fail) { 'Warning' } else { 'Information' })) | Out-Null
  }
  catch {
    $form.Cursor = [System.Windows.Forms.Cursors]::Default
    $btnWhatIf.Enabled = $true
    $progress.Value = 0
    Write-ErrorLog -Context 'Apply handler (unhandled)' -ErrorRecord $_
    $m = $_.Exception.GetType().FullName + ': ' + $_.Exception.Message + `
         "`n`n" + $_.InvocationInfo.PositionMessage + "`n`n" + $_.ScriptStackTrace
    [System.Windows.Forms.MessageBox]::Show($m,'Apply failed (diagnostic)','OK','Error') | Out-Null
  }
})

# ===========================================================================
# Go
# ===========================================================================
try { Add-Type -AssemblyName Microsoft.VisualBasic } catch { }

$script:Ctx.BindServer = $Server
$form.Add_Shown({ $form.Activate(); Initialize-Session })
[void]$form.ShowDialog()
$form.Dispose()
