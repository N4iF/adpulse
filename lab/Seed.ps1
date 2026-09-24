<#
.SYNOPSIS
    ADPulse lab seed (increments 3-4): a small organization with plain-attribute weaknesses. Lab domain only.

.DESCRIPTION
    Creates, if missing, OU=Lab with Staff, ServiceAccounts, Groups and Servers; 10 staff in five department
    groups; helpdesk with hd.user1; temp.intern and contractor1; four service accounts; the computer object
    APP01. Then applies the seeds (lab/README.md -> Seed.ps1):
        increment 3  ACC-01  temp.intern: password not required
                     KRB-02  svc_legacy: Kerberos pre-authentication off
        increment 4  KRB-03  SPNs on svc_sql, svc_web, svc_backup
                     ACC-04  contractor1: description mentions a password (no real password in it)
                     DEL-01  APP01: trusted for unconstrained delegation
                     DEL-05  machine account quota left at the default (nothing to do)
    Permission seeds (increment 5) and the GPO seed (increment 6) are not here yet.
    Idempotent: re-running changes nothing that is already in place. Account passwords are random and never
    printed or stored; nobody signs in with these accounts. Never touches the password policy (D33) or
    adpulse.reader.

.EXAMPLE
    # elevated Windows PowerShell on DC1, in C:\ADPulse\adpulse
    .\lab\Seed.ps1
#>
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param([string]$LabDomain = 'corp.local')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$domain = Get-ADDomain
$dns = $domain.DNSRoot.ToLower()
if ($dns -ne $LabDomain.ToLower()) { throw "Refusing to run: this domain is '$dns', not the ADPulse lab domain '$LabDomain'." }
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { throw 'Refusing to run: this machine is not a domain controller.' }

$script:Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$script:Changes = New-Object 'System.Collections.Generic.List[string]'

function Get-RandomIndex([int]$Max) {
    $bytes = New-Object byte[] 4
    $script:Rng.GetBytes($bytes)
    return [int]([BitConverter]::ToUInt32($bytes, 0) % [uint32]$Max)
}

function New-LabPassword([int]$Length = 24) {
    $sets = @('ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '-_.!@%')
    $all = -join $sets
    $chars = New-Object 'System.Collections.Generic.List[char]'
    foreach ($set in $sets) { $chars.Add($set[(Get-RandomIndex $set.Length)]) }
    while ($chars.Count -lt $Length) { $chars.Add($all[(Get-RandomIndex $all.Length)]) }
    for ($i = $chars.Count - 1; $i -gt 0; $i--) {
        $j = Get-RandomIndex ($i + 1)
        $tmp = $chars[$i]; $chars[$i] = $chars[$j]; $chars[$j] = $tmp
    }
    return -join $chars
}

function Confirm-OU([string]$Name, [string]$Path) {
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'")) {
        New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $false
        $script:Changes.Add("OU $dn created")
    }
    return $dn
}

function Confirm-Group([string]$Name, [string]$Path, [string]$Description) {
    if (-not (Get-ADGroup -Filter "SamAccountName -eq '$Name'")) {
        New-ADGroup -Name $Name -SamAccountName $Name -GroupScope Global -GroupCategory Security -Path $Path -Description $Description
        $script:Changes.Add("group $Name created")
    }
}

function Confirm-User([string]$Sam, [string]$Path, [string]$DisplayName, [string]$Department, [string]$Title) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$Sam'")) {
        $password = ConvertTo-SecureString (New-LabPassword) -AsPlainText -Force
        New-ADUser -Name $Sam -SamAccountName $Sam -UserPrincipalName "$Sam@$dns" -DisplayName $DisplayName `
            -Department $Department -Title $Title -Path $Path -AccountPassword $password -Enabled $true -PasswordNeverExpires $true
        $script:Changes.Add("user $Sam created")
    }
}

function Confirm-Member([string]$Group, [string]$Sam) {
    $members = @(Get-ADGroupMember -Identity $Group | ForEach-Object SamAccountName)
    if ($members -notcontains $Sam) {
        Add-ADGroupMember -Identity $Group -Members $Sam
        $script:Changes.Add("$Sam added to $Group")
    }
}

# --- the organization ----------------------------------------------------------------------------------
$lab = Confirm-OU 'Lab' $domain.DistinguishedName
$staffOU = Confirm-OU 'Staff' $lab
$serviceOU = Confirm-OU 'ServiceAccounts' $lab
$groupsOU = Confirm-OU 'Groups' $lab
$serversOU = Confirm-OU 'Servers' $lab

$departments = [ordered]@{ 'IT' = 'GRP-IT'; 'HR' = 'GRP-HR'; 'Finance' = 'GRP-Finance'; 'Sales' = 'GRP-Sales'; 'Operations' = 'GRP-Operations' }
foreach ($dept in $departments.Keys) { Confirm-Group $departments[$dept] $groupsOU "$dept department" }
Confirm-Group 'helpdesk' $groupsOU 'IT help desk'

$staff = @(
    @('it.fahad', 'Fahad', 'IT', 'Systems engineer'), @('it.sara', 'Sara', 'IT', 'Network engineer'),
    @('hr.noura', 'Noura', 'HR', 'HR specialist'), @('hr.omar', 'Omar', 'HR', 'HR manager'),
    @('fin.khalid', 'Khalid', 'Finance', 'Accountant'), @('fin.lama', 'Lama', 'Finance', 'Finance manager'),
    @('sales.reem', 'Reem', 'Sales', 'Account manager'), @('sales.yousef', 'Yousef', 'Sales', 'Sales lead'),
    @('ops.maha', 'Maha', 'Operations', 'Operations analyst'), @('ops.turki', 'Turki', 'Operations', 'Operations manager')
)
foreach ($s in $staff) {
    Confirm-User $s[0] $staffOU "$($s[1]) ($($s[2]))" $s[2] $s[3]
    Confirm-Member $departments[$s[2]] $s[0]
}
Confirm-User 'hd.user1' $staffOU 'Help desk agent' 'IT' 'Help desk agent'
Confirm-Member 'helpdesk' 'hd.user1'
Confirm-Member 'GRP-IT' 'hd.user1'
Confirm-User 'temp.intern' $staffOU 'Temporary intern' 'HR' 'Intern'
Confirm-Member 'GRP-HR' 'temp.intern'
Confirm-User 'contractor1' $staffOU 'External contractor' 'Operations' 'Contractor'
Confirm-Member 'GRP-Operations' 'contractor1'

foreach ($svc in @(@('svc_sql', 'SQL Server service'), @('svc_web', 'Intranet web service'), @('svc_backup', 'Backup service'), @('svc_legacy', 'Legacy application service'))) {
    Confirm-User $svc[0] $serviceOU $svc[1] 'IT' 'Service account'
}

if (-not (Get-ADComputer -Filter "Name -eq 'APP01'")) {
    New-ADComputer -Name 'APP01' -SamAccountName 'APP01$' -Path $serversOU -DNSHostName "app01.$dns" -Enabled $true -Description 'Application server'
    $script:Changes.Add('computer APP01 created')
}

# --- seeds: increment 3 ---------------------------------------------------------------------------------
if (-not (Get-ADUser 'temp.intern' -Properties PasswordNotRequired).PasswordNotRequired) {
    Set-ADUser 'temp.intern' -PasswordNotRequired $true
    $script:Changes.Add('ACC-01 seed: temp.intern password not required')
}
if (-not (Get-ADUser 'svc_legacy' -Properties DoesNotRequirePreAuth).DoesNotRequirePreAuth) {
    Set-ADAccountControl 'svc_legacy' -DoesNotRequirePreAuth $true
    $script:Changes.Add('KRB-02 seed: svc_legacy pre-authentication off')
}

# --- seeds: increment 4 ---------------------------------------------------------------------------------
$spns = [ordered]@{ 'svc_sql' = "MSSQLSvc/app01.${dns}:1433"; 'svc_web' = "HTTP/intranet.$dns"; 'svc_backup' = "BackupSvc/app01.$dns" }
foreach ($sam in $spns.Keys) {
    $current = @((Get-ADUser $sam -Properties servicePrincipalName).servicePrincipalName)
    if ($current -notcontains $spns[$sam]) {
        Set-ADUser $sam -ServicePrincipalNames @{ Add = $spns[$sam] }
        $script:Changes.Add("KRB-03 seed: SPN $($spns[$sam]) on $sam")
    }
}
$contractorText = 'Temp password given by phone - see ticket 1042'
if ((Get-ADUser 'contractor1' -Properties Description).Description -ne $contractorText) {
    Set-ADUser 'contractor1' -Description $contractorText
    $script:Changes.Add('ACC-04 seed: contractor1 description')
}
if (-not (Get-ADComputer 'APP01' -Properties TrustedForDelegation).TrustedForDelegation) {
    Set-ADComputer 'APP01' -TrustedForDelegation $true
    $script:Changes.Add('DEL-01 seed: APP01 trusted for unconstrained delegation')
}

# --- summary --------------------------------------------------------------------------------------------
if ($script:Changes.Count -eq 0) { 'Lab seed already in place; nothing changed.' } else { $script:Changes }
[pscustomobject]@{
    'Users in OU=Lab' = @(Get-ADUser -Filter * -SearchBase $lab).Count
    'Groups'          = @(Get-ADGroup -Filter * -SearchBase $lab).Count
    'Computers'       = @(Get-ADComputer -Filter * -SearchBase $lab).Count
    'Password policy' = 'unchanged (D33)'
} | Format-List
