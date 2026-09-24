<#
.SYNOPSIS
    ADPulse MVP-1 lab setup (D33): the reader account and LDAPS on this domain controller. Lab domain only.

.DESCRIPTION
    - Creates adpulse.reader (Domain Users only) with a generated password, or resets its password if it
      exists, and writes .env at the repo root (git-ignored). The password is never printed.
    - Creates a self-signed LDAPS certificate for this DC's DNS name if none is valid (Schannel CSP, KB 321051),
      trusts it on this DC, asks AD DS to load it without restarting NTDS (renewServerCertificate), waits until
      port 636 answers TLS, and exports it as PEM to lab\dc-ldaps.pem (git-ignored).
    - Never changes the password policy (D33); ADPulse itself only reads.

.EXAMPLE
    # elevated Windows PowerShell on DC1, in C:\ADPulse\adpulse
    .\lab\Setup-Lab.ps1
#>
#Requires -RunAsAdministrator
#Requires -Modules ActiveDirectory
[CmdletBinding()]
param(
    [string]$LabDomain = 'corp.local',
    [string]$ReaderName = 'adpulse.reader'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repo = Split-Path $PSScriptRoot -Parent
$domain = Get-ADDomain
$dns = $domain.DNSRoot.ToLower()
$fqdn = ('{0}.{1}' -f $env:COMPUTERNAME, $dns).ToLower()

# Lab only: refuse anything but a domain controller of the lab domain.
if ($dns -ne $LabDomain.ToLower()) { throw "Refusing to run: this domain is '$dns', not the ADPulse lab domain '$LabDomain'." }
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) { throw 'Refusing to run: this machine is not a domain controller.' }
foreach ($secretFile in '.env', 'lab/dc-ldaps.pem') {
    & git -C $repo check-ignore -q $secretFile
    if ($LASTEXITCODE -ne 0) { throw "Refusing to run: $secretFile is not git-ignored in this repo." }
}

# --- reader account --------------------------------------------------------------------------------
$script:Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

function Get-RandomIndex([int]$Max) {
    $bytes = New-Object byte[] 4
    $script:Rng.GetBytes($bytes)
    return [int]([BitConverter]::ToUInt32($bytes, 0) % [uint32]$Max)
}

function New-ReaderPassword([int]$Length = 24) {
    # letters, digits and -_.!@% only: never '#', quotes or spaces (.env stays simple); all four classes present
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

$upn = "$ReaderName@$dns"
$plain = New-ReaderPassword
$secure = ConvertTo-SecureString $plain -AsPlainText -Force
$reader = Get-ADUser -Filter "SamAccountName -eq '$ReaderName'"
if ($reader) {
    Set-ADAccountPassword -Identity $reader -Reset -NewPassword $secure
    Enable-ADAccount -Identity $reader
    $readerAction = 'password reset'
} else {
    New-ADUser -Name $ReaderName -SamAccountName $ReaderName -UserPrincipalName $upn -AccountPassword $secure `
        -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true `
        -Description 'ADPulse standard-user collector (lab)'
    $readerAction = 'created'
}
$extraGroups = @(Get-ADPrincipalGroupMembership -Identity $ReaderName | Where-Object { $_.Name -ne 'Domain Users' })
if ($extraGroups.Count -gt 0) {
    throw "$ReaderName must be a member of Domain Users only; also in: $(($extraGroups | ForEach-Object Name) -join ', ')"
}

$envLines = @(
    '# written by lab/Setup-Lab.ps1 - lab only, git-ignored, never commit',
    "ADPULSE_DC=$fqdn",
    "ADPULSE_DOMAIN=$dns",
    "ADPULSE_USER=$upn",
    "ADPULSE_PASSWORD=$plain",
    'ADPULSE_MODE=standard',
    'ADPULSE_CA_CERT=lab/dc-ldaps.pem'
)
[IO.File]::WriteAllText((Join-Path $repo '.env'), (($envLines -join "`n") + "`n"), (New-Object Text.ASCIIEncoding))
Remove-Variable plain, secure, envLines

# --- LDAPS certificate -----------------------------------------------------------------------------
$serverAuth = '1.3.6.1.5.5.7.3.1'
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object {
        $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date).AddDays(30) -and
        (@($_.DnsNameList | ForEach-Object { $_.Unicode.ToLower() }) -contains $fqdn) -and
        (@($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq $serverAuth }).Count -gt 0)
    } |
    Sort-Object NotAfter -Descending | Select-Object -First 1
if ($cert) {
    $certAction = 'kept'
} else {
    $cert = New-SelfSignedCertificate -DnsName $fqdn -CertStoreLocation Cert:\LocalMachine\My `
        -Provider 'Microsoft RSA SChannel Cryptographic Provider' -KeySpec KeyExchange -KeyLength 2048 `
        -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(2) -FriendlyName 'ADPulse lab LDAPS'
    $certAction = 'created'
}

# The DC must trust its own self-signed certificate (public part only).
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
$rootStore.Open('ReadWrite')
if (-not ($rootStore.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint })) {
    $rootStore.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $cert.RawData)))
}
$rootStore.Close()

function Get-LdapsThumbprint([string]$HostName) {
    try {
        $tcp = New-Object Net.Sockets.TcpClient($HostName, 636)
        try {
            $tls = New-Object Net.Security.SslStream($tcp.GetStream(), $false, ({ $true }))
            $tls.AuthenticateAsClient($HostName)
            return $tls.RemoteCertificate.GetCertHashString()
        } finally { $tcp.Dispose() }
    } catch { return $null }
}

$served = Get-LdapsThumbprint $fqdn
if ($served -ne $cert.Thumbprint) {
    # Load the certificate into AD DS without restarting NTDS (and the DNS and KDC services with it).
    $rootDse = [ADSI]'LDAP://localhost:389/RootDSE'
    $rootDse.Put('renewServerCertificate', 1)
    $rootDse.SetInfo()
    $deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 3
        $served = Get-LdapsThumbprint $fqdn
    } while ($served -ne $cert.Thumbprint -and (Get-Date) -lt $deadline)
}
if (-not $served) {
    throw "LDAPS on ${fqdn}:636 does not answer after 60 s. Check the Directory Service event log (event 1220)."
}
if ($served -ne $cert.Thumbprint) {
    Write-Warning "LDAPS answers with certificate $served, not $($cert.Thumbprint); the exported PEM may not match."
}

$pem = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($cert.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n"
[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'dc-ldaps.pem'), $pem, (New-Object Text.ASCIIEncoding))

[pscustomobject]@{
    Reader      = "$upn ($readerAction; Domain Users only)"
    DC          = $fqdn
    Certificate = "$($cert.Thumbprint) ($certAction; expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"
    LDAPS       = "OK on ${fqdn}:636"
    Files       = '.env and lab\dc-ldaps.pem written (git-ignored)'
    Policy      = 'unchanged (D33)'
} | Format-List
