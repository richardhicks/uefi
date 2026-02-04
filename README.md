# Get-UEFICertificate

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/richardhicks/uefi/blob/main/LICENSE)
[![Version](https://img.shields.io/badge/Version-1.2.1-green.svg)](https://github.com/richardhicks/uefi/)

A PowerShell script for reading and exporting UEFI Secure Boot certificates directly from firmware. This tool retrieves Platform Key (PK), Key Exchange Key (KEK), and signature database (DB) certificates, providing detailed information about each certificate and optional export functionality.

## Overview

Secure Boot is a critical security feature in UEFI firmware that ensures only trusted software loads during the boot process. Managing and auditing these certificates is essential for maintaining system security and compliance.

**Get-UEFICertificate** simplifies this process by:

- Reading certificates directly from UEFI firmware variables
- Parsing EFI Signature List (ESL) format data
- Displaying certificate details in a structured, readable format
- Exporting certificates to PEM-encoded files for further analysis or backup

## Features

- **Comprehensive Certificate Retrieval** - Access PK, KEK, and DB certificates from UEFI firmware
- **Flexible Output** - View certificate details on screen or export to files
- **Hash Support** - Optionally include SHA256 and SHA1 hash entries from the signature database
- **PEM Format Export** - Save certificates in industry-standard base64-encoded format
- **Detailed Certificate Information** - View subject, issuer, thumbprint, validity dates, and serial numbers
- **Secure Boot Status Check** - Automatically verifies Secure Boot availability and status

## Requirements

- **Operating System**: Windows 10/11 or Windows Server 2016+
- **PowerShell**: Version 5.1 or later
- **Privileges**: Administrator rights required
- **UEFI**: System must support UEFI with Secure Boot

## Installation

### Option 1: Direct Download

```powershell
# Download the script directly from GitHub
Invoke-WebRequest -Uri "https://github.com/richardhicks/uefi/raw/main/Get-UEFICertificate.ps1" -OutFile "Get-UEFICertificate.ps1"
```

### Option 2: Clone the Repository

```powershell
git clone https://github.com/richardhicks/uefi.git
cd uefi
```

## Usage

### Basic Usage

Retrieve all Secure Boot certificates:

```powershell
.\Get-UEFICertificate.ps1
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-CertificateType` | String[] | Specifies certificate type(s) to retrieve. Valid values: `All`, `PK`, `KEK`, `DB`. Default: `All` |
| `-OutFile` | Switch | Enables saving certificates to files |
| `-OutPath` | String | Folder path for exported certificates. Default: `$env:temp` |
| `-IncludeHashes` | Switch | Includes SHA256/SHA1 hash entries in output |

### Examples

**Retrieve all certificates:**

```powershell
.\Get-UEFICertificate.ps1
```

**Get only the Platform Key (PK):**

```powershell
.\Get-UEFICertificate.ps1 -CertificateType PK
```

**Get PK and KEK certificates:**

```powershell
.\Get-UEFICertificate.ps1 -CertificateType PK, KEK
```

**Include hash entries in output:**

```powershell
.\Get-UEFICertificate.ps1 -IncludeHashes
```

**Export all certificates to temp directory:**

```powershell
.\Get-UEFICertificate.ps1 -OutFile
```

**Export certificates to a specific folder:**

```powershell
.\Get-UEFICertificate.ps1 -OutFile -OutPath "C:\SecureBoot\Certificates"
```

**Export only DB certificates to a custom location:**

```powershell
.\Get-UEFICertificate.ps1 -CertificateType DB -OutFile -OutPath "C:\Backup\UEFI"
```

## Common Scenarios

### 1. Security Audit and Compliance

When conducting security audits or compliance assessments, you need to document the Secure Boot certificate chain on managed systems.

```powershell
# Export all certificates for documentation
.\Get-UEFICertificate.ps1 -OutFile -OutPath "C:\Audit\SecureBoot"

# Include hashes for complete audit trail
.\Get-UEFICertificate.ps1 -IncludeHashes | Export-Csv -Path "C:\Audit\SecureBootCerts.csv" -NoTypeInformation
```

### 2. Certificate Expiration Monitoring

Monitor certificate validity to prevent unexpected Secure Boot failures due to expired certificates.

```powershell
# Check certificate expiration dates
$certs = .\Get-UEFICertificate.ps1
$certs | Where-Object { $_.Expires -lt (Get-Date).AddDays(90) } | 
    Select-Object Type, Subject, Expires | 
    Format-Table -AutoSize
```

### 3. Backup Before System Changes

Before updating BIOS/UEFI firmware or making Secure Boot configuration changes, backup existing certificates.

```powershell
# Create timestamped backup
$backupPath = "C:\Backup\UEFI_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
.\Get-UEFICertificate.ps1 -OutFile -OutPath $backupPath
```

### 4. Comparing Certificates Across Systems

Verify certificate consistency across multiple systems in your environment.

```powershell
# Get certificate thumbprints for comparison
$certs = .\Get-UEFICertificate.ps1
$certs | Select-Object Type, Subject, Thumbprint | Format-Table -AutoSize
```

### 5. Troubleshooting Secure Boot Issues

When diagnosing Secure Boot problems, examine the certificate database for missing or invalid entries.

```powershell
# Display detailed certificate information
.\Get-UEFICertificate.ps1 -Verbose

# Check for parsing errors
$certs = .\Get-UEFICertificate.ps1
$certs | Where-Object { $_.ParseError -ne $null } | 
    Select-Object Type, Subject, ParseError
```

### 6. Identifying Third-Party Certificates

Identify certificates added by device manufacturers or third-party software.

```powershell
# List all DB certificates with issuer information
.\Get-UEFICertificate.ps1 -CertificateType DB | 
    Select-Object Subject, Issuer, Issued, Expires | 
    Format-Table -AutoSize
```

### 7. Custom Key Enrollment Preparation

When preparing to enroll custom Secure Boot keys, first document existing certificates.

```powershell
# Document existing keys before enrollment
.\Get-UEFICertificate.ps1 | 
    Select-Object Type, Subject, Thumbprint, Issued, Expires | 
    Export-Csv -Path ".\PreEnrollment_Certificates.csv" -NoTypeInformation
```

## Output

The script returns `PSCustomObject` instances with the following properties:

| Property | Description |
|----------|-------------|
| `Type` | Certificate type (PK, KEK, or DB) |
| `Description` | Human-readable description |
| `Index` | Certificate index within its type |
| `SignatureType` | UEFI signature type GUID |
| `OwnerGuid` | Certificate owner GUID |
| `CertificateSize` | Size in bytes |
| `Subject` | Certificate subject |
| `Issuer` | Certificate issuer |
| `Thumbprint` | Certificate thumbprint/hash |
| `Issued` | Certificate issue date |
| `Expires` | Certificate expiration date |
| `SerialNumber` | Certificate serial number |
| `ParseError` | Error message if parsing failed |
| `RawData` | Raw certificate bytes |

Each object also includes a `SaveToFile()` method for individual certificate export:

```powershell
$certs = .\Get-UEFICertificate.ps1
$certs[0].SaveToFile("C:\Temp\certificate.cer")
```

## Important Notes

- **Administrator privileges required** - The script must be run as Administrator to access UEFI variables
- **Secure Boot must be available** - The system must support UEFI Secure Boot
- **Read-only operation** - This script only reads certificates; it does not modify Secure Boot configuration
- **Hash entries excluded by default** - Use `-IncludeHashes` to display SHA256/SHA1 hash entries

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests on the [GitHub repository](https://github.com/richardhicks/uefi/).

## License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/richardhicks/uefi/blob/main/LICENSE) file for details.

## Author

**Richard Hicks**

- Website: [https://www.richardhicks.com/](https://www.richardhicks.com/)
- GitHub: [@richardhicks](https://github.com/richardhicks)
- X: [@richardhicks](https://x.com/richardhicks)

---

*Copyright (C) 2026 Richard M. Hicks Consulting, Inc. All Rights Reserved.*
