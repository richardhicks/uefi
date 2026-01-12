<#PSScriptInfo

.VERSION 1.2.1

.GUID 7c06efd4-2530-487d-b92c-d5874d0b53b3

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2026 Richard M. Hicks Consulting, Inc. All Rights Reserved.

.LICENSE Licensed under the MIT License. See LICENSE file in the project root for full license information.

.LICENSEURI https://github.com/richardhicks/uefi/blob/main/LICENSE

.PROJECTURI https://github.com/richardhicks/uefi/

.TAGS UEFI, SecureBoot, Certificates, PK, KEK, DB

#>

<#

.SYNOPSIS
    Reads Platform Key (PK), Key Exchange Key (KEK), and signature database (DB) certificates from UEFI.

.DESCRIPTION
    This script retrieves and displays Secure Boot certificates (PK, KEK, and DB) from UEFI firmware and optionally saves them to files.

.PARAMETER CertificateType
    Specifies which certificate type(s) to retrieve. Valid values are 'All', 'PK', 'KEK', and 'DB'. Use 'All' to retrieve all certificate types, or specify individual types. Multiple values can be specified as an array. If not specified, 'All' is used by default.

.PARAMETER OutFile
    Switch to enable saving certificates to files. When specified, certificates are saved to the folder specified by -OutPath. If -OutPath is not provided, files are saved to the user's temp directory ($env:temp). Files are named pkcert.cer, kekcert.cer, and dbcert.cer (with numeric suffixes if multiple certificates exist). Only certificates are saved; hashes are excluded from file output.

.PARAMETER OutPath
    Optional path to a folder where certificates will be saved when -OutFile is used. If not specified, certificates are saved to $env:temp by default.

.PARAMETER IncludeHashes
    Switch to include hash entries (SHA256, SHA1) in the output. By default, only certificates are displayed. Use this switch to also display hash-based signatures found in the signature database.

.EXAMPLE
    .\Get-UEFICertificate.ps1

    Returns all certificate objects (PK, KEK, and DB) without saving to files. Hashes are excluded by default.

.EXAMPLE
    .\Get-UEFICertificate.ps1 -CertificateType All

    Explicitly returns all certificate objects (PK, KEK, and DB) without saving to files. Hashes are excluded by default.

.EXAMPLE
    .\Get-UEFICertificate.ps1 -IncludeHashes

    Returns all certificate objects and hash entries (PK, KEK, and DB) without saving to files.

.EXAMPLE
    .\Get-UEFICertificate.ps1 -CertificateType DB -IncludeHashes

    Returns only the signature database (DB) entries including both certificates and hashes.

.EXAMPLE
    .\Get-UEFICertificate.ps1 -CertificateType PK

    Returns only the Platform Key (PK) certificate.

.EXAMPLE
    .\Get-UEFICertificate.ps1 -CertificateType PK, KEK

    Returns only the PK and KEK certificates.

.EXAMPLE
    .\Get-UEFICertificate.ps1 -OutFile

    Returns all certificate objects and saves them as base64-encoded .cer files in the user's temp directory.

.EXAMPLE
    .\Get-UEFICertificate.ps1 -OutFile -OutPath 'C:\Temp\UEFICertificates'

    Returns all certificate objects and saves them as base64-encoded .cer files in the specified folder.

.EXAMPLE
    .\Get-UEFICertificate.ps1 -CertificateType DB -OutFile -OutPath 'C:\SecureBoot'

    Returns only the signature database (DB) certificates and saves them to C:\SecureBoot directory.

.INPUTS
    None.

.OUTPUTS
    PSCustomObject representing each certificate with properties such as Type, Subject, Issuer, Thumbprint, Issued, Expires, SerialNumber, and methods to save the certificate to a file.

.LINK
    https://github.com/richardhicks/uefi/Get-UEFICertificate.ps1

.NOTES
    Version:        1.2.1
    Creation Date:  November 13, 2025
    Last Updated:   January 12, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

[CmdletBinding()]

Param (

    [Parameter()]
    [ValidateSet('All', 'PK', 'KEK', 'DB')]
    [Alias('Type')]
    [String[]]$CertificateType = 'All',
    [Switch]$OutFile,
    [String]$OutPath,
    [Switch]$IncludeHashes

)

# Script requires administrative privileges
#Requires -RunAsAdministrator

# Parse ESL (EFI Signature List) format
Function ConvertFrom-SignatureList {

    Param (

        [Byte[]]$Data

    )

    $Certificates = @()
    $Offset = 0

    While ($Offset -lt $Data.Length) {

        # ESL Header is 28 bytes
        If (($Data.Length - $Offset) -lt 28) {

            Break

        }

        # Read Signature Type GUID (16 bytes)
        $GuidBytes = $Data[$Offset..($Offset + 15)]
        $SignatureType = [Guid]::new([Byte[]]$GuidBytes)
        $Offset += 16

        # Read List Size (4 bytes)
        $ListSize = [BitConverter]::ToUInt32($Data, $Offset)
        $Offset += 4

        # Read Header Size (4 bytes)
        $HeaderSize = [BitConverter]::ToUInt32($Data, $Offset)
        $Offset += 4

        # Read Signature Size (4 bytes)
        $SignatureSize = [BitConverter]::ToUInt32($Data, $Offset)
        $Offset += 4

        If ($ListSize -eq 0 -or $SignatureSize -eq 0) {

            Break

        }

        # Skip signature list header
        If ($HeaderSize -gt 0) {

            $Offset += $HeaderSize

        }

        # Calculate number of signatures
        $DataSize = $ListSize - 28 - $HeaderSize
        $SigCount = [Math]::Floor($DataSize / $SignatureSize)

        # Extract each signature
        For ($I = 0; $I -lt $SigCount; $I++) {

            # Signature Header is 16 bytes (Owner GUID)
            If (($Offset + 16) -gt $Data.Length) {

                Break

            }

            $OwnerGuidBytes = $Data[$Offset..($Offset + 15)]
            $OwnerGuid = [Guid]::new([Byte[]]$OwnerGuidBytes)
            $Offset += 16

            # Certificate data
            $CertSize = $SignatureSize - 16
            If (($Offset + $CertSize) -gt $Data.Length) {

                Break

            }

            $CertData = $Data[$Offset..($Offset + $CertSize - 1)]
            $Offset += $CertSize

            $Certificates += [PSCustomObject]@{

                SignatureType   = $SignatureType
                OwnerGuid       = $OwnerGuid
                CertificateData = $CertData
                CertificateSize = $CertSize

            }

        }

    }

    Return $Certificates

}

# Convert certificate data to PEM format
Function ConvertTo-PemFormat {

    Param (

        [Byte[]]$CertificateData

    )

    $Base64 = [Convert]::ToBase64String($CertificateData)
    $Pem = "-----BEGIN CERTIFICATE-----`n"

    For ($I = 0; $I -lt $Base64.Length; $I += 64) {

        $Length = [Math]::Min(64, $Base64.Length - $I)
        $Pem += $Base64.Substring($I, $Length) + "`n"

    }

    $Pem += "-----END CERTIFICATE-----`n"

    Return $Pem

}

# Main script
Try {

    # Check if Secure Boot is available
    Try {

        $SecureBootStatus = Confirm-SecureBootUEFI

    }

    Catch {

        Write-Warning 'Unable to access UEFI Secure Boot information. This system may not support UEFI or Secure Boot.'
        Exit 1

    }

    Write-Verbose "Secure Boot Status: $SecureBootStatus."

    # Warn if Secure Boot is not enabled
    If (-not $SecureBootStatus) {

        Write-Warning 'Secure Boot is not enabled on this system. It must be enabled to successfully update UEFI Secure Boot certificates.'

    }

    # Determine output directory if -OutFile switch is used
    $OutputDirectory = $Null
    If ($OutFile) {

        # Use OutPath if provided, otherwise default to temp directory
        If ([String]::IsNullOrWhiteSpace($OutPath)) {

            $OutputDirectory = $env:temp
            Write-Verbose "Using default temp directory for output: $OutputDirectory"

        }
        Else {

            # Use provided path
            $OutputDirectory = $OutPath

            # Check if path looks like a file (has an extension)
            If ([System.IO.Path]::HasExtension($OutputDirectory)) {

                Write-Warning 'OutPath must be a folder path, not a file path. Please provide a folder path without a filename.'
                Exit 1

            }

            Write-Verbose "Using output directory: $OutputDirectory"

        }

        # Create directory if it doesn't exist
        If (-not (Test-Path $OutputDirectory)) {

            Write-Verbose "Output directory does not exist. Creating: $OutputDirectory"

            Try {

                New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
                Write-Verbose "Successfully created directory: $OutputDirectory"

            }

            Catch {

                Write-Warning "Failed to create directory '$OutputDirectory': $($_.Exception.Message)"
                Exit 1

            }

        }

        Else {

            # Verify it's a directory, not a file
            If (-not (Test-Path $OutputDirectory -PathType Container)) {

                Write-Warning "The path '$OutputDirectory' exists but is not a folder. Please provide a valid folder path."
                Exit 1

            }

        }

    }

    # Initialize results array, certificate counters, and saved files list
    $Results = @()
    $PkCount = 0
    $KekCount = 0
    $DbCount = 0
    $SavedFiles = @()

    # Define all available certificates
    $AllCertTypes = @(

        @{ Name = 'PK'; Description = 'Platform Key'; VariableName = 'pk' }
        @{ Name = 'KEK'; Description = 'Key Exchange Key'; VariableName = 'kek' }
        @{ Name = 'DB'; Description = 'Signature Database'; VariableName = 'db' }

    )

    # Filter based on CertificateType parameter
    If ($CertificateType -contains 'All') {

        $CertTypes = $AllCertTypes

    }

    Else {

        $CertTypes = $AllCertTypes | Where-Object { $CertificateType -contains $_.Name }

    }

    Write-Verbose "Retrieving certificate types: $($CertTypes.Name -join ', ')"

    ForEach ($CertType in $CertTypes) {

        Write-Verbose "Reading $($CertType.Description) ($($CertType.Name))..."

        Try {

            # Get UEFI variable
            $UefiVar = Get-SecureBootUEFI -Name $CertType.VariableName

            If ($Null -eq $UefiVar -or $Null -eq $UefiVar.Bytes -or $UefiVar.Bytes.Length -eq 0) {

                Write-Warning "No $($CertType.Name) certificate found or empty data."
                Continue

            }

            # Parse the signature list
            $Signatures = ConvertFrom-SignatureList -Data $UefiVar.Bytes

            If ($Signatures.Count -eq 0) {

                Write-Warning "Could not parse certificates from $($CertType.Name) data."
                Continue

            }

            Write-Verbose "Found $($Signatures.Count) signature(s)."

            # Create result object for each signature
            $SigIndex = 0
            ForEach ($Sig in $Signatures) {

                $SigIndex++

                # Define known signature type GUIDs
                $EFI_CERT_X509_GUID = 'a5c059a1-94e4-4aa7-87b5-ab155c2bf072'
                $EFI_CERT_SHA256_GUID = 'c1c41626-504c-4092-aca9-41f936934328'
                $EFI_CERT_SHA1_GUID = '826ca512-cf10-4ac9-b187-be01496631bd'
                $EFI_CERT_RSA2048_SHA256_GUID = 'e2b36190-879b-4a3d-ad8d-f2e7bba32784'

                # Check signature type and handle accordingly
                If ($Sig.SignatureType -eq $EFI_CERT_SHA256_GUID) {

                    # This is a SHA256 hash, not a certificate
                    $HashHex = ($Sig.CertificateData | ForEach-Object { $_.ToString('X2') }) -join ''

                    $CertInfo = @{

                        Subject      = 'SHA256 Hash'
                        Issuer       = 'SHA256 Hash'
                        Thumbprint   = $HashHex
                        Issued       = $Null
                        Expires      = $Null
                        SerialNumber = 'N/A'
                        ParseError   = $Null

                    }

                }

                ElseIf ($Sig.SignatureType -eq $EFI_CERT_SHA1_GUID) {

                    # This is a SHA1 hash, not a certificate
                    $HashHex = ($Sig.CertificateData | ForEach-Object { $_.ToString('X2') }) -join ''

                    $CertInfo = @{

                        Subject      = 'SHA1 Hash'
                        Issuer       = 'SHA1 Hash'
                        Thumbprint   = $HashHex
                        Issued       = $Null
                        Expires      = $Null
                        SerialNumber = 'N/A'
                        ParseError   = $Null

                    }

                }

                ElseIf ($Sig.SignatureType -eq $EFI_CERT_X509_GUID) {

                    # This is an X.509 certificate - standard format
                    Try {

                        $Cert = $Null
                        $ParseError = $Null

                        # Method 1: Direct parsing
                        Try {

                            $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New($Sig.CertificateData)

                        }

                        Catch {

                            $ParseError = $_.Exception.Message

                        }

                        # Method 2: Try parsing with explicit type
                        If ($Null -eq $Cert) {

                            Try {

                                $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New([Byte[]]$Sig.CertificateData)

                            }

                            Catch {

                                $ParseError = $_.Exception.Message

                            }

                        }

                        If ($Null -ne $Cert) {

                            $CertInfo = @{

                                Subject      = $Cert.Subject
                                Issuer       = $Cert.Issuer
                                Thumbprint   = $Cert.Thumbprint
                                Issued       = $Cert.NotBefore
                                Expires      = $Cert.NotAfter
                                SerialNumber = $Cert.SerialNumber
                                ParseError   = $Null

                            }

                        }

                        Else {

                            $CertInfo = @{

                                Subject      = 'Unable to parse X.509 certificate'
                                Issuer       = 'Unable to parse X.509 certificate'
                                Thumbprint   = 'N/A'
                                Issued       = $Null
                                Expires      = $Null
                                SerialNumber = 'N/A'
                                ParseError   = $ParseError

                            }

                        }

                    }

                    Catch {

                        $CertInfo = @{

                            Subject      = 'Error parsing X.509 certificate'
                            Issuer       = 'Error parsing X.509 certificate'
                            Thumbprint   = 'N/A'
                            Issued       = $Null
                            Expires      = $Null
                            SerialNumber = 'N/A'
                            ParseError   = $_.Exception.Message

                        }

                    }

                }

                ElseIf ($Sig.SignatureType -eq $EFI_CERT_RSA2048_SHA256_GUID) {

                    # This is an RSA2048-SHA256 signature
                    $CertInfo = @{

                        Subject      = 'RSA2048-SHA256 Signature'
                        Issuer       = 'RSA2048-SHA256 Signature'
                        Thumbprint   = 'N/A'
                        Issued       = $Null
                        Expires      = $Null
                        SerialNumber = 'N/A'
                        ParseError   = $Null

                    }

                }

                Else {

                    # Unknown signature type - attempt generic parsing
                    Try {

                        $Cert = $Null
                        $ParseError = $Null

                        Try {

                            $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::New($Sig.CertificateData)

                        }

                        Catch {

                            $ParseError = $_.Exception.Message

                        }

                        If ($Null -ne $Cert) {

                            $CertInfo = @{

                                Subject      = $Cert.Subject
                                Issuer       = $Cert.Issuer
                                Thumbprint   = $Cert.Thumbprint
                                Issued       = $Cert.NotBefore
                                Expires      = $Cert.NotAfter
                                SerialNumber = $Cert.SerialNumber
                                ParseError   = $Null

                            }

                        }

                        Else {

                            $CertInfo = @{

                                Subject      = "Unknown signature type: $($Sig.SignatureType)"
                                Issuer       = "Unknown signature type: $($Sig.SignatureType)"
                                Thumbprint   = 'N/A'
                                Issued       = $Null
                                Expires      = $Null
                                SerialNumber = 'N/A'
                                ParseError   = $ParseError

                            }

                        }

                    }

                    Catch {

                        $CertInfo = @{

                            Subject      = "Unknown signature type: $($Sig.SignatureType)"
                            Issuer       = "Unknown signature type: $($Sig.SignatureType)"
                            Thumbprint   = 'N/A'
                            Issued       = $Null
                            Expires      = $Null
                            SerialNumber = 'N/A'
                            ParseError   = $_.Exception.Message

                        }

                    }

                }

                # Skip hashes unless -IncludeHashes is specified
                $IsHash = $CertInfo.Subject -in @('SHA256 Hash', 'SHA1 Hash')

                If ($IsHash -and -not $IncludeHashes) {

                    Write-Verbose "Skipping hash entry (use -IncludeHashes to display): $($CertInfo.Subject)"
                    Continue

                }

                $ResultObj = [PSCustomObject]@{

                    Type            = $CertType.Name.ToUpper()
                    Description     = $CertType.Description
                    Index           = $SigIndex
                    SignatureType   = $Sig.SignatureType
                    OwnerGuid       = $Sig.OwnerGuid
                    CertificateSize = $Sig.CertificateSize
                    Subject         = $CertInfo.Subject
                    Issuer          = $CertInfo.Issuer
                    Thumbprint      = $CertInfo.Thumbprint
                    Issued          = $CertInfo.Issued
                    Expires         = $CertInfo.Expires
                    SerialNumber    = $CertInfo.SerialNumber
                    ParseError      = $CertInfo.ParseError
                    RawData         = $Sig.CertificateData

                }

                # Add Save method
                $ResultObj | Add-Member -MemberType ScriptMethod -Name 'SaveToFile' -Value {

                    Param (

                        [String]$Path

                    )

                    If ([String]::IsNullOrWhiteSpace($Path)) {

                        Throw 'Path parameter is required'

                    }

                    $Dir = Split-Path -Path $Path -Parent
                    If ($Dir -and -not (Test-Path $Dir)) {

                        New-Item -ItemType Directory -Path $Dir -Force | Out-Null

                    }

                    # Convert to PEM format using helper function
                    $Pem = ConvertTo-PemFormat -CertificateData $This.RawData
                    [System.IO.File]::WriteAllText($Path, $Pem)

                    Write-Output "Saved to: $Path"

                }

                $Results += $ResultObj

                # Handle -OutFile switch (skip hashes)
                If ($OutputDirectory -and -not $IsHash) {

                    # Determine filename based on certificate type and count
                    If ($CertType.Name -eq 'PK') {

                        $PkCount++
                        $Filename = If ($PkCount -eq 1) {

                            'pkcert.cer'

                        }

                        Else {

                            "pkcert$PkCount.cer"

                        }

                    }

                    ElseIf ($CertType.Name -eq 'KEK') {

                        $KekCount++
                        $Filename = If ($KekCount -eq 1) {

                            'kekcert.cer'

                        }

                        Else {

                            "kekcert$KekCount.cer"

                        }

                    }

                    Else {

                        $DbCount++
                        $Filename = If ($DbCount -eq 1) {

                            'dbcert.cer'

                        }

                        Else {

                            "dbcert$DbCount.cer"

                        }

                    }

                    $Filepath = Join-Path $OutputDirectory $Filename

                    # Save in proper PEM format using helper function
                    $Pem = ConvertTo-PemFormat -CertificateData $Sig.CertificateData
                    [System.IO.File]::WriteAllText($Filepath, $Pem)

                    # Store filepath for display at end
                    $SavedFiles += $Filepath

                }

            }

        }

        Catch {

            Write-Warning "Error reading $($CertType.Name): $($_.Exception.Message)"

        }

    }

    # Return results
    If ($Results.Count -eq 0) {

        Write-Warning 'No certificates were retrieved.'
        Exit 1

    }

    Write-Verbose "Successfully retrieved $($Results.Count) certificate(s)."

    # Output results first (they will be displayed)
    $Results

    # Display saved files after the objects
    If ($SavedFiles.Count -gt 0) {

        ForEach ($File in $SavedFiles) {

            Write-Output "Saved certificate to: $File"

        }

    }

}

Catch {

    Write-Warning "An unexpected error occurred: $($_.Exception.Message)"
    Write-Warning $_.ScriptStackTrace
    Exit 1

}

# SIG # Begin signature block
# MIIf2wYJKoZIhvcNAQcCoIIfzDCCH8gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBN2tBc6MqkrGt6
# AD6xmBy1bHbbeClUoBoiA9bfP5XMX6CCGpkwggNZMIIC36ADAgECAhAPuKdAuRWN
# A1FDvFnZ8EApMAoGCCqGSM49BAMDMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMT
# F0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMB4XDTIxMDQyOTAwMDAwMFoXDTM2MDQy
# ODIzNTk1OVowZDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9iYWwgRzMgQ29kZSBTaWduaW5nIEVDQyBT
# SEEzODQgMjAyMSBDQTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS7tKwnpUgNolNf
# jy6BPi9TdrgIlKKaqoqLmLWx8PwqFbu5s6UiL/1qwL3iVWhga5c0wWZTcSP8GtXK
# IA8CQKKjSlpGo5FTK5XyA+mrptOHdi/nZJ+eNVH8w2M1eHbk+HejggFXMIIBUzAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSbX7A2up0GrhknvcCgIsCLizh3
# 7TAfBgNVHSMEGDAWgBSz20ik+aHF2K42QcwRY2liKbxLxjAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcnQw
# QgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0R2xvYmFsUm9vdEczLmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEE
# ATAKBggqhkjOPQQDAwNoADBlAjB4vUmVZXEB0EZXaGUOaKncNgjB7v3UjttAZT8N
# /5Ovwq5jhqN+y7SRWnjsBwNnB3wCMQDnnx/xB1usNMY4vLWlUM7m6jh+PnmQ5KRb
# qwIN6Af8VqZait2zULLd8vpmdJ7QFmMwggP+MIIDhKADAgECAhANSjTahpCPwBMs
# vIE3k68kMAoGCCqGSM49BAMDMGQxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE8MDoGA1UEAxMzRGlnaUNlcnQgR2xvYmFsIEczIENvZGUgU2ln
# bmluZyBFQ0MgU0hBMzg0IDIwMjEgQ0ExMB4XDTI0MTIwNjAwMDAwMFoXDTI3MTIy
# NDIzNTk1OVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
# FAYDVQQHEw1NaXNzaW9uIFZpZWpvMSQwIgYDVQQKExtSaWNoYXJkIE0uIEhpY2tz
# IENvbnN1bHRpbmcxJDAiBgNVBAMTG1JpY2hhcmQgTS4gSGlja3MgQ29uc3VsdGlu
# ZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFCbtcqpc7vGGM4hVM79U+7f0tKz
# o8BAGMJ/0E7JUwKJfyMJj9jsCNpp61+mBNdTwirEm/K0Vz02vak0Ftcb/3yjggHz
# MIIB7zAfBgNVHSMEGDAWgBSbX7A2up0GrhknvcCgIsCLizh37TAdBgNVHQ4EFgQU
# KIMkVkfISNUyQJ7bwvLm9sCIkxgwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggr
# BgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBqwYDVR0fBIGjMIGgME6gTKBKhkho
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWdu
# aW5nRUNDU0hBMzg0MjAyMUNBMS5jcmwwTqBMoEqGSGh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEczQ29kZVNpZ25pbmdFQ0NTSEEzODQyMDIx
# Q0ExLmNybDCBjgYIKwYBBQUHAQEEgYEwfzAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMFcGCCsGAQUFBzAChktodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWduaW5nRUNDU0hBMzg0MjAy
# MUNBMS5jcnQwCQYDVR0TBAIwADAKBggqhkjOPQQDAwNoADBlAjBMOsBb80qx6E6S
# 2lnnHafuyY2paoDtPjcfddKaB1HKnAy7WLaEVc78xAC84iW3l6ECMQDhOPD5JHtw
# YxEH6DxVDle5pLKfuyQHiY1i0I9PrSn1plPUeZDTnYKmms1P66nBvCkwggWNMIIE
# daADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAe
# Fw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# ITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC
# 4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWl
# fr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1j
# KS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dP
# pzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3
# pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJ
# pMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aa
# dMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXD
# j/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB
# 4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ
# 33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amy
# HeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYD
# VR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcN
# AQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxpp
# VCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6
# mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPH
# h6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCN
# NWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg6
# 2fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8h
# mS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0z
# ODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGP
# NRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1I
# pYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5A
# vftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDRe
# b6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBUR
# Jg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/ao
# fEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQ
# skBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJ
# lIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev
# +7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6B
# aaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IB
# XTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQ
# VvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9
# vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwb
# SI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTL
# xLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD
# 8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVk
# o43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRa
# Ps+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8
# cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRz
# W6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KC
# LPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau
# 1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPS
# xyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0
# aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1w
# aW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2
# MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAg
# UmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdw
# bHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9
# RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrU
# cCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iU
# SROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw
# 2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe4
# 6YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seA
# O+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSH
# lq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6
# EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDch
# Ic2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAM
# BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNV
# HSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFt
# cGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3Rh
# bXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezR
# CESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0
# k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFO
# tj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLW
# U0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2n
# HkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIF
# eRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqR
# hoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7
# roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47Cdx
# VRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/r
# ptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL
# 6vdCvHlshtjdNXOCIUjsarfNZzGCBJgwggSUAgEBMHgwZDELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9i
# YWwgRzMgQ29kZSBTaWduaW5nIEVDQyBTSEEzODQgMjAyMSBDQTECEA1KNNqGkI/A
# Eyy8gTeTryQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgCqkLw6F1v7ASqOCutlPWKDz4
# kjmwcW0CHawchLzFYAUwCwYHKoZIzj0CAQUABEgwRgIhAJdhSgIXIF+HI2Cxj/lP
# 4WWBYmxjMP7KeF3PlWlImIghAiEA8KHgUXvSx35KC0O+Hp1BiNaxSo2vI7cyf+Ns
# ErklAGihggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# AhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwMTEyMjIyMzQ4WjAvBgkq
# hkiG9w0BCQQxIgQg70gHYlfHg0jGJ65xaAHsEF2V2LkTbCMHO3rTvaQ2i+MwDQYJ
# KoZIhvcNAQEBBQAEggIAep3MqHyQMMX54NxqScoOl+sJxqj6Mc7Or+bftDlKJSjo
# OQlicI37DinaAKJdmHozsrjJWtaunLZQZot5hfmk+9FbgDk55a0iY3CVfUxCHGzH
# js7nRyejjMt/C9EkhTA5yjPH+6ldxOp8KSN+jiACZygOyUYJ/t2lFpEAB05MkImc
# pN84mKlmYKMx3T+1vbxo68KHsodz087C9upbLFnSyB1FYU2+FSKVEM0NVFO/D36A
# 3Jb93EtvUsdbfK9r/BnIQ2XialS4otb2oCGeqsMQc6XEq18jKkm+hrviZVGUosRo
# PKXi8eztWhx4e/DIFba6iyNsrFFFbfYJzMjMOHOZ8rNF2Zs+CS47GQM5u//O43NO
# ldpE8EnNYYocm5cnJnP5z6rDIyKDADGC3TLNT6sq+Kmq31/oHa1bTOLV321uDnG2
# PLDQMFvqTdr1KK54/nwOuDyvXAfw36rpJrOGgIBnQWb1gmp/cF2V8iSe3lW8bl1W
# cpCdSvLlH9/wKmmS7FlP0x1Js7dX2wc/+sVlL/XdmAviHT8yCj9Lc8scQbGPM/U3
# GlZhO9pnRw6PwTv9hxAG/HtdgdTzWzeVYlleljMxVm2NEndkgZA4tPCSmaCLkbMP
# evSfxgKJn/b9VV3R+cu13AEcOq6z4ocPPKxGhlMkePNtxtTSucZGlrATpnNJDeo=
# SIG # End signature block
