<#PSScriptInfo

.VERSION 1.2

.GUID 7c06efd4-2530-487d-b92c-d5874d0b53b3

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2025 Richard M. Hicks Consulting, Inc. All Rights Reserved.

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
    Version:        1.2
    Creation Date:  November 13, 2025
    Last Updated:   November 17, 2025
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
