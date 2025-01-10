# Written by Enrico Jost, December 2023
# Version 0.9.6 - BETA
# GNU General Public License v3.0

# Versions 0.1 - 0.7 : initial codings, review, re-designs
# Version 0.8 : Working script, only HTTP without choice of protocol
# Version 0.9 : Added HTTP-HTTPS choice as well as certificate validation skipping (Credits to Bjorn Van Leemput - AudioCodes)
# Version 0.9.5 : Added Expiration calculation based on cert property NotAfter + current date, adjusted script output to display it
# Version 0.9.6 : Added SBC-input via CSV, Added Output via CSV - including device-IP, CN, expiration date, TLS Context number (will do multiple lines if multiple TLS contexts exist)

# Features planned:
# GUI to choose between HTTP/HTTPS
# GUI is going to include a choice between individual TLS-contexts or all of them
# Different output options in planning

# Setting TLS preference for older PS versions
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Function to extract and store certificates from API responses
function Get-Certificates {
    param (
        [string]$ip,
        [string]$username,
        [string]$password,
        [bool]$useHttps
    )

    # Build Authorization Header
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}"))
    $AuthorizationHeader = "Basic $base64AuthInfo"

    # Choose between HTTP and HTTPS
    $protocol = if ($useHttps) { "https" } else { "http" }

    # Get TLS contexts from the INI file
    try {
        $configEndpoint = "/api/v1/files/ini"
        $configUrl = "${protocol}://${ip}$configEndpoint"

        # Ignore certificate validation for this specific call
        if ($useHttps) {
            if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
                $certCallback = @"
                    using System;
                    using System.Net;
                    using System.Net.Security;
                    using System.Security.Cryptography.X509Certificates;
                    public class ServerCertificateValidationCallback
                    {
                        public static void Ignore()
                        {
                            if(ServicePointManager.ServerCertificateValidationCallback ==null)
                            {
                                ServicePointManager.ServerCertificateValidationCallback += 
                                    delegate
                                    (
                                        Object obj, 
                                        X509Certificate certificate, 
                                        X509Chain chain, 
                                        SslPolicyErrors errors
                                    )
                                    {
                                        return true;
                                    };
                            }
                        }
                    }
"@
                Add-Type $certCallback
            }

            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
            [ServerCertificateValidationCallback]::Ignore()
        }

        $configResponse = Invoke-RestMethod -Uri $configUrl -Headers @{ 'Authorization' = $AuthorizationHeader } -ErrorAction Stop
    } catch {
        Write-Host "Error getting TLS contexts from the config: $_"
        return $null
    }

    if ($configResponse) {
        # Extract TLS contexts using regex
        $tlsContexts = $configResponse -split '\r?\n' | Where-Object { $_ -match 'TLSContexts (\d+)' } | ForEach-Object { $matches[1] }
    } else {
        Write-Host "Error getting TLS contexts from the config."
        return $null
    }

    if ($tlsContexts.Count -eq 0) {
        Write-Host "No TLS contexts found in the config."
        return $null
    }

    # Initialize an array to store CNs, expiration dates, and TLS Context for each IP
    $cnList = @()

    # Loop through each TLS context
    foreach ($tlsContext in $tlsContexts) {
        $endpoint = "/api/v1/files/tls/$tlsContext/certificate"
        
        # Adjust the URL based on the user's choice of HTTP or HTTPS
        $url = "${protocol}://${ip}$endpoint"
        
        # Ignore certificate validation for this specific call
        if ($useHttps) {
            if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type) {
                $certCallback = @"
                    using System;
                    using System.Net;
                    using System.Net.Security;
                    using System.Security.Cryptography.X509Certificates;
                    public class ServerCertificateValidationCallback
                    {
                        public static void Ignore()
                        {
                            if(ServicePointManager.ServerCertificateValidationCallback ==null)
                            {
                                ServicePointManager.ServerCertificateValidationCallback += 
                                    delegate
                                    (
                                        Object obj, 
                                        X509Certificate certificate, 
                                        X509Chain chain, 
                                        SslPolicyErrors errors
                                    )
                                    {
                                        return true;
                                    };
                            }
                        }
                    }
"@
                Add-Type $certCallback
            }

            [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
            [ServerCertificateValidationCallback]::Ignore()
        }

        $response = Invoke-RestMethod -Uri $url -Headers @{ 'Authorization' = $AuthorizationHeader } -ErrorAction SilentlyContinue

        if ($response) {
            # Extract certificate content
            $certContent = $response -replace "(?s).*?(-----BEGIN CERTIFICATE-----)(.*?)(-----END CERTIFICATE-----).*", '$2'

            if ($certContent) {
                # Remove leading/trailing whitespaces
                $certContent = $certContent.Trim()

                # Decode the certificate content and extract the CN and expiration date
                $certBase64 = $certContent
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($certBase64))

                # Extract the CN (Common Name) from the certificate's Subject field
                $subject = $cert.Subject
                $cnMatch = $subject -match "CN=([^\s,]+)"
                if ($cnMatch) {
                    $cn = $matches[1] # CN is captured in $matches[1]
                    # Get the NotAfter (expiration date)
                    $notAfter = $cert.NotAfter

                    # Store the CN along with the IP, expiration date, and TLS context index
                    $cnList += [PSCustomObject]@{
                        IP = $ip
                        CN = $cn
                        ExpirationDate = $notAfter
                        TLSContext = $tlsContext
                    }
                } else {
                    Write-Output "CN not found in the certificate for TLS context $($tlsContext)"
                }
            }
        } else {
            Write-Output "Certificate content not found for TLS context $($tlsContext)"
        }
    }

    return $cnList
}

# Read CSV file for input
$csvFilePath = Read-Host "Enter the path to the CSV file (e.g., C:\path\to\file.csv)"
if (-not (Test-Path $csvFilePath)) {
    Write-Host "CSV file not found at the specified path. Exiting."
    exit
}

# Import CSV and loop through each row
$csvData = Import-Csv -Path $csvFilePath
$allCNs = @()

foreach ($row in $csvData) {
    # Get protocol choice based on CSV data
    $useHttps = if ($row.Protocol -eq "HTTPS") { $true } else { $false }

    # Get user input for IP, username, password from CSV
    $ip = $row.IP
    $username = $row.Username
    $password = $row.Password

    # Invoke the Get-Certificates function for each entry
    Write-Host "Processing IP: $ip (Protocol: $($row.Protocol))"
    $cnList = Get-Certificates -ip $ip -username $username -password $password -useHttps $useHttps

    # Add the CNs, expiration dates, and TLS contexts to the overall list
    $allCNs += $cnList
}

# Define the output CSV file path (same as input but with 'export' suffix)
$exportCsvPath = [System.IO.Path]::Combine([System.IO.Path]::GetDirectoryName($csvFilePath), 'export.csv')

# Export the results to CSV
$allCNs | Export-Csv -Path $exportCsvPath -NoTypeInformation

Write-Host "Export complete. Data saved to $exportCsvPath"
Read-Host "Press Enter to exit"
