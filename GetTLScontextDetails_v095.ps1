# Written by Enrico Jost, December 2023
# Version 0.9.5 - BETA
# GNU General Public License v3.0

# Versions 0.1 - 0.7 : initial codings, review, re-designs
# Version 0.8 : Working script, only HTTP without choice of protocol
# Version 0.9 : Added HTTP-HTTPS choice as well as certificate validation skipping (Credits to Bjorn Van Leemput - AudioCodes)
# Version 0.9.5 : Added Expiration calculation based on cert property NotAfter + current date, adjusted script output to display it

# Features planned:
# Input via csv file
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

                # Define variable name
                $variableName = "Response${endpoint -replace '/','-'}"

                # Store certificate content in the variable
                Set-Variable -Name $variableName -Value $certContent


            # Decode and display certificate information
            $certBase64 = $certContent
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($certBase64))

            # Store the "NotAfter" attribute in expiresCount variable
            $Expiration = $cert.NotAfter

            # Calculate remaining days until the certificate expires
            $daysUntilExpiration = ($Expiration - (Get-Date)).Days

            # Output information about the stored certificate with remaining days
            Write-Output "Stored cert for TLS context $($tlsContext):"
            Write-Output $certContent
           

            $cert | Select-Object Issuer, Subject, NotBefore, NotAfter | Format-List *
			
			Write-Output "Certificate expires in $daysUntilExpiration days." `n
			 
        } else {
            Write-Output "Certificate content not found for TLS context $($tlsContext)"
        }
    }
}
}

# Get user input for HTTP or HTTPS
$useHttps = Read-Host "Choose protocol:`n1. HTTP`n2. HTTPS`nEnter '1' for HTTP or '2' for HTTPS"

# Validate user input
if ($useHttps -eq '1' -or $useHttps -eq '2') {
    $useHttps = ($useHttps -eq '2')
} else {
    Write-Host "Invalid choice. Defaulting to HTTP."
    $useHttps = $false
}

# Get user input
$ip = Read-Host "Enter SBC IP address"
$username = Read-Host "Enter username"
$password = Read-Host -Prompt "Enter password" -AsSecureString

# Convert SecureString to plain text password
$passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

# Invoke the Get-Certificates function
$certificates = Get-Certificates -ip $ip -username $username -password $passwordPlain -useHttps $useHttps

# Output TLS contexts
if ($certificates) {
    Write-Host "TLS Contexts:" `n
    $certificates
}

# End of the script
Read-Host "Press Enter to exit"
