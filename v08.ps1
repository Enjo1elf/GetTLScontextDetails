
# Written by Enrico Jost, December 2023
# Version 0.8 - stil BETA

# Still work in progress
# Features planned: GUI to choose between HTTP/HTTPS
# GUI is going to include a choice between individual TLS-contexts or all of them
# Different output options in planning
# Only tested for HTTP connection, HTTPS in progress

# Function to extract and store certificates from API responses
function Get-Certificates {
    param (
        [string]$ip,
        [string]$username,
        [string]$password
    )

    # Build Authorization Header
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("${username}:${password}")))
    $AuthorizationHeader = "Basic $base64AuthInfo"

    # Get TLS contexts from the INI file
    try {
        $configResponse = Invoke-RestMethod -Uri "http://${ip}/api/v1/files/ini" -Headers @{ 'Authorization' = $AuthorizationHeader } -ErrorAction Stop
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
        $url = "http://${ip}$endpoint"
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

                # Output information about the stored certificate
                Write-Output "Stored cert for TLS context $($tlsContext):"
                
                Write-Output $certContent

                # Decode and display certificate information
                $certBase64 = $certContent
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([System.Convert]::FromBase64String($certBase64))
                $cert | Select-Object Issuer, Subject, NotBefore, NotAfter | Format-List *
            } else {
                Write-Output "Certificate content not found for TLS context $($tlsContext)"
            }
        }
    }
}

# Get user input
$ip = Read-Host "Enter SBC IP address"
$username = Read-Host "Enter username"
$password = Read-Host -Prompt "Enter password" -AsSecureString

# Convert SecureString to plain text password
$passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password))

# Invoke the Get-Certificates function
Get-Certificates -ip $ip -username $username -password $passwordPlain
