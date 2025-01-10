# GetTLScontextDetails

 GetTLScontextDetails Script to receive details about every configured TLS context (cert) on an AudioCodes SBC - utilizing REST API via HTTP or HTTPS.
 
This script uses a CSV input (IP, protocol, credentials) 
 It will login to the SBC, grab the full INI file and parse it. 
 It will store all configured TLS context indexes into variables.
 
 It will build REST API requests to receive the full certificate (base64 encoded) from the AudioCodes SBC - which it stores again.
 
 Afterwards it will convert these inputs into human readable outputs and export: CN, NotAfter, TLS-context-ID

## published under GNU General Public License v3.0
