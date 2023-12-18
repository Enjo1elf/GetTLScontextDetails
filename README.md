# GetTLScontextDetails

A Powershell script to connect to an AudioCodes SBC and receive readable certificate details.

The script will connect to the AudioCodes SBC and request the FULL ini via REST-API.
Afterwards the script will go through the INI, searching for TLScontexts.
Each TLScontext #index number will be stored in a variable and will be used to create REST-API URLs.
These URLs are used to request certificate information for each and every configured TLS context.
The REST response for such a request is in base64 encoding, hence why the script stores it in new variables - and as last step:
Makes it "human readable" and shares the output for following certificate details: 
Issuer, Subject, NotBefore, NotAfter
