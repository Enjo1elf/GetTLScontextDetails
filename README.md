# GetTLScontextDetails

 GetTLScontextDetails Script to receive details about every configured TLS context (cert) on an AudioCodes SBC - utilizing REST API via HTTP or HTTPS.#
 
 This Script will ask for IP address of the SBC, give a choice for connection type and needs user credentials for a REST API permitted user.
 
 It will login to the SBC, grab the full INI file and parse it. It will store all configured TLS context indexes into variables.
 It will build REST API requests to receive the full certificate (base64 encoded) from the AudioCodes SBC - which it stores again.
 
 Afterwards it will convert these inputs into human readable outputs and will show the details for: Issuer, Subject, NotBefore, NotAfter
 ... as well as a calculated expiration time in days for each and every certificate.



## published under GNU General Public License v3.0
