# pgSDK

================Demo=========================
package main

import (
	"fmt"
	"github.com/mingus2021/pgSDK"
)

const (
	url  = "192.168.2.21:8083"
	path = "lc.pem"
)

func main() {
	pgInterface := pgSDK.NewPGinterface()
	code,err := pgInterface.VerifyClientCertSignature(url, path)
	if err != nil {
		fmt.Printf("Failed to verify client certificate signature: %v[%d]\n", err, code)
	}
}

================Demo=========================

================interface====================      

  -key
        generate RSA Key
        interface：pgInterface.GeneratePGKey()
-------------------------------------------      
  -list
        list certificate content
        interface：pgInterface.PrintCertContent(path)
-------------------------------------------      
  -verify
        verify certificate
        interface：pgInterface.VerifyClientCertSignature(url, path)
	
 	[code&err]:
  	1, "Failed to read CA certificate"
   
	2, "Failed to decode PEM block containing the certificate"
 
	3, "Failed to parse client certificate"
 
	4, "Certificate has expired"
 
	5, "Error syncing CRL"
 
	6, "The specified CA server is invalid, and the verification has failed"
 
	7, "The SerialNumber is revoked"
 
	8, "Error loading RSA public key"
 
	9, "Failed to hash TBS certificate"
 
	10, "failed to verify signature" 
 -------------------------------------------
  -url string
        set server url
 -------------------------------------------       
  -path string
        set the path of certificate file   
 -------------------------------------------         
  -ca string
        Path to the certificate request file (JSON format)
 ------------------------------------------- 
 ================interface====================       
