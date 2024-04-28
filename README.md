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
