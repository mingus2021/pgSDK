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
	generator := pgSDK.NewRSAKeyGenerator()
	err, code := generator.VerifyClientCertSignature(url, path)
	if err != nil {
		fmt.Printf("Failed to verify client certificate signature: %v[%d]\n", err, code)
	}
}
================Demo=========================

================interface====================      

  -key
        generate RSA Key
        interface：generator.GenerateRSAKey()
-------------------------------------------      
  -list
        list certificate content
        interface：generator.PrintCertContent(path)
-------------------------------------------      
  -verify
        verify certificate
        interface：generator.VerifyClientCertSignature(url, path)
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
