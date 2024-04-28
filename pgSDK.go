package pgSDK

import (
	"bufio"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

const (
	privateKeyFile = "private_key.pem"
	publicKeyFile  = "public_key.pem"
	jsonFilePath   = "servers.json" // JSON文件的路径
)

var servers []ServerConfig
var certFilename string
var serverURL string

// ServerConfig 表示服务器配置
type ServerConfig struct {
	Wallet    common.Address `json:"wallet"`
	IP        string         `json:"ip"`
	PublicKey string         `json:"public_key"`
	Level     uint8          `json:"level"`
	Valid     bool           `json:"valid"`
	Superiors common.Address `json:"superiors"`
}

// CertRequest 包含客户端请求的证书信息
type CertRequest struct {
	CommonName         string `json:"commonName"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	SerialNumber       string `json:"serialNumber"`
	Country            string `json:"country"`
	Province           string `json:"province"`
	Locality           string `json:"locality"`
	StreetAddress      string `json:"streetAddress"`
	PostalCode         string `json:"postalCode"`
	EmailAddresses     string `json:"emailAddresses"`
	PublicKey          string `json:"publicKey"`
}

// PGinterface 接口定义
type PGinterface interface {
	SetCertFilePath(path string)
	SetServerAddr(addr string)
	GeneratePGKey() error
	VerifyClientCertSignature(serverURL string, certFilename string) (int, error)

	PrintCertContent(certFilename string) error
	SendCertRequest(certReq CertRequest, serverURL string, certFilename string) error
	ReadCertRequest(inputFilePath string) (CertRequest, error)
}

// PGinterfaceImpl 实现了PGinterface接口
type PGinterfaceImpl struct{}

// NewPGinterface 创建一个新的PGinterface实例
func NewPGinterface() PGinterface {
	return &PGinterfaceImpl{}
}

// 设置证书文件路径的函数
func (g *PGinterfaceImpl) SetCertFilePath(path string) {
	certFilename = path
	fmt.Println("set certFilename:", certFilename)
}

// 设置服务器地址的函数
func (g *PGinterfaceImpl) SetServerAddr(addr string) {
	serverURL = addr
	fmt.Println("set serverURL:", serverURL)
}

// 生成公钥和私钥
func (g *PGinterfaceImpl) GeneratePGKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("Failed to generate RSA public and private keys: %v", err)
	}

	// 将私钥保存到文件
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privateKeyBytes})
	err = os.WriteFile(privateKeyFile, privateKeyPEM, 0644)
	if err != nil {
		return fmt.Errorf("Failed to save privatekey to file: %v", err)
	}
	log.Printf("Private key saved to %s\n", privateKeyFile)

	publicKey := &privateKey.PublicKey
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("Failed to save publickey to file: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})

	ioutil.WriteFile(publicKeyFile, publicKeyPEM, 0644)
	log.Printf("Public key saved to %s\n", publicKeyFile)
	return nil
}

// readCertRequest 从JSON文件中读取证书请求
func (g *PGinterfaceImpl) ReadCertRequest(inputFilePath string) (CertRequest, error) {
	certReqBytes, err := ioutil.ReadFile(inputFilePath)
	if err != nil {
		return CertRequest{}, fmt.Errorf("failed to read certificate request file: %v", err)
	}

	var certReq CertRequest
	if err := json.Unmarshal(certReqBytes, &certReq); err != nil {
		return CertRequest{}, fmt.Errorf("failed to parse certificate request: %v", err)
	}
	return certReq, nil
}

// sendCertRequest 发送证书请求到服务端
func (g *PGinterfaceImpl) SendCertRequest(certReq CertRequest, serverURL string, certFilename string) error {
	jsonData, err := json.Marshal(certReq)
	if err != nil {
		return fmt.Errorf("failed to marshal certificate request: %v", err)
	}
	req, err := http.NewRequest("POST", "http://"+serverURL+"/issueCertificate", strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request to server: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("server returned non-200 status: %d, failed to read response body: %v", resp.StatusCode, err)
		}
		defer resp.Body.Close()
		return fmt.Errorf("server returned non-200 status: %d, response body: %s", resp.StatusCode, bodyBytes)
	}
	// 读取请求体中的证书内容
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Failed to read request body")
	}
	defer resp.Body.Close()
	// 解析PEM编码的证书
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatalf("Invalid certificate format.")
	}
	// 保存证书到文件
	certOut, err := os.Create(certFilename)
	if err != nil {
		return fmt.Errorf("Failed to Create pem")
	}
	defer certOut.Close()
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})
	log.Printf("Certificate received and saved to %s\n", certFilename)

	return nil
}

// printCertContent 打印证书内容
func (g *PGinterfaceImpl) PrintCertContent(certFilename string) error {
	certData, err := ioutil.ReadFile(certFilename)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block from certificate file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	fmt.Printf("Subject: %s\n", cert.Subject)
	fmt.Printf("Issuer: %s\n", cert.Issuer)
	fmt.Printf("Serial Number: %s\n", hex.EncodeToString(cert.SerialNumber.Bytes()))
	fmt.Printf("Valid From: %s\n", cert.NotBefore)
	fmt.Printf("Valid Until: %s\n", cert.NotAfter)
	fmt.Printf("EmailAddresses: %s\n", cert.EmailAddresses)
	// 可以继续添加其他证书字段的打印逻辑

	return nil
}

// verifyClientCertSignature 使用端CA公钥验证客户端证书的签名
func (g *PGinterfaceImpl) VerifyClientCertSignature(serverURL string, certFilename string) (int, error) {
	if err := syncCRL(serverURL); err != nil {
		//log.Fatalf("Error syncing CRL: %v", err)
		return 1, fmt.Errorf("Error syncing CRL: %v", err)
	}
	// 调用函数获取 PublicKey
	publicKey, found := getPublicKeyByIP(serverURL)
	if found {
		//fmt.Printf("找到的公钥为: %s\n", publicKey)
	} else {
		return 2, fmt.Errorf("The specified CA server is invalid, and the verification has failed")
	}
	// 加载RSA公钥
	rsaPubKey, err := stringToPublicKey(publicKey)
	if err != nil {
		return 3, fmt.Errorf("Error loading RSA public key: %v", err)
	}
	// 读取待验证的CA证书
	caCertPEM, err := ioutil.ReadFile(certFilename)
	if err != nil {
		//log.Fatalf("Failed to read CA certificate: %v", err)
		return 4, fmt.Errorf("Failed to read CA certificate: %v", err)
	}
	// 解析PEM编码的证书
	block, _ := pem.Decode(caCertPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		log.Fatal("Failed to decode PEM block containing the certificate")
		return 5, fmt.Errorf("Failed to decode PEM block containing the certificate")
	}
	// 解析DER编码的证书
	clientCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 6, fmt.Errorf("Failed to parse client certificate: %v", err)
	}
	// 计算证书签名的哈希值
	hash := sha256.New()
	_, err = hash.Write(clientCert.RawTBSCertificate)
	if err != nil {
		return 7, fmt.Errorf("Failed to hash TBS certificate: %w", err)
	}
	digest := hash.Sum(nil)
	// 验证签名
	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, digest, clientCert.Signature)
	if err != nil {
		return 8, fmt.Errorf("failed to verify signature: %w", err)
	}
	fmt.Println("Client certificate signature verified successfully.")
	return 0, nil
}

// syncCRL 同步CRL（证书吊销列表）
func syncCRL(serverURL string) error {
	// 创建HTTP客户端
	client := &http.Client{}
	// 发送GET请求
	resp, err := client.Get("http://" + serverURL + "/server_list")
	if err != nil {
		log.Fatalf("HTTP GET request failed: %v", err)
	}
	defer resp.Body.Close()
	// 检查响应状态码
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Server returned non-200 status: %d", resp.StatusCode)
	}
	// 读取响应体
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response body: %v", err)
	}
	// 解析JSON到[]ServerInfo切片
	err = json.Unmarshal(body, &servers)
	if err != nil {
		log.Fatalf("Failed to unmarshal JSON: %v", err)
	}
	// 将解析后的数据写入本地文件
	file, err := os.Create(jsonFilePath)
	if err != nil {
		log.Fatalf("Failed to create file: %v", err)
	}
	defer file.Close()
	// 将切片编码回JSON并写入文件
	encoder := json.NewEncoder(file)
	err = encoder.Encode(servers)
	if err != nil {
		log.Fatalf("Failed to encode JSON to file: %v", err)
	}

	fmt.Println("Server list successfully saved to server_list.json")
	return nil
}

func stringToPublicKey(publicKeyString string) (*rsa.PublicKey, error) {
	// 将Base64字符串解码为字节切片
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyString)
	if err != nil {
		return nil, err
	}
	// 解析响应体为RSA公钥
	publicKey, err := parsePublicKeyFromResponse(publicKeyBytes)
	if err != nil {
		log.Fatalf("Failed to parse RSA public key from response: %v", err)
		return nil, err
	}
	return publicKey, nil
}

// getPublicKeyByIP 从 servers 切片中查找具有指定 IP 的服务器的 PublicKey
func getPublicKeyByIP(ip string) (string, bool) {
	// 从JSON文件中读取servers
	err := readServersFromJSON(jsonFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法读取服务器配置: %v\n", err)
		os.Exit(1)
	}

	for _, server := range servers {
		if server.IP == ip {
			return server.PublicKey, true
		}
	}
	return "", false
}

// 从JSON文件中读取servers
func readServersFromJSON(filePath string) error {
	jsonData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(jsonData, &servers)
	if err != nil {
		return err
	}

	return nil
}

// readServerConfig 读取配置文件并返回服务器地址
func readServerConfig(configFilePath string) (string, error) {
	file, err := os.Open(configFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open config file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "server_url = ") {
			parts := strings.Split(line, " = ")
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading config file: %v", err)
	}

	return "", fmt.Errorf("server URL not found in config file")
}

// parsePublicKeyFromResponse 解析从 GetPubliceKeyHandler 获取的响应为 RSA 公钥
func parsePublicKeyFromResponse(responseJSON []byte) (*rsa.PublicKey, error) {
	var publicKeyString string
	if err := json.Unmarshal(responseJSON, &publicKeyString); err != nil {
		return nil, err
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyString)
	if err != nil {
		return nil, err
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("unsupported public key type")
	}

	return rsaPublicKey, nil
}
