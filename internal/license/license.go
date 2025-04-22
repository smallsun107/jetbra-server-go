package license

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

var (
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
)

type License struct {
	Products           []Product `json:"products"`
	LicenseID          string    `json:"licenseId"`
	LicenseeName       string    `json:"licenseeName"`
	AssigneeName       string    `json:"assigneeName"`
	AssigneeEmail      string    `json:"assigneeEmail"`
	LicenseRestriction string    `json:"licenseRestriction"`
	Metadata           string    `json:"metadata"`
	Hash               string    `json:"hash"`
	GracePeriodDays    int       `json:"gracePeriodDays"`
	CheckConcurrentUse bool      `json:"checkConcurrentUse"`
	AutoProlongated    bool      `json:"autoProlongated"`
	IsAutoProlongated  bool      `json:"isAutoProlongated"`
}

type Product struct {
	Code         string `json:"code"`
	FallbackDate string `json:"fallbackDate"`
	PaidUpTo     string `json:"paidUpTo"`
	Extended     bool   `json:"extended"`
}

const (
	keyFileName     = "cert/jetbra.key"
	certificateFile = "cert/jetbra.pem"
)

func init() {
	loadPrivateKey()
	loadCertificate()
}

func loadPrivateKey() (*rsa.PrivateKey, error) {
	private, err := os.ReadFile(keyFileName)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file (jetbra.key): %v", err)
	}

	block, _ := pem.Decode(private)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from private key file (jetbra.key)")
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key (jetbra.key): %v", err)
	}

	return privateKey, nil
}

func loadCertificate() (*x509.Certificate, error) {

	cert, err := os.ReadFile(certificateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file (jetbra.pem): %v", err)
	}

	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from certificate file (jetbra.pem)")
	}

	certificate, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate (jetbra.pem): %v", err)
	}

	return certificate, nil
}

func generateLicenseID() string {
	const allowedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const licenseLength = 16
	b := make([]byte, licenseLength)
	for i := range b {
		index, _ := rand.Int(rand.Reader, big.NewInt(int64(len(allowedCharacters))))
		b[i] = allowedCharacters[index.Int64()]
	}
	return string(b)
}

func GenerateLicense(body string) string {
	var license License
	err := json.Unmarshal([]byte(body), &license)
	if err != nil {
		return err.Error()
	}
	license.LicenseID = generateLicenseID()
	licenseStr, _ := json.Marshal(license)
	//fmt.Println(string(licenseStr))

	// Sign the license using SHA1withRSA
	hashed := sha1.Sum(licenseStr)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hashed[:])

	licensePartBase64 := base64.StdEncoding.EncodeToString(licenseStr)
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)
	certBase64 := base64.StdEncoding.EncodeToString(certificate.Raw)

	licenseResult := fmt.Sprintf("%s-%s-%s-%s", license.LicenseID, licensePartBase64, signatureBase64, certBase64)
	// fmt.Printf("licenseResult:%s\n", licenseResult)
	return licenseResult
}
