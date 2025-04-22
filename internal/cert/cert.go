package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

const (
	keyFileName     = "cert/jetbra.key"
	certificateFile = "cert/jetbra.pem"
	rootCertFile    = "cert/root.pem"
	powerFile       = "cert/power.txt"
)

func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating private key: %v", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

func createCertificate(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) ([]byte, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 80))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial: %v", err)
	}

	parent := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: "JetProfile CA"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	template := parent
	template.Subject = pkix.Name{CommonName: "Smallsun"}

	return x509.CreateCertificate(rand.Reader, &template, &parent, publicKey, privateKey)
}

func parseCertificate(fileName string) (*x509.Certificate, error) {
	certPem, err := os.ReadFile(fileName)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate file %s: %v", fileName, err)
	}

	certBlock, _ := pem.Decode(certPem)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", fileName)
	}
	return x509.ParseCertificate(certBlock.Bytes)
}

func GenerateJetCA() error {
	var saveFile = func(fileName, fileType string, bytes []byte) error {
		file, err := os.Create(fileName)
		defer file.Close()
		if err != nil {
			return fmt.Errorf("error creating file %s: %v", fileName, err)
		}
		pemBlock := &pem.Block{
			Type:  fileType,
			Bytes: bytes,
		}
		if err := pem.Encode(file, pemBlock); err != nil {
			return fmt.Errorf("error encoding PEM file %s: %v", fileName, err)
		}
		return nil
	}

	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %v", err)
	}

	certificate, err := createCertificate(privateKey, publicKey)
	if err != nil {
		return fmt.Errorf("failed to generate certificate: %v", err)
	}

	if err := saveFile(keyFileName, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privateKey)); err != nil {
		return fmt.Errorf("failed to save private key: %v", err)
	}

	if err := saveFile(certificateFile, "CERTIFICATE", certificate); err != nil {
		return fmt.Errorf("failed to save certificate: %v", err)
	}

	fmt.Println("Certificate and private key generated successfully!")
	return nil
}

func GeneratePowerResult() error {
	rootCert, err := parseCertificate(rootCertFile)
	if err != nil {
		return err
	}

	cert, err := parseCertificate(certificateFile)
	if err != nil {
		return err
	}

	x := new(big.Int).SetBytes(cert.Signature) // 证书的签名密文
	y := rootCert.PublicKey.(*rsa.PublicKey).E // 证书指数
	z := rootCert.PublicKey.(*rsa.PublicKey).N // 内置根证书的公钥

	r := new(big.Int)
	r.Exp(x, big.NewInt(int64(y)), cert.PublicKey.(*rsa.PublicKey).N)
	output := fmt.Sprintf("EQUAL,%d,%d,%d->%d", x, y, z, r)

	if err := os.WriteFile(powerFile, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to save power: %v", err)
	}

	fmt.Println("Power generated successfully!")
	return nil
}
