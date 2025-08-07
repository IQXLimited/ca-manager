package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// Create the output directory if it doesn't exist
	if _, err := os.Stat(outputDir); os.IsNotExist(err) {
		os.Mkdir(outputDir, 0755)
	}
}

// CAInput holds the details for the Certificate Authority.
type CAInput struct {
	Country    string `json:"country"`
	State      string `json:"state"`
	Locality   string `json:"locality"`
	Org        string `json:"org"`
	CommonName string `json:"commonName"`
	ExpiryDays int    `json:"expiryDays"`
}

// CertDetails holds the inspected information for a certificate.
type CertDetails struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	ValidFrom    string `json:"validFrom"`
	ValidUntil   string `json:"validUntil"`
	SerialNumber string `json:"serialNumber"`
	IPAddresses  []string `json:"ipAddresses"`
}


// ListCAs scans the output directory for CA files.
func (a *App) ListCAs() []string {
	var cas []string
	files, err := os.ReadDir(outputDir)
	if err != nil {
		log.Printf("Could not read output directory: %v", err)
		return cas
	}

	for _, file := range files {
		fileName := file.Name()
		if !file.IsDir() && strings.HasSuffix(fileName, ".pem") && !strings.Contains(fileName, "_signed-by_") {
			keyFileName := strings.TrimSuffix(fileName, ".pem") + ".key"
			if fileExists(filepath.Join(outputDir, keyFileName)) {
				cas = append(cas, strings.TrimSuffix(fileName, ".pem"))
			}
		}
	}
	return cas
}

// CreateCA generates the root CA key and certificate.
func (a *App) CreateCA(input CAInput) string {
	if input.CommonName == "" {
		return "Error: CA Common Name cannot be empty."
	}
	if input.ExpiryDays <= 0 {
		input.ExpiryDays = 3650 // Default to 10 years
	}

	caKeyPath := filepath.Join(outputDir, fmt.Sprintf("%s.key", input.CommonName))
	caCertPath := filepath.Join(outputDir, fmt.Sprintf("%s.pem", input.CommonName))

	if fileExists(caKeyPath) || fileExists(caCertPath) {
		return fmt.Sprintf("Error: A CA with the name '%s' already exists.", input.CommonName)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			Country:      []string{input.Country},
			Province:     []string{input.State},
			Locality:     []string{input.Locality},
			Organization: []string{input.Org},
			CommonName:   input.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, input.ExpiryDays),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, rsaBitsCA)
	if err != nil {
		return fmt.Sprintf("Error generating private key: %v", err)
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Sprintf("Error creating certificate: %v", err)
	}

	certOut, err := os.Create(caCertPath)
	if err != nil {
		return fmt.Sprintf("Error saving CA cert: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(caKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Sprintf("Error saving CA key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	keyOut.Close()

	return fmt.Sprintf("Success! CA '%s' created in the 'output' folder.", input.CommonName)
}

// CreateCert generates a server/device certificate signed by a chosen CA.
func (a *App) CreateCert(ipStr string, caName string, expiryDays int) string {
	if caName == "" {
		return "Error: You must select a CA to sign the certificate with."
	}
	if expiryDays <= 0 {
		expiryDays = 730 // Default to 2 years
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Sprintf("Error: '%s' is not a valid IP address.", ipStr)
	}

	caKeyPath := filepath.Join(outputDir, fmt.Sprintf("%s.key", caName))
	caCertPath := filepath.Join(outputDir, fmt.Sprintf("%s.pem", caName))

	if !fileExists(caKeyPath) || !fileExists(caCertPath) {
		return fmt.Sprintf("Error: CA files for '%s' not found.", caName)
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Sprintf("Error reading CA cert: %v", err)
	}
	pemBlock, _ := pem.Decode(caCertPEM)
	caCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return fmt.Sprintf("Error parsing CA cert: %v", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Sprintf("Error reading CA key: %v", err)
	}
	pemBlock, _ = pem.Decode(caKeyPEM)
	caPrivateKey, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return fmt.Sprintf("Error parsing CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: ipStr},
		IPAddresses:  []net.IP{ip},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, expiryDays),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	deviceKey, err := rsa.GenerateKey(rand.Reader, rsaBitsSrv)
	if err != nil {
		return fmt.Sprintf("Error generating device key: %v", err)
	}

	deviceCertBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &deviceKey.PublicKey, caPrivateKey)
	if err != nil {
		return fmt.Sprintf("Error signing device cert: %v", err)
	}

	deviceCertFile := filepath.Join(outputDir, fmt.Sprintf("%s_signed-by_%s.pem", ipStr, caName))
	deviceKeyFile := filepath.Join(outputDir, fmt.Sprintf("%s_signed-by_%s.key", ipStr, caName))

	certOut, err := os.Create(deviceCertFile)
	if err != nil {
		return fmt.Sprintf("Error saving device cert: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: deviceCertBytes})
	certOut.Close()

	keyOut, err := os.OpenFile(deviceKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Sprintf("Error saving device key: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(deviceKey)})
	keyOut.Close()

	return fmt.Sprintf("Success! Certificate for %s created in the 'output' folder.", ipStr)
}

// ListCerts scans the output directory and returns a list of generated device .pem files.
func (a *App) ListCerts() []string {
	var certs []string
	files, err := os.ReadDir(outputDir)
	if err != nil {
		log.Printf("Could not read output directory: %v", err)
		return certs
	}

	for _, file := range files {
		fileName := file.Name()
		if !file.IsDir() && strings.HasSuffix(fileName, ".pem") && strings.Contains(fileName, "_signed-by_") {
			certs = append(certs, fileName)
		}
	}
	return certs
}

// DeleteCA deletes the .pem and .key file for a given CA.
func (a *App) DeleteCA(caName string) string {
	if caName == "" {
		return "Error: No CA name provided for deletion."
	}
	caKeyPath := filepath.Join(outputDir, fmt.Sprintf("%s.key", caName))
	caCertPath := filepath.Join(outputDir, fmt.Sprintf("%s.pem", caName))

	errKey := os.Remove(caKeyPath)
	errCert := os.Remove(caCertPath)

	if errKey != nil || errCert != nil {
		return fmt.Sprintf("Error deleting files for CA '%s'. They may have already been removed.", caName)
	}
	return fmt.Sprintf("Success! CA '%s' has been deleted.", caName)
}

// DeleteCert deletes the .pem and .key file for a given device certificate.
func (a *App) DeleteCert(certName string) string {
	if certName == "" {
		return "Error: No certificate name provided for deletion."
	}
	keyName := strings.TrimSuffix(certName, ".pem") + ".key"
	certPath := filepath.Join(outputDir, certName)
	keyPath := filepath.Join(outputDir, keyName)

	errCert := os.Remove(certPath)
	errKey := os.Remove(keyPath)

	if errKey != nil || errCert != nil {
		return fmt.Sprintf("Error deleting files for certificate '%s'. They may have already been removed.", certName)
	}
	return fmt.Sprintf("Success! Certificate '%s' has been deleted.", certName)
}

// InspectCert reads a certificate file and returns its details.
func (a *App) InspectCert(certName string) (*CertDetails, error) {
	certPath := filepath.Join(outputDir, certName)
	pemData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("could not read certificate file: %w", err)
	}

	pemBlock, _ := pem.Decode(pemData)
	if pemBlock == nil {
		return nil, fmt.Errorf("could not decode PEM block from certificate")
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate: %w", err)
	}

	var ips []string
	for _, ip := range cert.IPAddresses {
		ips = append(ips, ip.String())
	}

	details := &CertDetails{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		ValidFrom:    cert.NotBefore.Format(time.RFC1123),
		ValidUntil:   cert.NotAfter.Format(time.RFC1123),
		SerialNumber: cert.SerialNumber.String(),
		IPAddresses:  ips,
	}

	return details, nil
}


// Helper function to check if a file exists.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
