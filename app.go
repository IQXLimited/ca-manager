package main

import (
	"archive/zip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"software.sslmate.com/src/go-pkcs12"
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
		os.MkdirAll(outputDir, 0755)
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
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	ValidFrom    string   `json:"validFrom"`
	ValidUntil   string   `json:"validUntil"`
	SerialNumber string   `json:"serialNumber"`
	IPAddresses  []string `json:"ipAddresses"`
	DNSNames     []string `json:"dnsNames"`
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
		NotAfter:              time.Now().Add(time.Duration(input.ExpiryDays) * 24 * time.Hour),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, // Removed CRLSign
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

// CreateCert generates a server/device certificate with a CN and SANs, signed by a chosen CA.
func (a *App) CreateCert(cn string, sans string, caName string, expiryDays int) string {
	if caName == "" {
		return "Error: You must select a CA to sign the certificate with."
	}
	if expiryDays <= 0 {
		expiryDays = 730 // Default to 2 years
	}
	if cn == "" {
		return "Error: Common Name (CN) cannot be empty."
	}

	// The full list of SANs must include the CN
	allSans := []string{cn}
	if sans != "" {
		sanList := strings.Split(sans, ",")
		for _, s := range sanList {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				// Avoid duplicates
				isDuplicate := false
				for _, existingSan := range allSans {
					if existingSan == trimmed {
						isDuplicate = true
						break
					}
				}
				if !isDuplicate {
					allSans = append(allSans, trimmed)
				}
			}
		}
	}

	caCert, caPrivateKey, err := loadCA(caName)
	if err != nil {
		return fmt.Sprintf("Error loading CA: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, expiryDays),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	for _, san := range allSans {
		ip := net.ParseIP(san)
		if ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	deviceKey, err := rsa.GenerateKey(rand.Reader, rsaBitsSrv)
	if err != nil {
		return fmt.Sprintf("Error generating device key: %v", err)
	}

	deviceCertBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, &deviceKey.PublicKey, caPrivateKey)
	if err != nil {
		return fmt.Sprintf("Error signing device cert: %v", err)
	}

	safeFilename := strings.ReplaceAll(cn, "*", "_wildcard")
	deviceCertFile := filepath.Join(outputDir, fmt.Sprintf("%s_signed-by_%s.pem", safeFilename, caName))
	deviceKeyFile := filepath.Join(outputDir, fmt.Sprintf("%s_signed-by_%s.key", safeFilename, caName))

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

	return fmt.Sprintf("Success! Certificate for %s created.", cn)
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

	os.Remove(caKeyPath)
	os.Remove(caCertPath)

	return fmt.Sprintf("Success! CA '%s' and all related files have been deleted.", caName)
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
		return fmt.Sprintf("Error deleting files for certificate '%s'.", certName)
	}
	return fmt.Sprintf("Success! Certificate '%s' has been deleted.", certName)
}

// InspectCert reads a certificate file and returns its details.
func (a *App) InspectCert(certName string) (*CertDetails, error) {
	cert, err := loadCert(certName)
	if err != nil {
		return nil, err
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
		DNSNames:     cert.DNSNames,
	}

	return details, nil
}

// ExportToPFX exports a certificate and its key to a PFX/P12 file.
func (a *App) ExportToPFX(certName string, password string) string {
	// Load the device certificate
	cert, err := loadCert(certName)
	if err != nil {
		return fmt.Sprintf("Error loading certificate '%s': %v", certName, err)
	}

	// Load the device's private key
	keyPath := filepath.Join(outputDir, strings.TrimSuffix(certName, ".pem")+".key")
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Sprintf("Error loading private key: %v", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Sprintf("Error parsing private key: %v", err)
	}

	// Load the issuing CA to include in the chain
	caCert, _, err := loadCA(cert.Issuer.CommonName)
	if err != nil {
		return fmt.Sprintf("Error loading issuing CA '%s': %v", cert.Issuer.CommonName, err)
	}

	// Create the PFX data using the sslmate package.
	pfxData, err := pkcs12.Encode(rand.Reader, privateKey, cert, []*x509.Certificate{caCert}, password)
	if err != nil {
		return fmt.Sprintf("Error creating PFX file: %v", err)
	}

	// Save the PFX file
	pfxPath := filepath.Join(outputDir, strings.TrimSuffix(certName, ".pem")+".pfx")
	err = os.WriteFile(pfxPath, pfxData, 0644)
	if err != nil {
		return fmt.Sprintf("Error saving PFX file: %v", err)
	}

	return fmt.Sprintf("Success! Exported to '%s'.", pfxPath)
}

// GenerateInstaller creates a zip file with the CA cert and an installation script.
func (a *App) GenerateInstaller(caName string) string {
	if caName == "" {
		return "Error: No CA selected to generate an installer for."
	}

	// Define paths
	caCertPath := filepath.Join(outputDir, fmt.Sprintf("%s.pem", caName))
	zipPath := filepath.Join(outputDir, fmt.Sprintf("%s_Installer.zip", caName))

	// Check if the source certificate exists
	if !fileExists(caCertPath) {
		return fmt.Sprintf("Error: CA certificate for '%s' not found.", caName)
	}

	// Create the zip file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Sprintf("Error creating zip file: %v", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add the install script to the zip with the new, more reliable admin check and embedded filename
	batchContent := fmt.Sprintf(`@echo off
setlocal

net session >nul 2>&1
if %%errorLevel%% == 1 (
    echo Failure: Current permissions inadequate.
    pause >nul
) else (
    echo [*] Attempting to install '%s' certificate...
    certutil.exe -addstore -f "ROOT" "%%~dp0%s.pem"
    echo.
    pause
)
endlocal`, caName, caName)

	scriptWriter, err := zipWriter.Create("install-ca.bat")
	if err != nil {
		return fmt.Sprintf("Error adding batch script to zip: %v", err)
	}
	_, err = io.WriteString(scriptWriter, batchContent)
	if err != nil {
		return fmt.Sprintf("Error writing batch script content: %v", err)
	}

	// Add the CA certificate to the zip
	certData, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Sprintf("Error reading CA certificate: %v", err)
	}
	certWriter, err := zipWriter.Create(fmt.Sprintf("%s.pem", caName))
	if err != nil {
		return fmt.Sprintf("Error adding certificate to zip: %v", err)
	}
	_, err = certWriter.Write(certData)
	if err != nil {
		return fmt.Sprintf("Error writing certificate content: %v", err)
	}

	return fmt.Sprintf("Success! Installer created at '%s'.", zipPath)
}


// --- Helper Functions ---
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func loadCA(caName string) (*x509.Certificate, *rsa.PrivateKey, error) {
	cert, err := loadCert(caName + ".pem")
	if err != nil {
		return nil, nil, err
	}

	caKeyPath := filepath.Join(outputDir, fmt.Sprintf("%s.key", caName))
	keyData, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read key file: %w", err)
	}
	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("could not decode PEM block from key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("could not parse private key: %w", err)
	}

	return cert, privateKey, nil
}

func loadCert(certFileName string) (*x509.Certificate, error) {
	certPath := filepath.Join(outputDir, certFileName)
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
	return cert, nil
}
