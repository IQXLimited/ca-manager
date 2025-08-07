//go:build windows

package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CERT_FRIENDLY_NAME_PROP_ID is the property identifier for a certificate's friendly name.
const CERT_FRIENDLY_NAME_PROP_ID = 11

// dataBlob is a local definition of the Windows DATA_BLOB structure.
// This avoids potential version mismatches from the golang.org/x/sys/windows package.
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// InstallCA adds the selected CA certificate to the Windows "ROOT" certificate store.
func (a *App) InstallCA(caName string) string {
	if caName == "" {
		return "Error: You must select a CA to install."
	}

	caCertPath := filepath.Join(outputDir, fmt.Sprintf("%s.pem", caName))
	if !fileExists(caCertPath) {
		return fmt.Sprintf("Error: CA certificate for '%s' not found in output folder.", caName)
	}

	caPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Sprintf("Error reading CA file: %v", err)
	}

	pemBlock, _ := pem.Decode(caPEM)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		return "Error: Failed to decode PEM block containing certificate."
	}
	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return fmt.Sprintf("Error parsing certificate: %v", err)
	}

	// Open the system's "ROOT" certificate store using the windows package
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr("ROOT"))),
	)
	if err != nil {
		return "Error: Failed to open certificate store. Please run this application as an Administrator."
	}
	defer windows.CertCloseStore(store, 0)

	// Create a certificate context from our certificate data
	certContext, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		&cert.Raw[0],
		uint32(len(cert.Raw)),
	)
	if err != nil {
		return fmt.Sprintf("Error creating certificate context: %v", err)
	}
	defer windows.CertFreeCertificateContext(certContext)

	// Add the certificate context to the store, getting a handle to the newly added cert
	var newCertContext *windows.CertContext
	err = windows.CertAddCertificateContextToStore(
		store,
		certContext,
		windows.CERT_STORE_ADD_REPLACE_EXISTING,
		&newCertContext,
	)
	if err != nil {
		return "Error: Failed to add certificate to store. Please ensure you are running as an Administrator."
	}

	// If we got a handle to the new cert, set its friendly name
	if newCertContext != nil {
		defer windows.CertFreeCertificateContext(newCertContext)

		// Create the friendly name string
		var friendlyNameBase string
		if len(cert.Subject.Organization) > 0 {
			friendlyNameBase = cert.Subject.Organization[0]
		} else {
			friendlyNameBase = cert.Subject.CommonName // Fallback to common name
		}
		friendlyName := fmt.Sprintf("%s Signing Root", friendlyNameBase)

		// Convert to the required Windows format (UTF-16 blob)
		friendlyNamePtr, err := windows.UTF16PtrFromString(friendlyName)
		if err != nil {
			return "Error: Could not create friendly name string for Windows."
		}

		// Use our local, stable struct definition
		blob := dataBlob{
			cbData: uint32(len(friendlyName)+1) * 2,
			pbData: (*byte)(unsafe.Pointer(friendlyNamePtr)),
		}
		
		// Dynamically load the function from crypt32.dll
		crypt32 := windows.NewLazySystemDLL("crypt32.dll")
        procCertSetCertificateContextProperty := crypt32.NewProc("CertSetCertificateContextProperty")

		// Set the property on the certificate in the store
		ret, _, err := procCertSetCertificateContextProperty.Call(
			uintptr(unsafe.Pointer(newCertContext)),
			CERT_FRIENDLY_NAME_PROP_ID,
			0,
			uintptr(unsafe.Pointer(&blob)),
		)
		
		// A return value of 0 indicates failure.
		if ret == 0 {
			// This is not a critical error, so we just log it and continue
			log.Printf("Warning: Could not set friendly name on certificate: %v", err)
		}
	}

	return fmt.Sprintf("Success! CA Certificate '%s' installed in Windows. You may need to restart browsers.", caName)
}