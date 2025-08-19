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
type dataBlob struct {
	cbData uint32
	pbData *byte
}

// InstallCA adds the selected CA certificate to the Windows "ROOT" and "CA" certificate stores.
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

	// Install into both the ROOT and CA (Intermediate) stores
	stores := []string{"ROOT", "CA"}
	for _, storeName := range stores {
		err := installCertInStore(cert, storeName)
		if err != nil {
			// Return on the first error, but it might have succeeded in the ROOT store.
			return fmt.Sprintf("Error installing into '%s' store: %v", storeName, err)
		}
	}

	return fmt.Sprintf("Success! CA Certificate '%s' installed in Windows. You may need to restart browsers.", caName)
}

// installCertInStore is a helper function to add a certificate to a specific system store.
func installCertInStore(cert *x509.Certificate, storeName string) error {
	store, err := windows.CertOpenStore(
		windows.CERT_STORE_PROV_SYSTEM,
		0,
		0,
		windows.CERT_SYSTEM_STORE_LOCAL_MACHINE,
		uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(storeName))),
	)
	if err != nil {
		return fmt.Errorf("failed to open certificate store. Please run as Administrator")
	}
	defer windows.CertCloseStore(store, 0)

	certContext, err := windows.CertCreateCertificateContext(
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		&cert.Raw[0],
		uint32(len(cert.Raw)),
	)
	if err != nil {
		return fmt.Errorf("failed to create certificate context: %w", err)
	}
	defer windows.CertFreeCertificateContext(certContext)

	var newCertContext *windows.CertContext
	err = windows.CertAddCertificateContextToStore(
		store,
		certContext,
		windows.CERT_STORE_ADD_REPLACE_EXISTING,
		&newCertContext,
	)
	if err != nil {
		return fmt.Errorf("failed to add certificate to store: %w", err)
	}

	// If we got a handle to the new cert, set its friendly name
	if newCertContext != nil {
		defer windows.CertFreeCertificateContext(newCertContext)

		var friendlyNameBase string
		if len(cert.Subject.Organization) > 0 {
			friendlyNameBase = cert.Subject.Organization[0]
		} else {
			friendlyNameBase = cert.Subject.CommonName
		}
		friendlyName := fmt.Sprintf("%s Signing Root", friendlyNameBase)

		friendlyNamePtr, err := windows.UTF16PtrFromString(friendlyName)
		if err != nil {
			return fmt.Errorf("could not create friendly name string for Windows")
		}

		blob := dataBlob{
			cbData: uint32(len(friendlyName)+1) * 2,
			pbData: (*byte)(unsafe.Pointer(friendlyNamePtr)),
		}

		crypt32 := windows.NewLazySystemDLL("crypt32.dll")
		procCertSetCertificateContextProperty := crypt32.NewProc("CertSetCertificateContextProperty")

		ret, _, err := procCertSetCertificateContextProperty.Call(
			uintptr(unsafe.Pointer(newCertContext)),
			CERT_FRIENDLY_NAME_PROP_ID,
			0,
			uintptr(unsafe.Pointer(&blob)),
		)

		if ret == 0 {
			log.Printf("Warning: Could not set friendly name on certificate in '%s' store: %v", storeName, err)
		}
	}
	return nil
}
