# IQX Certificate Authority Manager

A simple, cross-platform desktop application for creating and managing a local Certificate Authority (CA). Built with Go and Wails, this tool is ideal for securing internal network services that use hostnames, IP addresses, or require certificates from an external request.

![Screenshot of CA Manager](screenshot.apng "Screenshot of CA Manager")

## Features

* **Create & Manage Multiple CAs:** Generate unique Certificate Authorities with custom details and expiry dates.
* **Generate Device Certificates:**
  * Create certificates with a Common Name (CN) and multiple Subject Alternative Names (SANs).
  * Supports hostnames, IP addresses, and wildcard domains (e.g., `*.my-domain.local`).
  * Uses a modern "pill" input for easy management of SANs.
* **Sign from CSR:** Sign externally generated Certificate Signing Requests (CSRs) using any of your local CAs. The tool intelligently handles pasted text that includes both a CSR and a private key.
* **Modern Key Standards:** Generates new private keys in the modern **PKCS#8** format while maintaining backward compatibility for reading and using older **PKCS#1** keys.
* **Windows Integration:**
  * Install any of your CAs directly into the Windows **Trusted Root** and **Intermediate** stores with a single click (requires administrator privileges).
  * Certificates are installed with a "Friendly Name" for easy identification.
* **Easy Distribution:**
  * **Generate Installer:** Create a distributable `.zip` file containing a CA certificate and a robust batch script for easy installation on other Windows machines.
  * **Export to PFX:** Export device certificates and their private keys to a single, password-protected `.pfx` file, ideal for Windows servers and other systems.
* **Manage & Inspect:**
  * View the details of any generated device certificate.
  * Safely delete CAs and device certificates directly from the UI.
  * Quickly open the `output` directory from the application.
* **Standalone Executable:** Compiles to a single, dependency-free executable with embedded version information.

## Prerequisites

To build this application from source, you will need the following installed on your system:

1. **Go:** Version 1.18 or newer. You can download it from [go.dev](https://go.dev/dl/).
2. **Wails CLI:** The command-line tool for Wails. Install it by running:

    ```bash
    go install https://github.com/wailsapp/wails/v2/cmd/wails@latest
    ```

3. **System Dependencies:** Wails may require additional system libraries (like a C compiler). Run `wails doctor` to check if your system is ready.

## Building from Source

1. Clone the repository:

    ```bash
    git clone https://github.com/IQXLimited/ca-manager.git
    ```

2. Navigate into the project directory:

    ```bash
    cd ca-manager
    ```

3. Ensure all dependencies are downloaded:

    ```bash
    go mod tidy
    ```

4. Run the build command:

    ```bash
    wails build
    ```

5. The compiled executable (`IQX CA Manager.exe` on Windows) will be located in the `build/bin/` directory.

## Usage

1. Run the executable from the `build/bin/` directory.
2. All generated certificates and keys will be saved in an `output` folder created in the same directory as the executable.
3. To use the "Install CA in Windows" feature, you must right-click the executable and select **"Run as administrator"**.

## Branding & Copyright

© 2025 IQX Limited. All rights reserved.
