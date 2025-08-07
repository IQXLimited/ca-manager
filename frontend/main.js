// This file connects the HTML UI to the Go backend functions

// --- Get references to all our HTML elements ---
const logOutput = document.getElementById('log-output');
const toastContainer = document.getElementById('toast-container');

// Create CA section
const createCADetails = document.getElementById('create-ca-details');
const btnCreateCA = document.getElementById('btn-create-ca');
const caCountry = document.getElementById('ca-country');
const caState = document.getElementById('ca-state');
const caLocality = document.getElementById('ca-locality');
const caOrg = document.getElementById('ca-org');
const caCommon = document.getElementById('ca-common');
const caExpiry = document.getElementById('ca-expiry');

// Create Device Cert section
const btnCreateCert = document.getElementById('btn-create-cert');
const caSelectorDevice = document.getElementById('ca-selector-device');
const certHostname = document.getElementById('cert-hostname');
const deviceExpiry = document.getElementById('device-expiry');
const btnDeleteCaDevice = document.getElementById('btn-delete-ca-device');

// Install CA section
const installCaSection = document.getElementById('install-ca-section');
const btnInstallCA = document.getElementById('btn-install-ca');
const caSelectorInstall = document.getElementById('ca-selector-install');
const btnDeleteCaInstall = document.getElementById('btn-delete-ca-install');


// Generated Certs section
const btnRefreshCerts = document.getElementById('btn-refresh-certs');
const certList = document.getElementById('cert-list');

// Modal section
const inspectModal = document.getElementById('inspect-modal');
const modalCloseBtn = document.getElementById('modal-close-btn');
const modalBody = document.getElementById('modal-body');

// Footer
const appFooter = document.getElementById('app-footer');


// --- Event Listeners ---

// On window load, initialize everything
window.addEventListener('load', () => {
    populateYearDropdowns();
    checkAdminStatus();
    refreshCAList();
    refreshCertList();
    setCopyright();
});

// Create CA button
btnCreateCA.addEventListener('click', () => {
    if (!caCommon.value) {
        showToast("CA Common Name is required.", "error");
        return;
    }
    const caInput = {
        country: caCountry.value || "GB",
        state: caState.value || "Scotland",
        locality: caLocality.value || "Jedburgh",
        org: caOrg.value || "IQX Limited",
        commonName: caCommon.value,
        expiryDays: parseInt(caExpiry.value) * 365,
    };
    logMessage(`Creating CA '${caInput.commonName}'...`);
    window.go.main.App.CreateCA(caInput).then(handleResult).then(refreshCAList);
});

// Create Certificate button
btnCreateCert.addEventListener('click', () => {
    const hostnameOrIP = certHostname.value;
    const selectedCA = caSelectorDevice.value;
    const expiry = parseInt(deviceExpiry.value) * 365;

    if (!hostnameOrIP) {
        showToast("Please enter a hostname or IP address.", "error");
        return;
    }
    if (!selectedCA) {
        showToast("Please select a CA to sign with.", "error");
        return;
    }

    logMessage(`Creating certificate for ${hostnameOrIP}...`);
    window.go.main.App.CreateCert(hostnameOrIP, selectedCA, expiry)
        .then(result => {
            handleResult(result);
            // If the creation was successful, clear the input field
            if (result && result.toLowerCase().startsWith("success")) {
                certHostname.value = '';
            }
        })
        .then(refreshCertList);
});

// Install CA button
btnInstallCA.addEventListener('click', () => {
    const selectedCA = caSelectorInstall.value;
    if (!selectedCA) {
        showToast("Please select a CA to install.", "error");
        return;
    }
    logMessage(`Attempting to install CA '${selectedCA}' into Windows trust store...`);
    window.go.main.App.InstallCA(selectedCA).then(handleResult);
});

// Refresh device certificate list button
btnRefreshCerts.addEventListener('click', refreshCertList);

// Delete CA buttons
btnDeleteCaDevice.addEventListener('click', () => deleteCA(caSelectorDevice.value));
btnDeleteCaInstall.addEventListener('click', () => deleteCA(caSelectorInstall.value));

// Modal close listeners
modalCloseBtn.addEventListener('click', () => inspectModal.style.display = 'none');
inspectModal.addEventListener('click', (e) => {
    if (e.target === inspectModal) {
        inspectModal.style.display = 'none';
    }
});


// --- Helper Functions ---

function setCopyright() {
    const currentYear = new Date().getFullYear();
    appFooter.textContent = `© ${currentYear} IQX Limited. All rights reserved.`;
}

function inspectCert(certName) {
    logMessage(`Inspecting certificate '${certName}'...`);
    window.go.main.App.InspectCert(certName).then(details => {
        let addresses = '';
        if (details.ipAddresses && details.ipAddresses.length > 0) {
            addresses += `<p><strong>IP Addresses:</strong> ${details.ipAddresses.join(', ')}</p>`;
        }
        if (details.dnsNames && details.dnsNames.length > 0) {
            addresses += `<p><strong>DNS Names:</strong> ${details.dnsNames.join(', ')}</p>`;
        }

        modalBody.innerHTML = `
            <p><strong>Subject:</strong> ${details.subject}</p>
            <p><strong>Issuer:</strong> ${details.issuer}</p>
            ${addresses}
            <p><strong>Valid From:</strong> ${details.validFrom}</p>
            <p><strong>Valid Until:</strong> ${details.validUntil}</p>
            <p><strong>Serial Number:</strong> ${details.serialNumber}</p>
        `;
        inspectModal.style.display = 'flex';
    }).catch(err => {
        handleResult(`Error inspecting certificate: ${err}`);
    });
}

function deleteCA(caName) {
    if (!caName) {
        showToast("No CA selected to delete.", "error");
        return;
    }
    if (confirm(`Are you sure you want to permanently delete the CA '${caName}' and its private key? This cannot be undone.`)) {
        logMessage(`Deleting CA '${caName}'...`, "error");
        window.go.main.App.DeleteCA(caName).then(handleResult).then(refreshCAList);
    }
}

function deleteCert(certName) {
     if (!certName) {
        showToast("No certificate name provided for deletion.", "error");
        return;
    }
    if (confirm(`Are you sure you want to permanently delete the certificate '${certName}' and its private key?`)) {
        logMessage(`Deleting certificate '${certName}'...`, "error");
        window.go.main.App.DeleteCert(certName).then(handleResult).then(refreshCertList);
    }
}

// checkAdminStatus checks if running as admin and updates UI.
function checkAdminStatus() {
    if (window.go.main.App.IsAdmin) {
        window.go.main.App.IsAdmin().then(isAdmin => {
            if (!isAdmin) {
                btnInstallCA.disabled = true;
                btnInstallCA.title = "You must run this application as an Administrator to install CAs.";
            }
        });
    } else {
        installCaSection.style.display = 'none';
    }
}

// populateYearDropdowns fills the expiry dropdowns with options from 1 to 30.
function populateYearDropdowns() {
    for (let i = 1; i <= 30; i++) {
        const caOption = document.createElement('option');
        caOption.value = i;
        caOption.textContent = `${i} Year${i > 1 ? 's' : ''}`;
        caExpiry.appendChild(caOption);

        const deviceOption = document.createElement('option');
        deviceOption.value = i;
        deviceOption.textContent = `${i} Year${i > 1 ? 's' : ''}`;
        deviceExpiry.appendChild(deviceOption);
    }
    caExpiry.value = 10;
    deviceExpiry.value = 2;
}

// refreshCAList calls the Go backend to get the list of CAs and updates the dropdowns
function refreshCAList() {
    logMessage("Refreshing CA list...");
    window.go.main.App.ListCAs().then(cas => {
        caSelectorDevice.innerHTML = '';
        caSelectorInstall.innerHTML = '';

        if (cas && cas.length > 0) {
            cas.forEach(caName => {
                const option1 = document.createElement('option');
                option1.value = caName;
                option1.textContent = caName;
                caSelectorDevice.appendChild(option1);

                const option2 = document.createElement('option');
                option2.value = caName;
                option2.textContent = caName;
                caSelectorInstall.appendChild(option2);
            });
            logMessage("CA list updated.");
            createCADetails.open = false;
        } else {
            logMessage("No CAs found in the output folder.");
            createCADetails.open = true;
        }
    }).catch(err => {
        logMessage(`Error refreshing CA list: ${err}`, "error");
    });
}


// refreshCertList calls the Go backend to get the list of device certs and updates the UI
function refreshCertList() {
    logMessage("Refreshing device certificate list...");
    window.go.main.App.ListCerts().then(certs => {
        certList.innerHTML = ''; // Clear the list
        if (certs && certs.length > 0) {
            certs.forEach(certName => {
                const li = document.createElement('li');
                
                const span = document.createElement('span');
                span.textContent = certName;
                span.className = 'cert-name';
                
                const actionsDiv = document.createElement('div');
                actionsDiv.className = 'cert-actions';

                const inspectBtn = document.createElement('button');
                inspectBtn.textContent = 'Inspect';
                inspectBtn.className = 'btn-inspect';
                inspectBtn.onclick = () => inspectCert(certName);

                const deleteBtn = document.createElement('button');
                deleteBtn.textContent = 'X';
                deleteBtn.className = 'btn-delete';
                deleteBtn.title = `Delete ${certName}`;
                deleteBtn.onclick = () => deleteCert(certName);

                actionsDiv.appendChild(inspectBtn);
                actionsDiv.appendChild(deleteBtn);
                li.appendChild(span);
                li.appendChild(actionsDiv);
                certList.appendChild(li);
            });
             logMessage("Device certificate list updated.");
        } else {
            const li = document.createElement('li');
            li.textContent = 'No device certificates found in output folder.';
            certList.appendChild(li);
            logMessage("No device certificates found.");
        }
    }).catch(err => {
        logMessage(`Error refreshing list: ${err}`, "error");
    });
}

// handleResult takes the string response from Go and shows a toast.
function handleResult(result) {
    if (result) {
        logMessage(result); // Also log it for history
        if (result.toLowerCase().startsWith("success")) {
            showToast(result, "success");
        } else if (result.toLowerCase().startsWith("error")) {
            showToast(result, "error");
        }
    }
    return result; // Pass the result along the promise chain
}

// showToast creates and displays a toast notification.
function showToast(message, type = 'success') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;

    toastContainer.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// logMessage adds a new entry to the log output on the screen
function logMessage(message, type = 'info') {
    const now = new Date().toLocaleTimeString();
    const newLog = document.createElement('div');
    newLog.textContent = `[${now}] ${message}`;

    if (type === 'success') {
        newLog.className = 'success';
    } else if (type === 'error') {
        newLog.className = 'error';
    }

    logOutput.prepend(newLog);
}
