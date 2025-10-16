// Threat Intelligence Module
class ThreatIntelligence {
    constructor() {
        this.apiEndpoints = {
            virustotal: {
                base: 'https://www.virustotal.com/vtapi/v2',
                key: '0ddfbaf2e6331dc0a5718a9c3e3128764b87a542602c26c83b563043cf5638ba' // Replace with actual key
            },
            hibp: {
                base: 'https://haveibeenpwned.com/api/v3',
                key: '00000000000000000000000000000000' // Replace with actual key
            },
            abuseipdb: {
                base: 'https://api.abuseipdb.com/api/v2',
                key: '00eaad20baa3852a004e6c0ab9f42d3c4ca1f57c13de500c0c268313e44675a4416fa24f7108c41f' // Replace with actual key
            }
        };
    }

    async analyzeFileHash() {
        const hash = document.getElementById('file-hash').value.trim();
        
        if (!hash) {
            securityApp.showNotification('Please enter a file hash', 'warning');
            return;
        }

        if (!SecurityUtils.validateHash(hash)) {
            securityApp.showNotification('Please enter a valid MD5, SHA1, or SHA256 hash', 'warning');
            return;
        }

        securityApp.showLoading('Analyzing file hash...');

        try {
            // Simulate API call - replace with actual VirusTotal API
            const result = await this.simulateVirusTotalScan(hash);
            this.displayVirusTotalResults(result);
            
            securityApp.addScanActivity({
                type: 'File Hash Analysis',
                target: hash,
                result: result.positives > 0 ? 'Malicious' : 'Clean',
                severity: result.positives > 0 ? 'high' : 'low'
            });
            
        } catch (error) {
            console.error('Error analyzing file hash:', error);
            securityApp.showNotification('Error analyzing file hash', 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    async analyzeURL() {
        const url = document.getElementById('scan-url').value.trim();
        
        if (!url) {
            securityApp.showNotification('Please enter a URL', 'warning');
            return;
        }

        securityApp.showLoading('Scanning URL...');

        try {
            // Simulate API call - replace with actual VirusTotal API
            const result = await this.simulateURLScan(url);
            this.displayVirusTotalResults(result);
            
            securityApp.addScanActivity({
                type: 'URL Scan',
                target: url,
                result: result.positives > 0 ? 'Malicious' : 'Clean',
                severity: result.positives > 0 ? 'high' : 'low'
            });
            
        } catch (error) {
            console.error('Error scanning URL:', error);
            securityApp.showNotification('Error scanning URL', 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    async checkEmailBreach() {
        const email = document.getElementById('hibp-email').value.trim();
        
        if (!email) {
            securityApp.showNotification('Please enter an email address', 'warning');
            return;
        }

        if (!SecurityUtils.validateEmail(email)) {
            securityApp.showNotification('Please enter a valid email address', 'warning');
            return;
        }

        securityApp.showLoading('Checking email breaches...');

        try {
            // Simulate API call - replace with actual HIBP API
            const result = await this.simulateHIBPCheck(email);
            this.displayHIBPResults(result);
            
            securityApp.addScanActivity({
                type: 'Email Breach Check',
                target: email,
                result: result.breaches.length > 0 ? 'Compromised' : 'Safe',
                severity: result.breaches.length > 0 ? 'medium' : 'low'
            });
            
        } catch (error) {
            console.error('Error checking email breaches:', error);
            securityApp.showNotification('Error checking email breaches', 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    async checkPasswordBreach() {
        const password = document.getElementById('hibp-password').value;
        
        if (!password) {
            securityApp.showNotification('Please enter a password', 'warning');
            return;
        }

        securityApp.showLoading('Checking password breaches...');

        try {
            // Simulate API call - replace with actual HIBP API
            const result = await this.simulatePasswordCheck(password);
            this.displayPasswordResults(result);
            
            securityApp.addScanActivity({
                type: 'Password Check',
                target: '***' + password.slice(-3),
                result: result.found ? 'Compromised' : 'Safe',
                severity: result.found ? 'high' : 'low'
            });
            
        } catch (error) {
            console.error('Error checking password:', error);
            securityApp.showNotification('Error checking password', 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    async checkIPReputation() {
        const ip = document.getElementById('abuseipdb-ip').value.trim();
        const days = document.getElementById('abuseipdb-days').value;
        
        if (!ip) {
            securityApp.showNotification('Please enter an IP address', 'warning');
            return;
        }

        if (!SecurityUtils.validateIP(ip)) {
            securityApp.showNotification('Please enter a valid IP address', 'warning');
            return;
        }

        securityApp.showLoading('Checking IP reputation...');

        try {
            // Simulate API call - replace with actual AbuseIPDB API
            const result = await this.simulateAbuseIPDBCheck(ip, days);
            this.displayAbuseIPDBResults(result);
            
            securityApp.addScanActivity({
                type: 'IP Reputation Check',
                target: ip,
                result: result.abuseConfidenceScore > 50 ? 'Suspicious' : 'Clean',
                severity: result.abuseConfidenceScore > 50 ? 'medium' : 'low'
            });
            
        } catch (error) {
            console.error('Error checking IP reputation:', error);
            securityApp.showNotification('Error checking IP reputation', 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    // Simulation methods - Replace with actual API calls
    async simulateVirusTotalScan(hash) {
        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        return {
            positives: Math.random() > 0.7 ? Math.floor(Math.random() * 20) + 1 : 0,
            total: 65,
            scans: Array.from({length: 10}, (_, i) => ({
                name: `Antivirus ${i + 1}`,
                detected: Math.random() > 0.8,
                result: Math.random() > 0.8 ? 'malicious' : 'clean'
            }))
        };
    }

    async simulateURLScan(url) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        return {
            positives: Math.random() > 0.8 ? Math.floor(Math.random() * 15) + 1 : 0,
            total: 65,
            scans: Array.from({length: 8}, (_, i) => ({
                name: `Scanner ${i + 1}`,
                detected: Math.random() > 0.85,
                result: Math.random() > 0.85 ? 'malicious' : 'clean'
            }))
        };
    }

    async simulateHIBPCheck(email) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const hasBreaches = Math.random() > 0.6;
        return {
            breaches: hasBreaches ? [
                { Name: 'Example Breach 1', BreachDate: '2022-01-15', DataClasses: ['Emails', 'Passwords'] },
                { Name: 'Example Breach 2', BreachDate: '2021-08-22', DataClasses: ['Emails'] }
            ] : []
        };
    }

    async simulatePasswordCheck(password) {
        await new Promise(resolve => setTimeout(resolve, 800));
        
        return {
            found: Math.random() > 0.7,
            count: Math.random() > 0.7 ? Math.floor(Math.random() * 1000) + 1 : 0
        };
    }

    async simulateAbuseIPDBCheck(ip, days) {
        await new Promise(resolve => setTimeout(resolve, 1200));
        
        return {
            abuseConfidenceScore: Math.floor(Math.random() * 100),
            totalReports: Math.floor(Math.random() * 50),
            countryCode: 'US',
            isp: 'Example ISP',
            domain: 'example.com',
            lastReportedAt: new Date().toISOString()
        };
    }

    displayVirusTotalResults(result) {
        const container = document.getElementById('virustotal-results');
        const statusClass = result.positives > 0 ? 'result-malicious' : 'result-safe';
        
        container.innerHTML = `
            <div class="result-panel ${statusClass} fade-in">
                <h5><i class="fas fa-shield-alt me-2"></i>Scan Results</h5>
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Detection Ratio:</strong> ${result.positives}/${result.total}</p>
                        <p><strong>Status:</strong> ${result.positives > 0 ? 'MALICIOUS' : 'CLEAN'}</p>
                    </div>
                    <div class="col-md-6">
                        <div class="progress mb-2">
                            <div class="progress-bar ${result.positives > 0 ? 'bg-danger' : 'bg-success'}" 
                                 style="width: ${(result.positives / result.total) * 100}%">
                                ${Math.round((result.positives / result.total) * 100)}%
                            </div>
                        </div>
                    </div>
                </div>
                ${result.positives > 0 ? `
                    <div class="mt-3">
                        <h6>Detection Details:</h6>
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Scanner</th>
                                        <th>Result</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${result.scans.slice(0, 5).map(scan => `
                                        <tr>
                                            <td>${scan.name}</td>
                                            <td class="${scan.detected ? 'text-danger' : 'text-success'}">
                                                ${scan.detected ? 'Malicious' : 'Clean'}
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ` : ''}
            </div>
        `;
    }

    displayHIBPResults(result) {
        const container = document.getElementById('hibp-results');
        const statusClass = result.breaches.length > 0 ? 'result-suspicious' : 'result-safe';
        
        container.innerHTML = `
            <div class="result-panel ${statusClass} fade-in">
                <h5><i class="fas fa-envelope me-2"></i>Breach Check Results</h5>
                <p><strong>Email Status:</strong> ${result.breaches.length > 0 ? 'COMPROMISED' : 'SAFE'}</p>
                <p><strong>Breaches Found:</strong> ${result.breaches.length}</p>
                
                ${result.breaches.length > 0 ? `
                    <div class="mt-3">
                        <h6>Breach Details:</h6>
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Breach Name</th>
                                        <th>Date</th>
                                        <th>Compromised Data</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${result.breaches.map(breach => `
                                        <tr>
                                            <td>${breach.Name}</td>
                                            <td>${breach.BreachDate}</td>
                                            <td>${breach.DataClasses.join(', ')}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ` : `
                    <p class="text-success mb-0">
                        <i class="fas fa-check-circle me-2"></i>
                        No breaches found for this email address.
                    </p>
                `}
            </div>
        `;
    }

    displayPasswordResults(result) {
        const container = document.getElementById('hibp-results');
        const statusClass = result.found ? 'result-malicious' : 'result-safe';
        
        container.innerHTML += `
            <div class="result-panel ${statusClass} fade-in mt-3">
                <h5><i class="fas fa-key me-2"></i>Password Check Results</h5>
                <p><strong>Password Status:</strong> ${result.found ? 'COMPROMISED' : 'SAFE'}</p>
                ${result.found ? `
                    <p class="text-danger">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        This password has been found in ${result.count} data breaches.
                    </p>
                    <p><strong>Recommendation:</strong> Change this password immediately.</p>
                ` : `
                    <p class="text-success">
                        <i class="fas fa-check-circle me-2"></i>
                        This password has not been found in any known breaches.
                    </p>
                `}
            </div>
        `;
    }

    displayAbuseIPDBResults(result) {
        const container = document.getElementById('abuseipdb-results');
        let statusClass = 'result-safe';
        let statusText = 'CLEAN';
        
        if (result.abuseConfidenceScore > 75) {
            statusClass = 'result-malicious';
            statusText = 'MALICIOUS';
        } else if (result.abuseConfidenceScore > 25) {
            statusClass = 'result-suspicious';
            statusText = 'SUSPICIOUS';
        }
        
        container.innerHTML = `
            <div class="result-panel ${statusClass} fade-in">
                <h5><i class="fas fa-flag me-2"></i>IP Reputation Results</h5>
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>IP Address:</strong> ${document.getElementById('abuseipdb-ip').value}</p>
                        <p><strong>Abuse Confidence:</strong> ${result.abuseConfidenceScore}%</p>
                        <p><strong>Status:</strong> ${statusText}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Total Reports:</strong> ${result.totalReports}</p>
                        <p><strong>Country:</strong> ${result.countryCode}</p>
                        <p><strong>ISP:</strong> ${result.isp}</p>
                    </div>
                </div>
                <div class="progress mb-2">
                    <div class="progress-bar 
                        ${result.abuseConfidenceScore > 75 ? 'bg-danger' : 
                          result.abuseConfidenceScore > 25 ? 'bg-warning' : 'bg-success'}" 
                         style="width: ${result.abuseConfidenceScore}%">
                        ${result.abuseConfidenceScore}%
                    </div>
                </div>
                <p><strong>Last Reported:</strong> ${new Date(result.lastReportedAt).toLocaleString()}</p>
            </div>
        `;
    }
}

// Initialize Threat Intelligence
const threatIntel = new ThreatIntelligence();

// Global functions for HTML onclick events
function analyzeFileHash() {
    threatIntel.analyzeFileHash();
}

function analyzeURL() {
    threatIntel.analyzeURL();
}

function checkEmailBreach() {
    threatIntel.checkEmailBreach();
}

function checkPasswordBreach() {
    threatIntel.checkPasswordBreach();
}

function checkIPReputation() {
    threatIntel.checkIPReputation();
}