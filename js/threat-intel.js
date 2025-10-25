// Threat Intelligence Module - Complete with All APIs
class ThreatIntelligence {
    constructor() {
        this.apiEndpoints = {
            virustotal: {
                base: 'https://www.virustotal.com/vtapi/v2',
                key: '0ddfbaf2e6331dc0a5718a9c3e3128764b87a542602c26c83b563043cf5638ba',
                status: 'active'
            },
            shodan: {
                base: 'https://api.shodan.io',
                key: 'eHkUEq8GimPQmhAumcVOHYAfGOp2Xvpc',
                status: 'active'
            },
            censys: {
                base: 'https://search.censys.io/api/v2',
                id: 'censys_iDMcXBED_Mw84T9Ufyvh3b28TpZdqX438',
                secret: '', // Leave empty for public endpoints
                status: 'active'
            },
            breachdirectory: {
                base: 'https://breachdirectory.p.rapidapi.com',
                status: 'active'
            },
            leakcheck: {
                base: 'https://leakcheck.io/api',
                status: 'active'
            },
            dehashed: {
                base: 'https://api.dehashed.com',
                status: 'active'
            },
            intelx: {
                base: 'https://2.intelx.io',
                status: 'active'
            }
        };
        
        this.corsProxies = [
            'https://api.allorigins.win/raw?url=',
            'https://cors-anywhere.herokuapp.com/',
            'https://cors-proxy.htmldriven.com/?url=',
            'https://api.codetabs.com/v1/proxy?quest='
        ];
        
        this.currentProxyIndex = 0;
        this.initializeAPIs();
    }

    async initializeAPIs() {
        console.log('Initializing all threat intelligence APIs...');
        // Don't test APIs on init to avoid CORS errors during startup
    }

    // Enhanced CORS handler with multiple fallbacks
    async makeAPICall(url, options = {}) {
        const maxRetries = this.corsProxies.length;
        
        for (let i = 0; i < maxRetries; i++) {
            const proxy = this.corsProxies[this.currentProxyIndex];
            try {
                const proxyUrl = proxy + encodeURIComponent(url);
                console.log(`Attempting API call with proxy: ${proxy}`);
                
                const response = await fetch(proxyUrl, {
                    method: 'GET',
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest',
                        ...options.headers
                    },
                    timeout: 10000
                });
                
                if (response.ok) {
                    const data = await response.json();
                    console.log(`API call successful with proxy: ${proxy}`);
                    return data;
                }
            } catch (error) {
                console.log(`Proxy ${proxy} failed: ${error.message}`);
            }
            
            // Rotate to next proxy
            this.currentProxyIndex = (this.currentProxyIndex + 1) % this.corsProxies.length;
        }
        
        throw new Error('All CORS proxies failed. Using simulation mode.');
    }

    // Direct API call without proxy (for APIs that don't have CORS issues)
    async makeDirectAPICall(url, options = {}) {
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    ...options.headers
                }
            });
            
            if (response.ok) {
                return await response.json();
            }
            throw new Error(`API returned ${response.status}`);
        } catch (error) {
            throw new Error(`Direct API call failed: ${error.message}`);
        }
    }

    async analyzeFileHash() {
        const hash = document.getElementById('file-hash').value.trim();
        
        if (!hash) {
            securityApp.showNotification('Please enter a file hash', 'warning');
            return;
        }

        if (!this.validateHash(hash)) {
            securityApp.showNotification('Please enter a valid MD5, SHA1, or SHA256 hash', 'warning');
            return;
        }

        securityApp.showLoading('Analyzing file hash with VirusTotal...');

        try {
            const result = await this.callVirusTotalFileAPI(hash);
            this.displayVirusTotalResults(result, 'File Analysis');
            
            securityApp.addScanActivity({
                type: 'File Hash Analysis',
                target: hash,
                result: result.positives > 0 ? 'Malicious' : 'Clean',
                severity: result.positives > 0 ? 'high' : 'low'
            });
            
        } catch (error) {
            console.error('VirusTotal API failed, using simulation:', error);
            const result = await this.simulateFileAnalysis(hash);
            this.displaySimulatedResults(result, 'File Analysis');
            
            securityApp.addScanActivity({
                type: 'File Hash Analysis (Simulated)',
                target: hash,
                result: result.positives > 0 ? 'Malicious' : 'Clean',
                severity: result.positives > 0 ? 'high' : 'low'
            });
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

        try {
            new URL(url);
        } catch {
            securityApp.showNotification('Please enter a valid URL', 'warning');
            return;
        }

        securityApp.showLoading('Scanning URL with VirusTotal...');

        try {
            const result = await this.callVirusTotalURLAPI(url);
            this.displayVirusTotalResults(result, 'URL Analysis');
            
            securityApp.addScanActivity({
                type: 'URL Scan',
                target: url,
                result: result.positives > 0 ? 'Malicious' : 'Clean',
                severity: result.positives > 0 ? 'high' : 'low'
            });
            
        } catch (error) {
            console.error('VirusTotal API failed, using simulation:', error);
            const result = await this.simulateURLAnalysis(url);
            this.displaySimulatedResults(result, 'URL Analysis');
            
            securityApp.addScanActivity({
                type: 'URL Scan (Simulated)',
                target: url,
                result: result.positives > 0 ? 'Malicious' : 'Clean',
                severity: result.positives > 0 ? 'high' : 'low'
            });
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

        if (!this.validateEmail(email)) {
            securityApp.showNotification('Please enter a valid email address', 'warning');
            return;
        }

        securityApp.showLoading('Checking email across multiple breach databases...');

        try {
            let result;
            let apiUsed = 'Multiple Sources';
            
            // Try all breach APIs in sequence
            const apisToTry = ['leakcheck', 'breachdirectory', 'dehashed'];
            
            for (const apiName of apisToTry) {
                try {
                    if (apiName === 'leakcheck') {
                        result = await this.callLeakCheckAPI(email);
                        apiUsed = 'LeakCheck.io';
                        break;
                    } else if (apiName === 'breachdirectory') {
                        result = await this.callBreachDirectoryAPI(email);
                        apiUsed = 'BreachDirectory';
                        break;
                    } else if (apiName === 'dehashed') {
                        result = await this.callDehashedAPI(email);
                        apiUsed = 'DeHashed';
                        break;
                    }
                } catch (error) {
                    console.log(`${apiName} failed, trying next...`);
                    continue;
                }
            }
            
            if (!result) {
                throw new Error('All breach APIs failed');
            }
            
            this.displayBreachResults(result, email, apiUsed);
            
            securityApp.addScanActivity({
                type: 'Email Breach Check',
                target: email,
                result: result.found > 0 ? 'Compromised' : 'Safe',
                severity: result.found > 0 ? 'medium' : 'low'
            });
            
        } catch (error) {
            console.error('All breach APIs failed, using simulation:', error);
            const result = await this.simulateBreachCheck(email);
            this.displayBreachResults(result, email, 'Simulation');
            
            securityApp.addScanActivity({
                type: 'Email Breach Check (Simulated)',
                target: email,
                result: result.found > 0 ? 'Compromised' : 'Safe',
                severity: result.found > 0 ? 'medium' : 'low'
            });
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

        securityApp.showLoading('Checking password against known breaches...');

        try {
            const result = await this.callHIBPPasswordAPI(password);
            this.displayPasswordResults(result);
            
            securityApp.addScanActivity({
                type: 'Password Check',
                target: '***' + password.slice(-3),
                result: result.found ? 'Compromised' : 'Safe',
                severity: result.found ? 'high' : 'low'
            });
            
        } catch (error) {
            console.error('Password API failed, using simulation:', error);
            const result = await this.simulatePasswordCheck(password);
            this.displayPasswordResults(result, true);
            
            securityApp.addScanActivity({
                type: 'Password Check (Simulated)',
                target: '***' + password.slice(-3),
                result: result.found ? 'Compromised' : 'Safe',
                severity: result.found ? 'high' : 'low'
            });
        } finally {
            securityApp.hideLoading();
        }
    }

    async checkIPReputation() {
        const ip = document.getElementById('abuseipdb-ip').value.trim();
        
        if (!ip) {
            securityApp.showNotification('Please enter an IP address', 'warning');
            return;
        }

        if (!this.validateIP(ip)) {
            securityApp.showNotification('Please enter a valid IP address', 'warning');
            return;
        }

        securityApp.showLoading('Analyzing IP reputation across multiple sources...');

        try {
            let result;
            let apiUsed = 'Multiple Sources';
            
            // Try all IP reputation APIs
            const apisToTry = ['shodan', 'censys'];
            
            for (const apiName of apisToTry) {
                try {
                    if (apiName === 'shodan') {
                        result = await this.callShodanIPAPI(ip);
                        apiUsed = 'Shodan';
                        break;
                    } else if (apiName === 'censys') {
                        result = await this.callCensysIPAPI(ip);
                        apiUsed = 'Censys';
                        break;
                    }
                } catch (error) {
                    console.log(`${apiName} failed, trying next...`);
                    continue;
                }
            }
            
            if (!result) {
                throw new Error('All IP reputation APIs failed');
            }
            
            this.displayIPReputationResults(result, apiUsed);
            
            securityApp.addScanActivity({
                type: 'IP Reputation Check',
                target: ip,
                result: this.getIPRiskLevel(result),
                severity: this.getIPRiskSeverity(result)
            });
            
        } catch (error) {
            console.error('All IP APIs failed, using simulation:', error);
            const result = await this.simulateIPAnalysis(ip);
            this.displayIPReputationResults(result, 'Simulation');
            
            securityApp.addScanActivity({
                type: 'IP Reputation Check (Simulated)',
                target: ip,
                result: this.getIPRiskLevel(result),
                severity: this.getIPRiskSeverity(result)
            });
        } finally {
            securityApp.hideLoading();
        }
    }

    // REAL API CALLS - ALL INTEGRATIONS
    async callVirusTotalFileAPI(hash) {
        const url = `${this.apiEndpoints.virustotal.base}/file/report?apikey=${this.apiEndpoints.virustotal.key}&resource=${hash}`;
        return await this.makeAPICall(url);
    }

    async callVirusTotalURLAPI(url) {
        const apiUrl = `${this.apiEndpoints.virustotal.base}/url/report?apikey=${this.apiEndpoints.virustotal.key}&resource=${encodeURIComponent(url)}`;
        return await this.makeAPICall(apiUrl);
    }

    async callShodanIPAPI(ip) {
        const url = `${this.apiEndpoints.shodan.base}/shodan/host/${ip}?key=${this.apiEndpoints.shodan.key}`;
        return await this.makeAPICall(url);
    }

    async callCensysIPAPI(ip) {
        // Use public Censys endpoint
        const url = `https://search.censys.io/api/v2/hosts/${ip}`;
        return await this.makeAPICall(url);
    }

    async callBreachDirectoryAPI(email) {
        const url = `https://breachdirectory.tk/?func=auto&term=${encodeURIComponent(email)}`;
        return await this.makeAPICall(url);
    }

    async callLeakCheckAPI(email) {
        const url = `https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`;
        return await this.makeAPICall(url);
    }

    async callDehashedAPI(email) {
        const url = `https://api.dehashed.com/search?query=email:"${encodeURIComponent(email)}"`;
        return await this.makeAPICall(url);
    }

    async callIntelxAPI(query) {
        const url = `https://2.intelx.io/intelligent/search?q=${encodeURIComponent(query)}`;
        return await this.makeAPICall(url);
    }

    async callHIBPPasswordAPI(password) {
        // HIBP Password API (no CORS issues - works directly)
        const hash = await this.sha1(password);
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5).toUpperCase();
        
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        
        if (!response.ok) {
            throw new Error(`HIBP API error: ${response.status}`);
        }
        
        const data = await response.text();
        const found = data.includes(suffix);
        
        return {
            found: found,
            count: found ? this.extractCount(data, suffix) : 0
        };
    }

    // SIMULATION METHODS (Fallbacks - Keep all existing)
    async simulateFileAnalysis(hash) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        return {
            positives: Math.random() > 0.7 ? Math.floor(Math.random() * 20) + 1 : 0,
            total: 65,
            scan_date: new Date().toISOString(),
            scans: Array.from({length: 8}, (_, i) => ({
                name: `Antivirus ${i + 1}`,
                detected: Math.random() > 0.8,
                result: Math.random() > 0.8 ? 'malicious' : 'clean'
            }))
        };
    }

    async simulateURLAnalysis(url) {
        await new Promise(resolve => setTimeout(resolve, 1200));
        
        return {
            positives: Math.random() > 0.8 ? Math.floor(Math.random() * 15) + 1 : 0,
            total: 65,
            scan_date: new Date().toISOString()
        };
    }

    async simulateBreachCheck(email) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        const hasBreaches = Math.random() > 0.4;
        return {
            found: hasBreaches ? Math.floor(Math.random() * 5) + 1 : 0,
            breaches: hasBreaches ? [
                { 
                    name: 'Example Breach 2023', 
                    date: '2023-01-15', 
                    data_classes: ['Emails', 'Passwords'],
                    description: 'Sample breach description for demonstration'
                },
                { 
                    name: 'Test Service 2022', 
                    date: '2022-08-22', 
                    data_classes: ['Emails', 'Usernames'],
                    description: 'Another sample breach for testing'
                }
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

    async simulateIPAnalysis(ip) {
        await new Promise(resolve => setTimeout(resolve, 1300));
        
        return {
            ip: ip,
            riskScore: Math.floor(Math.random() * 10),
            ports: Array.from({length: Math.floor(Math.random() * 6)}, () => 
                [80, 443, 22, 21, 25, 53, 3389][Math.floor(Math.random() * 7)]
            ),
            country: 'US',
            isp: 'Example ISP',
            lastSeen: new Date().toISOString()
        };
    }

    // UTILITY METHODS
    validateHash(hash) {
        const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
        return hashRegex.test(hash.trim());
    }

    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email.trim());
    }

    validateIP(ip) {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip.trim());
    }

    async sha1(str) {
        const buffer = new TextEncoder().encode(str);
        const hash = await crypto.subtle.digest('SHA-1', buffer);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    extractCount(data, suffix) {
        const lines = data.split('\n');
        for (const line of lines) {
            if (line.startsWith(suffix)) {
                return parseInt(line.split(':')[1]);
            }
        }
        return 0;
    }

    getIPRiskLevel(result) {
        const score = result.riskScore || (result.ports ? result.ports.length * 2 : 0);
        if (score > 7) return 'High Risk';
        if (score > 4) return 'Medium Risk';
        return 'Low Risk';
    }

    getIPRiskSeverity(result) {
        const score = result.riskScore || (result.ports ? result.ports.length * 2 : 0);
        if (score > 7) return 'high';
        if (score > 4) return 'medium';
        return 'low';
    }

    getPortRiskColor(port) {
        const highRiskPorts = [21, 22, 23, 25, 53, 135, 139, 1433, 1434, 1521, 3306, 3389, 5432, 5900];
        const mediumRiskPorts = [80, 443, 8080, 8443, 8888];
        
        if (highRiskPorts.includes(port)) return 'danger';
        if (mediumRiskPorts.includes(port)) return 'warning';
        return 'info';
    }

    // DISPLAY METHODS (Keep all existing display methods)
    displayVirusTotalResults(result, type) {
        const container = document.getElementById('virustotal-results');
        const statusClass = result.positives > 0 ? 'result-malicious' : 'result-safe';
        
        container.innerHTML = `
            <div class="result-panel ${statusClass} fade-in">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-shield-alt me-2"></i>${type} - VirusTotal</h5>
                    <span class="badge bg-success">Live Data</span>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Detection Ratio:</strong> ${result.positives}/${result.total}</p>
                        <p><strong>Status:</strong> 
                            <span class="badge bg-${result.positives > 0 ? 'danger' : 'success'}">
                                ${result.positives > 0 ? 'MALICIOUS' : 'CLEAN'}
                            </span>
                        </p>
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
            </div>
        `;
    }

    displaySimulatedResults(result, type) {
        const container = document.getElementById('virustotal-results');
        const statusClass = result.positives > 0 ? 'result-suspicious' : 'result-safe';
        
        container.innerHTML = `
            <div class="result-panel ${statusClass} fade-in">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-desktop me-2"></i>${type}</h5>
                    <span class="badge bg-warning">Demo Data</span>
                </div>
                <div class="alert alert-info">
                    <i class="fas fa-info-circle me-2"></i>
                    Using simulated data. API services may be temporarily unavailable.
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Detection Ratio:</strong> ${result.positives}/${result.total}</p>
                        <p><strong>Status:</strong> 
                            <span class="badge bg-${result.positives > 0 ? 'warning' : 'success'}">
                                ${result.positives > 0 ? 'SUSPICIOUS' : 'CLEAN'}
                            </span>
                        </p>
                    </div>
                    <div class="col-md-6">
                        <div class="progress mb-2">
                            <div class="progress-bar ${result.positives > 0 ? 'bg-warning' : 'bg-success'}" 
                                 style="width: ${(result.positives / result.total) * 100}%">
                                ${Math.round((result.positives / result.total) * 100)}%
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    displayBreachResults(result, email, apiUsed) {
        const container = document.getElementById('hibp-results');
        const statusClass = result.found > 0 ? 'result-suspicious' : 'result-safe';
        const isSimulated = apiUsed === 'Simulation';
        
        container.innerHTML = `
            <div class="result-panel ${statusClass} fade-in">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-envelope me-2"></i>Email Breach Check</h5>
                    <span class="badge bg-${isSimulated ? 'warning' : 'success'}">${apiUsed}</span>
                </div>
                ${isSimulated ? `
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        Using simulated breach data for demonstration.
                    </div>
                ` : ''}
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Email:</strong> ${email}</p>
                        <p><strong>Status:</strong> 
                            <span class="badge bg-${result.found > 0 ? 'warning' : 'success'}">
                                ${result.found > 0 ? 'COMPROMISED' : 'SAFE'}
                            </span>
                        </p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Breaches Found:</strong> ${result.found}</p>
                    </div>
                </div>
                
                ${result.found > 0 ? `
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
                                            <td><strong>${breach.name}</strong></td>
                                            <td>${breach.date}</td>
                                            <td>${Array.isArray(breach.data_classes) ? breach.data_classes.join(', ') : breach.data_classes}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ` : `
                    <div class="alert alert-success mt-2">
                        <i class="fas fa-check-circle me-2"></i>
                        No breaches found for this email address.
                    </div>
                `}
            </div>
        `;
    }

    displayPasswordResults(result, isSimulated = false) {
        const container = document.getElementById('hibp-results');
        const statusClass = result.found ? 'result-malicious' : 'result-safe';
        
        container.innerHTML += `
            <div class="result-panel ${statusClass} fade-in mt-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-key me-2"></i>Password Security Check</h5>
                    <span class="badge bg-${isSimulated ? 'warning' : 'success'}">${isSimulated ? 'Demo' : 'HIBP Live'}</span>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Password Status:</strong> 
                            <span class="badge bg-${result.found ? 'danger' : 'success'}">
                                ${result.found ? 'COMPROMISED' : 'SECURE'}
                            </span>
                        </p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Times Exposed:</strong> ${result.found ? result.count.toLocaleString() : '0'}</p>
                    </div>
                </div>
                
                ${result.found ? `
                    <div class="alert alert-danger mt-2">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        <strong>Security Alert:</strong> This password has been exposed in data breaches.
                    </div>
                ` : `
                    <div class="alert alert-success mt-2">
                        <i class="fas fa-check-circle me-2"></i>
                        This password has not been found in any known data breaches.
                    </div>
                `}
            </div>
        `;
    }

    displayIPReputationResults(result, apiUsed) {
        const container = document.getElementById('abuseipdb-results');
        const isSimulated = apiUsed === 'Simulation';
        
        let statusClass = 'result-safe';
        let statusText = 'LOW RISK';
        const riskScore = result.riskScore || (result.ports ? result.ports.length * 2 : 0);
        
        if (riskScore > 7) {
            statusClass = 'result-malicious';
            statusText = 'HIGH RISK';
        } else if (riskScore > 4) {
            statusClass = 'result-suspicious';
            statusText = 'MEDIUM RISK';
        }
        
        container.innerHTML = `
            <div class="result-panel ${statusClass} fade-in">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-flag me-2"></i>IP Reputation Analysis</h5>
                    <span class="badge bg-${isSimulated ? 'warning' : 'success'}">${apiUsed}</span>
                </div>
                ${isSimulated ? `
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        Using simulated IP data for demonstration.
                    </div>
                ` : ''}
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>IP Address:</strong> ${result.ip}</p>
                        <p><strong>Risk Score:</strong> ${riskScore}/10</p>
                        <p><strong>Status:</strong> 
                            <span class="badge bg-${statusClass === 'result-malicious' ? 'danger' : statusClass === 'result-suspicious' ? 'warning' : 'success'}">
                                ${statusText}
                            </span>
                        </p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Country:</strong> ${result.country || 'Unknown'}</p>
                        <p><strong>ISP:</strong> ${result.isp || 'Unknown'}</p>
                        <p><strong>Last Seen:</strong> ${new Date(result.lastSeen).toLocaleDateString()}</p>
                    </div>
                </div>
                
                ${result.ports && result.ports.length > 0 ? `
                    <div class="mt-3">
                        <h6>Open Ports:</h6>
                        <div class="d-flex flex-wrap gap-2">
                            ${result.ports.map(port => `
                                <span class="badge bg-${this.getPortRiskColor(port)}">Port ${port}</span>
                            `).join('')}
                        </div>
                    </div>
                ` : ''}
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