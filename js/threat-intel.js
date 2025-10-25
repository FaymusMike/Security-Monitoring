// Threat Intelligence Module with Smart Fallbacks
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
                secret: 'YOUR_CENSYS_SECRET', // You'll need to get this
                status: 'active'
            },
            breachdirectory: {
                base: 'https://breachdirectory.p.rapidapi.com',
                status: 'active'
            },
            leakcheck: {
                base: 'https://leakcheck.io/api',
                status: 'active'
            }
        };
        
        this.currentBreachAPI = 'breachdirectory';
        this.currentIPAPI = 'shodan';
        this.initializeAPIs();
    }

    async initializeAPIs() {
        // Test API availability
        await this.testAPIs();
    }

    async testAPIs() {
        console.log('Testing API availability...');
        
        // Test VirusTotal
        try {
            const test = await fetch(`${this.apiEndpoints.virustotal.base}/domain/report?apikey=${this.apiEndpoints.virustotal.key}&domain=example.com`);
            if (!test.ok) {
                this.apiEndpoints.virustotal.status = 'inactive';
                console.warn('VirusTotal API not available');
            }
        } catch (error) {
            this.apiEndpoints.virustotal.status = 'inactive';
            console.warn('VirusTotal API test failed:', error);
        }

        // Test Shodan
        try {
            const test = await fetch(`${this.apiEndpoints.shodan.base}/api-info?key=${this.apiEndpoints.shodan.key}`);
            if (!test.ok) {
                this.apiEndpoints.shodan.status = 'inactive';
                console.warn('Shodan API not available');
            }
        } catch (error) {
            this.apiEndpoints.shodan.status = 'inactive';
            console.warn('Shodan API test failed:', error);
        }
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
            let result;
            
            // Try VirusTotal first
            if (this.apiEndpoints.virustotal.status === 'active') {
                try {
                    result = await this.callVirusTotalFileAPI(hash);
                    this.displayVirusTotalResults(result);
                } catch (error) {
                    console.warn('VirusTotal failed, using simulation:', error);
                    result = await this.simulateFileAnalysis(hash);
                    this.displaySimulatedResults(result, 'File Analysis');
                }
            } else {
                result = await this.simulateFileAnalysis(hash);
                this.displaySimulatedResults(result, 'File Analysis');
            }
            
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
            let result;
            
            // Try multiple approaches for URL scanning
            if (this.apiEndpoints.virustotal.status === 'active') {
                try {
                    result = await this.callVirusTotalURLReportAPI(url);
                    this.displayVirusTotalResults(result);
                } catch (error) {
                    console.warn('VirusTotal URL scan failed:', error);
                    result = await this.simulateURLAnalysis(url);
                    this.displaySimulatedResults(result, 'URL Analysis');
                }
            } else {
                result = await this.simulateURLAnalysis(url);
                this.displaySimulatedResults(result, 'URL Analysis');
            }
            
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
            let result;
            let apiUsed = 'Simulation';
            
            // Try multiple breach APIs with fallbacks
            const apisToTry = ['breachdirectory', 'leakcheck'];
            
            for (const apiName of apisToTry) {
                if (this.apiEndpoints[apiName]?.status === 'active') {
                    try {
                        if (apiName === 'breachdirectory') {
                            result = await this.callBreachDirectoryAPI(email);
                            apiUsed = 'BreachDirectory';
                            break;
                        } else if (apiName === 'leakcheck') {
                            result = await this.callLeakCheckAPI(email);
                            apiUsed = 'LeakCheck';
                            break;
                        }
                    } catch (error) {
                        console.warn(`${apiName} failed:`, error);
                        continue;
                    }
                }
            }
            
            // If all APIs fail, use simulation
            if (!result) {
                result = await this.simulateBreachCheck(email);
                apiUsed = 'Simulation';
            }
            
            this.displayBreachResults(result, email, apiUsed);
            
            securityApp.addScanActivity({
                type: 'Email Breach Check',
                target: email,
                result: result.found > 0 ? 'Compromised' : 'Safe',
                severity: result.found > 0 ? 'medium' : 'low'
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

        securityApp.showLoading('Checking password security...');

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
            let result;
            let apiUsed = 'Simulation';
            
            // Try multiple IP reputation APIs
            const apisToTry = ['shodan', 'censys'];
            
            for (const apiName of apisToTry) {
                if (this.apiEndpoints[apiName]?.status === 'active') {
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
                        console.warn(`${apiName} failed:`, error);
                        continue;
                    }
                }
            }
            
            // If all APIs fail, use simulation
            if (!result) {
                result = await this.simulateIPAnalysis(ip);
                apiUsed = 'Simulation';
            }
            
            this.displayIPReputationResults(result, apiUsed);
            
            securityApp.addScanActivity({
                type: 'IP Reputation Check',
                target: ip,
                result: result.riskScore > 7 ? 'High Risk' : result.riskScore > 4 ? 'Medium Risk' : 'Low Risk',
                severity: result.riskScore > 7 ? 'high' : result.riskScore > 4 ? 'medium' : 'low'
            });
            
        } catch (error) {
            console.error('Error checking IP reputation:', error);
            securityApp.showNotification('Error checking IP reputation', 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    // API Call Methods with CORS Proxies
    async callVirusTotalFileAPI(hash) {
        // Use CORS proxy for VirusTotal
        const proxyUrl = 'https://cors-anywhere.herokuapp.com/';
        const targetUrl = `${this.apiEndpoints.virustotal.base}/file/report?apikey=${this.apiEndpoints.virustotal.key}&resource=${hash}`;
        
        const response = await fetch(proxyUrl + targetUrl, {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (!response.ok) {
            throw new Error(`VirusTotal API error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.response_code === 0) {
            throw new Error('File not found in VirusTotal database');
        }
        
        return data;
    }

    async callVirusTotalURLReportAPI(url) {
        // Direct report API call (no scanning required)
        const proxyUrl = 'https://cors-anywhere.herokuapp.com/';
        const targetUrl = `${this.apiEndpoints.virustotal.base}/url/report?apikey=${this.apiEndpoints.virustotal.key}&resource=${encodeURIComponent(url)}`;
        
        const response = await fetch(proxyUrl + targetUrl, {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (!response.ok) {
            throw new Error(`VirusTotal API error: ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.response_code === 0) {
            throw new Error('URL not found in VirusTotal database');
        }
        
        return data;
    }

    async callShodanIPAPI(ip) {
        const proxyUrl = 'https://cors-anywhere.herokuapp.com/';
        const targetUrl = `${this.apiEndpoints.shodan.base}/shodan/host/${ip}?key=${this.apiEndpoints.shodan.key}`;
        
        const response = await fetch(proxyUrl + targetUrl, {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (!response.ok) {
            if (response.status === 404) {
                return { error: 'IP not found in Shodan database' };
            }
            throw new Error(`Shodan API error: ${response.status}`);
        }
        
        return await response.json();
    }

    async callCensysIPAPI(ip) {
        // Censys API implementation
        const proxyUrl = 'https://cors-anywhere.herokuapp.com/';
        const targetUrl = `${this.apiEndpoints.censys.base}/hosts/${ip}`;
        
        const auth = btoa(`${this.apiEndpoints.censys.id}:${this.apiEndpoints.censys.secret}`);
        
        const response = await fetch(proxyUrl + targetUrl, {
            headers: {
                'Authorization': `Basic ${auth}`,
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (!response.ok) {
            throw new Error(`Censys API error: ${response.status}`);
        }
        
        return await response.json();
    }

    async callBreachDirectoryAPI(email) {
        // Using direct API call with CORS proxy
        const proxyUrl = 'https://cors-anywhere.herokuapp.com/';
        const targetUrl = `https://breachdirectory.tk/?func=auto&term=${encodeURIComponent(email)}`;
        
        const response = await fetch(proxyUrl + targetUrl, {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (!response.ok) {
            throw new Error(`BreachDirectory API error: ${response.status}`);
        }
        
        return await response.json();
    }

    async callLeakCheckAPI(email) {
        // LeakCheck API implementation
        const proxyUrl = 'https://cors-anywhere.herokuapp.com/';
        const targetUrl = `https://leakcheck.io/api/public?check=${encodeURIComponent(email)}`;
        
        const response = await fetch(proxyUrl + targetUrl, {
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (!response.ok) {
            throw new Error(`LeakCheck API error: ${response.status}`);
        }
        
        return await response.json();
    }

    async callHIBPPasswordAPI(password) {
        // HIBP Password API (free - no key required, no CORS issues)
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

    // Simulation Methods (Fallbacks)
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
            scan_date: new Date().toISOString(),
            url: url
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
                }
            ] : []
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

    // Display Methods
    displayVirusTotalResults(result) {
        const container = document.getElementById('virustotal-results');
        const statusClass = result.positives > 0 ? 'result-malicious' : 'result-safe';
        
        container.innerHTML = `
            <div class="result-panel ${statusClass} fade-in">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-shield-alt me-2"></i>VirusTotal Analysis</h5>
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
                    <h5><i class="fas fa-desktop me-2"></i>${type} (Simulated)</h5>
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

    displayPasswordResults(result) {
        const container = document.getElementById('hibp-results');
        const statusClass = result.found ? 'result-malicious' : 'result-safe';
        
        container.innerHTML += `
            <div class="result-panel ${statusClass} fade-in mt-3">
                <div class="d-flex justify-content-between align-items-center mb-3">
                    <h5><i class="fas fa-key me-2"></i>Password Security Check</h5>
                    <span class="badge bg-success">HIBP Live</span>
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
        
        if (result.riskScore > 7) {
            statusClass = 'result-malicious';
            statusText = 'HIGH RISK';
        } else if (result.riskScore > 4) {
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
                        <p><strong>Risk Score:</strong> ${result.riskScore}/10</p>
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

    // Utility Methods
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

    getPortRiskColor(port) {
        const highRiskPorts = [21, 22, 23, 25, 53, 135, 139, 1433, 1434, 1521, 3306, 3389, 5432, 5900];
        const mediumRiskPorts = [80, 443, 8080, 8443, 8888];
        
        if (highRiskPorts.includes(port)) return 'danger';
        if (mediumRiskPorts.includes(port)) return 'warning';
        return 'info';
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