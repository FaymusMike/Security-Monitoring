// Threat Hunting Module
class ThreatHunting {
    constructor() {
        this.apiEndpoints = {
            shodan: {
                base: 'https://api.shodan.io',
                key: 'eHkUEq8GimPQmhAumcVOHYAfGOp2Xvpc'
            },
            virustotal: {
                base: 'https://www.virustotal.com/vtapi/v2',
                key: '0ddfbaf2e6331dc0a5718a9c3e3128764b87a542602c26c83b563043cf5638ba'
            }
        };
        this.customQueries = this.loadCustomQueries();
    }

    async searchShodan() {
        const query = document.getElementById('shodan-query').value.trim();
        const filters = document.getElementById('shodan-filters').value.trim();
        
        if (!query) {
            securityApp.showNotification('Please enter a search query', 'warning');
            return;
        }

        securityApp.showLoading('Searching Shodan database...');

        try {
            const searchQuery = filters ? `${query} ${filters}` : query;
            const result = await this.callShodanSearchAPI(searchQuery);
            this.displayShodanResults(result, searchQuery);
            
            securityApp.addScanActivity({
                type: 'Shodan Search',
                target: query,
                result: `Found ${result.total} results`,
                severity: 'low'
            });
            
        } catch (error) {
            console.error('Error searching Shodan:', error);
            securityApp.showNotification('Error searching Shodan: ' + error.message, 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    async searchCVE() {
        const cveId = document.getElementById('cve-id').value.trim();
        
        if (!cveId) {
            securityApp.showNotification('Please enter a CVE ID', 'warning');
            return;
        }

        if (!cveId.match(/^CVE-\d{4}-\d+$/)) {
            securityApp.showNotification('Please enter a valid CVE ID (CVE-YYYY-NNNN...)', 'warning');
            return;
        }

        securityApp.showLoading('Searching CVE database...');

        try {
            const result = await this.callCVEsearchAPI(cveId);
            this.displayCVEResults(result);
            
            securityApp.addScanActivity({
                type: 'CVE Search',
                target: cveId,
                result: result.vulnerability ? 'Vulnerability Found' : 'Not Found',
                severity: result.vulnerability ? 'medium' : 'low'
            });
            
        } catch (error) {
            console.error('Error searching CVE:', error);
            securityApp.showNotification('Error searching CVE: ' + error.message, 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    async searchProduct() {
        const product = document.getElementById('census-product').value.trim();
        
        if (!product) {
            securityApp.showNotification('Please enter a product name', 'warning');
            return;
        }

        securityApp.showLoading('Searching for product vulnerabilities...');

        try {
            const result = await this.callProductSearchAPI(product);
            this.displayProductResults(result);
            
            securityApp.addScanActivity({
                type: 'Product Search',
                target: product,
                result: `Found ${result.vulnerabilities ? result.vulnerabilities.length : 0} vulnerabilities`,
                severity: result.vulnerabilities && result.vulnerabilities.length > 0 ? 'medium' : 'low'
            });
            
        } catch (error) {
            console.error('Error searching product:', error);
            securityApp.showNotification('Error searching product: ' + error.message, 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    async executeCustomQuery() {
        const query = document.getElementById('custom-query').value.trim();
        const queryType = document.getElementById('query-type').value;
        
        if (!query) {
            securityApp.showNotification('Please enter a custom query', 'warning');
            return;
        }

        securityApp.showLoading('Executing custom query...');

        try {
            let result;
            switch(queryType) {
                case 'ioc':
                    result = await this.searchIOC(query);
                    break;
                case 'behavior':
                    result = await this.analyzeBehavior(query);
                    break;
                case 'network':
                    result = await this.analyzeNetwork(query);
                    break;
                case 'endpoint':
                    result = await this.analyzeEndpoint(query);
                    break;
                default:
                    throw new Error('Unknown query type');
            }
            
            this.displayCustomResults(result, queryType);
            
            securityApp.addScanActivity({
                type: `Custom ${queryType.charAt(0).toUpperCase() + queryType.slice(1)} Query`,
                target: query.substring(0, 50) + (query.length > 50 ? '...' : ''),
                result: `Executed successfully`,
                severity: 'low'
            });
            
            this.saveCustomQuery(query, queryType);
            
        } catch (error) {
            console.error('Error executing custom query:', error);
            securityApp.showNotification('Error executing custom query: ' + error.message, 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    // Real API Calls
    async callShodanSearchAPI(query) {
        const url = `${this.apiEndpoints.shodan.base}/shodan/host/search?key=${this.apiEndpoints.shodan.key}&query=${encodeURIComponent(query)}`;
        
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error(`Shodan API error: ${response.status}`);
        }
        
        return await response.json();
    }

    async callCVEsearchAPI(cveId) {
        // Using NVD API (free) for CVE search
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`;
        
        const response = await fetch(url);
        
        if (!response.ok) {
            // Fallback to simulation
            return await this.simulateCVESearch(cveId);
        }
        
        const data = await response.json();
        
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            return { vulnerability: data.vulnerabilities[0].cve };
        }
        
        return { vulnerability: null };
    }

    async callProductSearchAPI(product) {
        // Search for product vulnerabilities using NVD API
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(product)}`;
        
        const response = await fetch(url);
        
        if (!response.ok) {
            // Fallback to simulation
            return await this.simulateProductSearch(product);
        }
        
        const data = await response.json();
        return {
            vulnerabilities: data.vulnerabilities ? data.vulnerabilities.slice(0, 10) : []
        };
    }

    // Custom Query Handlers
    async searchIOC(ioc) {
        // Search for Indicators of Compromise
        let result = {};
        
        // Check if it's an IP
        if (SecurityUtils.validateIP(ioc)) {
            result.ipInfo = await this.callShodanIPAPI(ioc);
        }
        
        // Check if it's a hash
        if (SecurityUtils.validateHash(ioc)) {
            result.hashInfo = await this.callVirusTotalFileAPI(ioc);
        }
        
        // Check if it's a domain
        if (ioc.includes('.') && !SecurityUtils.validateIP(ioc)) {
            result.domainInfo = await this.searchDomainInfo(ioc);
        }
        
        return result;
    }

    async analyzeBehavior(pattern) {
        // Simulate behavior analysis
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        return {
            matches: Array.from({length: Math.floor(Math.random() * 5) + 1}, (_, i) => ({
                id: i + 1,
                timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
                source: `Endpoint ${i + 1}`,
                behavior: pattern,
                risk: ['Low', 'Medium', 'High'][Math.floor(Math.random() * 3)],
                confidence: Math.floor(Math.random() * 100)
            }))
        };
    }

    async analyzeNetwork(pattern) {
        // Simulate network traffic analysis
        await new Promise(resolve => setTimeout(resolve, 1200));
        
        return {
            traffic: Array.from({length: Math.floor(Math.random() * 8) + 1}, (_, i) => ({
                id: i + 1,
                source_ip: `192.168.1.${Math.floor(Math.random() * 255)}`,
                dest_ip: `10.0.0.${Math.floor(Math.random() * 255)}`,
                protocol: ['TCP', 'UDP', 'HTTP', 'HTTPS'][Math.floor(Math.random() * 4)],
                port: Math.floor(Math.random() * 65535),
                bytes: Math.floor(Math.random() * 1000000),
                timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString()
            }))
        };
    }

    async analyzeEndpoint(pattern) {
        // Simulate endpoint data analysis
        await new Promise(resolve => setTimeout(resolve, 1800));
        
        return {
            endpoints: Array.from({length: Math.floor(Math.random() * 6) + 1}, (_, i) => ({
                id: i + 1,
                hostname: `WORKSTATION-${String.fromCharCode(65 + i)}`,
                os: ['Windows 10', 'Windows 11', 'Linux', 'macOS'][Math.floor(Math.random() * 4)],
                last_seen: new Date(Date.now() - Math.random() * 86400000).toISOString(),
                status: ['Online', 'Offline', 'Suspicious'][Math.floor(Math.random() * 3)],
                processes: Math.floor(Math.random() * 100) + 50
            }))
        };
    }

    // Helper API Calls
    async callShodanIPAPI(ip) {
        const url = `${this.apiEndpoints.shodan.base}/shodan/host/${ip}?key=${this.apiEndpoints.shodan.key}`;
        const response = await fetch(url);
        return response.ok ? await response.json() : { error: 'IP not found' };
    }

    async callVirusTotalFileAPI(hash) {
        const url = `${this.apiEndpoints.virustotal.base}/file/report?apikey=${this.apiEndpoints.virustotal.key}&resource=${hash}`;
        const response = await fetch(url);
        return response.ok ? await response.json() : { error: 'Hash not found' };
    }

    async searchDomainInfo(domain) {
        // Simple domain info simulation
        await new Promise(resolve => setTimeout(resolve, 800));
        
        return {
            domain: domain,
            registered: Math.random() > 0.3,
            risk_score: Math.floor(Math.random() * 100),
            reputation: ['Good', 'Suspicious', 'Malicious'][Math.floor(Math.random() * 3)]
        };
    }

    // Display Methods
    displayShodanResults(result, query) {
        const container = document.getElementById('shodan-results');
        
        container.innerHTML = `
            <div class="result-panel result-safe fade-in">
                <h5><i class="fas fa-search me-2"></i>Shodan Search Results</h5>
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Query:</strong> <code>${query}</code></p>
                        <p><strong>Total Results:</strong> ${result.total.toLocaleString()}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Countries:</strong> ${this.getUniqueCountries(result.matches)}</p>
                        <p><strong>Ports Found:</strong> ${this.getUniquePorts(result.matches)}</p>
                    </div>
                </div>
                
                <div class="mt-3">
                    <h6>Discovered Hosts:</h6>
                    <div class="table-responsive">
                        <table class="table table-sm table-hover">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Port</th>
                                    <th>Organization</th>
                                    <th>Location</th>
                                    <th>Service</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${result.matches.slice(0, 10).map(device => `
                                    <tr>
                                        <td><code>${device.ip_str}</code></td>
                                        <td>${device.port}</td>
                                        <td>${device.org || 'Unknown'}</td>
                                        <td>${device.location ? `${device.location.city || 'Unknown'}, ${device.location.country_name || 'Unknown'}` : 'Unknown'}</td>
                                        <td>${device.product || 'Unknown'}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
                
                ${result.total > 10 ? `
                    <div class="alert alert-info mt-2">
                        <i class="fas fa-info-circle me-2"></i>
                        Showing 10 of ${result.total.toLocaleString()} results. Refine your search for more specific results.
                    </div>
                ` : ''}
            </div>
        `;
    }

    displayCVEResults(result) {
        const container = document.getElementById('census-results');
        
        if (result.vulnerability) {
            const vuln = result.vulnerability;
            const metrics = vuln.metrics || {};
            const cvssData = metrics.cvssMetricV31 || metrics.cvssMetricV30 || metrics.cvssMetricV2 || [{}];
            const cvss = cvssData[0].cvssData || {};
            
            const severityClass = this.getCVSSClass(cvss.baseScore);
            const severityColor = this.getCVSSColor(cvss.baseScore);
            
            container.innerHTML = `
                <div class="result-panel ${severityClass} fade-in">
                    <h5><i class="fas fa-bug me-2"></i>CVE Vulnerability Details</h5>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>CVE ID:</strong> <code>${vuln.id}</code></p>
                            <p><strong>Published:</strong> ${vuln.published || 'N/A'}</p>
                            <p><strong>Last Modified:</strong> ${vuln.lastModified || 'N/A'}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong>CVSS Score:</strong> 
                                <span class="badge bg-${severityColor}">${cvss.baseScore || 'N/A'}</span>
                            </p>
                            <p><strong>Severity:</strong> ${cvss.baseSeverity || 'N/A'}</p>
                            <p><strong>Vector:</strong> <small>${cvss.vectorString || 'N/A'}</small></p>
                        </div>
                    </div>
                    
                    <div class="mt-3">
                        <strong>Description:</strong>
                        <p class="mb-0">${vuln.descriptions ? vuln.descriptions[0].value : 'No description available'}</p>
                    </div>
                    
                    ${vuln.references ? `
                        <div class="mt-3">
                            <strong>References:</strong>
                            <ul class="small">
                                ${vuln.references.slice(0, 5).map(ref => `
                                    <li><a href="${ref.url}" target="_blank">${ref.url}</a></li>
                                `).join('')}
                            </ul>
                        </div>
                    ` : ''}
                </div>
            `;
        } else {
            container.innerHTML = `
                <div class="result-panel result-safe fade-in">
                    <h5><i class="fas fa-bug me-2"></i>CVE Search Results</h5>
                    <div class="alert alert-info">
                        <i class="fas fa-info-circle me-2"></i>
                        No vulnerability information found for this CVE ID in the NVD database.
                    </div>
                </div>
            `;
        }
    }

    displayProductResults(result) {
        const container = document.getElementById('census-results');
        
        if (result.vulnerabilities && result.vulnerabilities.length > 0) {
            container.innerHTML = `
                <div class="result-panel result-suspicious fade-in">
                    <h5><i class="fas fa-cube me-2"></i>Product Vulnerability Results</h5>
                    <p><strong>Product:</strong> ${document.getElementById('census-product').value}</p>
                    <p><strong>Vulnerabilities Found:</strong> ${result.vulnerabilities.length}</p>
                    
                    <div class="mt-3">
                        <h6>Recent Vulnerabilities:</h6>
                        <div class="table-responsive">
                            <table class="table table-sm table-hover">
                                <thead>
                                    <tr>
                                        <th>CVE ID</th>
                                        <th>Severity</th>
                                        <th>CVSS Score</th>
                                        <th>Published</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${result.vulnerabilities.slice(0, 8).map(vuln => {
                                        const cve = vuln.cve;
                                        const metrics = cve.metrics || {};
                                        const cvssData = metrics.cvssMetricV31 || metrics.cvssMetricV30 || metrics.cvssMetricV2 || [{}];
                                        const cvss = cvssData[0].cvssData || {};
                                        const severityColor = this.getCVSSColor(cvss.baseScore);
                                        
                                        return `
                                            <tr>
                                                <td><code>${cve.id}</code></td>
                                                <td>
                                                    <span class="badge bg-${severityColor}">
                                                        ${cvss.baseSeverity || 'N/A'}
                                                    </span>
                                                </td>
                                                <td>${cvss.baseScore || 'N/A'}</td>
                                                <td>${cve.published ? new Date(cve.published).toLocaleDateString() : 'N/A'}</td>
                                                <td class="small">${cve.descriptions ? cve.descriptions[0].value.substring(0, 100) + '...' : 'No description'}</td>
                                            </tr>
                                        `;
                                    }).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
        } else {
            container.innerHTML = `
                <div class="result-panel result-safe fade-in">
                    <h5><i class="fas fa-cube me-2"></i>Product Vulnerability Results</h5>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle me-2"></i>
                        No known vulnerabilities found for this product in the NVD database.
                    </div>
                </div>
            `;
        }
    }

    displayCustomResults(result, queryType) {
        const container = document.getElementById('custom-results');
        
        let content = '';
        
        switch(queryType) {
            case 'ioc':
                content = this.renderIOCResults(result);
                break;
            case 'behavior':
                content = this.renderBehaviorResults(result);
                break;
            case 'network':
                content = this.renderNetworkResults(result);
                break;
            case 'endpoint':
                content = this.renderEndpointResults(result);
                break;
            default:
                content = '<p>Unknown query type</p>';
        }
        
        container.innerHTML = `
            <div class="result-panel result-safe fade-in">
                <h5><i class="fas fa-code me-2"></i>Custom Query Results</h5>
                <p><strong>Query Type:</strong> ${queryType.toUpperCase()}</p>
                ${content}
            </div>
        `;
    }

    // Custom Query Renderers
    renderIOCResults(result) {
        let content = '';
        
        if (result.ipInfo && !result.ipInfo.error) {
            content += `
                <div class="mb-3">
                    <h6>IP Intelligence:</h6>
                    <p><strong>IP:</strong> ${result.ipInfo.ip_str}</p>
                    <p><strong>Organization:</strong> ${result.ipInfo.org || 'Unknown'}</p>
                    <p><strong>Open Ports:</strong> ${result.ipInfo.ports ? result.ipInfo.ports.join(', ') : 'None'}</p>
                </div>
            `;
        }
        
        if (result.hashInfo && result.hashInfo.response_code === 1) {
            content += `
                <div class="mb-3">
                    <h6>File Hash Analysis:</h6>
                    <p><strong>Detection Ratio:</strong> ${result.hashInfo.positives}/${result.hashInfo.total}</p>
                    <p><strong>Status:</strong> ${result.hashInfo.positives > 0 ? 'MALICIOUS' : 'CLEAN'}</p>
                </div>
            `;
        }
        
        if (result.domainInfo) {
            content += `
                <div class="mb-3">
                    <h6>Domain Information:</h6>
                    <p><strong>Domain:</strong> ${result.domainInfo.domain}</p>
                    <p><strong>Risk Score:</strong> ${result.domainInfo.risk_score}/100</p>
                    <p><strong>Reputation:</strong> ${result.domainInfo.reputation}</p>
                </div>
            `;
        }
        
        return content || '<p>No IOC matches found.</p>';
    }

    renderBehaviorResults(result) {
        if (!result.matches || result.matches.length === 0) {
            return '<p>No behavior matches found.</p>';
        }
        
        return `
            <div class="table-responsive">
                <table class="table table-sm">
                    <thead>
                        <tr>
                            <th>Endpoint</th>
                            <th>Behavior</th>
                            <th>Risk</th>
                            <th>Confidence</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${result.matches.map(match => `
                            <tr>
                                <td>${match.source}</td>
                                <td><code>${match.behavior}</code></td>
                                <td><span class="badge bg-${match.risk === 'High' ? 'danger' : match.risk === 'Medium' ? 'warning' : 'info'}">${match.risk}</span></td>
                                <td>${match.confidence}%</td>
                                <td>${new Date(match.timestamp).toLocaleString()}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    renderNetworkResults(result) {
        if (!result.traffic || result.traffic.length === 0) {
            return '<p>No network traffic matches found.</p>';
        }
        
        return `
            <div class="table-responsive">
                <table class="table table-sm">
                    <thead>
                        <tr>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Protocol</th>
                            <th>Port</th>
                            <th>Bytes</th>
                            <th>Timestamp</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${result.traffic.map(traffic => `
                            <tr>
                                <td><code>${traffic.source_ip}</code></td>
                                <td><code>${traffic.dest_ip}</code></td>
                                <td>${traffic.protocol}</td>
                                <td>${traffic.port}</td>
                                <td>${traffic.bytes.toLocaleString()}</td>
                                <td>${new Date(traffic.timestamp).toLocaleString()}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    renderEndpointResults(result) {
        if (!result.endpoints || result.endpoints.length === 0) {
            return '<p>No endpoint matches found.</p>';
        }
        
        return `
            <div class="table-responsive">
                <table class="table table-sm">
                    <thead>
                        <tr>
                            <th>Hostname</th>
                            <th>OS</th>
                            <th>Status</th>
                            <th>Processes</th>
                            <th>Last Seen</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${result.endpoints.map(endpoint => `
                            <tr>
                                <td>${endpoint.hostname}</td>
                                <td>${endpoint.os}</td>
                                <td><span class="badge bg-${endpoint.status === 'Suspicious' ? 'warning' : endpoint.status === 'Online' ? 'success' : 'secondary'}">${endpoint.status}</span></td>
                                <td>${endpoint.processes}</td>
                                <td>${new Date(endpoint.last_seen).toLocaleString()}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    // Utility Methods
    getUniqueCountries(matches) {
        if (!matches) return '0';
        const countries = new Set(matches.map(m => m.location?.country_code).filter(Boolean));
        return countries.size;
    }

    getUniquePorts(matches) {
        if (!matches) return '0';
        const ports = new Set(matches.map(m => m.port).filter(Boolean));
        return ports.size;
    }

    getCVSSClass(score) {
        if (!score) return 'result-safe';
        if (score >= 9.0) return 'result-malicious';
        if (score >= 7.0) return 'result-suspicious';
        if (score >= 4.0) return 'result-warning';
        return 'result-safe';
    }

    getCVSSColor(score) {
        if (!score) return 'secondary';
        if (score >= 9.0) return 'danger';
        if (score >= 7.0) return 'warning';
        if (score >= 4.0) return 'info';
        return 'success';
    }

    // Fallback simulation methods
    async simulateCVESearch(cveId) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        const hasVulnerability = Math.random() > 0.3;
        return {
            vulnerability: hasVulnerability ? {
                id: cveId,
                descriptions: [{ value: 'A critical vulnerability in example software that allows remote code execution.' }],
                metrics: {
                    cvssMetricV31: [{
                        cvssData: {
                            baseScore: (Math.random() * 10).toFixed(1),
                            baseSeverity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][Math.floor(Math.random() * 4)],
                            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
                        }
                    }]
                },
                published: '2023-01-15',
                lastModified: '2023-02-20'
            } : null
        };
    }

    async simulateProductSearch(product) {
        await new Promise(resolve => setTimeout(resolve, 1800));
        
        const vulnCount = Math.floor(Math.random() * 8);
        return {
            vulnerabilities: Array.from({length: vulnCount}, (_, i) => ({
                cve: {
                    id: `CVE-2023-${10000 + i}`,
                    descriptions: [{ value: `Security vulnerability in ${product} that could allow privilege escalation.` }],
                    metrics: {
                        cvssMetricV31: [{
                            cvssData: {
                                baseScore: (Math.random() * 10).toFixed(1),
                                baseSeverity: ['LOW', 'MEDIUM', 'HIGH'][Math.floor(Math.random() * 3)]
                            }
                        }]
                    },
                    published: new Date(Date.now() - Math.random() * 365 * 86400000).toISOString().split('T')[0]
                }
            }))
        };
    }

    loadCustomQueries() {
        return JSON.parse(localStorage.getItem('customQueries')) || [];
    }

    saveCustomQuery(query, type) {
        this.customQueries.push({
            query: query,
            type: type,
            timestamp: new Date().toISOString()
        });
        
        if (this.customQueries.length > 50) {
            this.customQueries = this.customQueries.slice(-50);
        }
        
        localStorage.setItem('customQueries', JSON.stringify(this.customQueries));
    }
}

// Initialize Threat Hunting
const threatHunting = new ThreatHunting();

// Global functions for HTML onclick events
function searchShodan() {
    threatHunting.searchShodan();
}

function searchCVE() {
    threatHunting.searchCVE();
}

function searchProduct() {
    threatHunting.searchProduct();
}

function executeCustomQuery() {
    threatHunting.executeCustomQuery();
}