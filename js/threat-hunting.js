// Threat Hunting Module
class ThreatHunting {
    constructor() {
        this.apiEndpoints = {
            shodan: {
                base: 'https://api.shodan.io',
                key: 'UJ6NlmKnrFWlwkLJFBEifVaDeo77w6U6' // Replace with actual key
            },
            census: {
                base: 'https://api.censys.io/api/v1',
                key: 'censys_iDMcXBED_Mw84T9Ufyvh3b28TpZdqX438' // Replace with actual key
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

        securityApp.showLoading('Searching Shodan...');

        try {
            // Simulate API call - replace with actual Shodan API
            const result = await this.simulateShodanSearch(query, filters);
            this.displayShodanResults(result);
            
            securityApp.addScanActivity({
                type: 'Shodan Search',
                target: query,
                result: `Found ${result.total} results`,
                severity: 'low'
            });
            
        } catch (error) {
            console.error('Error searching Shodan:', error);
            securityApp.showNotification('Error searching Shodan', 'error');
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
            // Simulate API call - replace with actual CVE search
            const result = await this.simulateCVESearch(cveId);
            this.displayCVEResults(result);
            
            securityApp.addScanActivity({
                type: 'CVE Search',
                target: cveId,
                result: result.vulnerability ? 'Vulnerability Found' : 'Not Found',
                severity: result.vulnerability ? 'medium' : 'low'
            });
            
        } catch (error) {
            console.error('Error searching CVE:', error);
            securityApp.showNotification('Error searching CVE', 'error');
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

        securityApp.showLoading('Searching product vulnerabilities...');

        try {
            // Simulate API call - replace with actual product search
            const result = await this.simulateProductSearch(product);
            this.displayProductResults(result);
            
            securityApp.addScanActivity({
                type: 'Product Search',
                target: product,
                result: `Found ${result.vulnerabilities.length} vulnerabilities`,
                severity: result.vulnerabilities.length > 0 ? 'medium' : 'low'
            });
            
        } catch (error) {
            console.error('Error searching product:', error);
            securityApp.showNotification('Error searching product', 'error');
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
            // Simulate custom query execution
            const result = await this.simulateCustomQuery(query, queryType);
            this.displayCustomResults(result, queryType);
            
            securityApp.addScanActivity({
                type: `Custom ${queryType.charAt(0).toUpperCase() + queryType.slice(1)} Query`,
                target: query.substring(0, 50) + '...',
                result: `Executed successfully`,
                severity: 'low'
            });
            
            this.saveCustomQuery(query, queryType);
            
        } catch (error) {
            console.error('Error executing custom query:', error);
            securityApp.showNotification('Error executing custom query', 'error');
        } finally {
            securityApp.hideLoading();
        }
    }

    // Simulation methods - Replace with actual API calls
    async simulateShodanSearch(query, filters) {
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        return {
            total: Math.floor(Math.random() * 1000) + 1,
            results: Array.from({length: 5}, (_, i) => ({
                ip: `192.168.1.${i + 1}`,
                port: [80, 443, 22, 3389][i % 4],
                org: `ISP ${i + 1}`,
                location: { country: 'US', city: `City ${i + 1}` },
                data: `HTTP/1.1 200 OK\nServer: Apache\nContent-Type: text/html`
            }))
        };
    }

    async simulateCVESearch(cveId) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        const hasVulnerability = Math.random() > 0.3;
        return {
            vulnerability: hasVulnerability ? {
                id: cveId,
                description: 'A critical vulnerability in example software',
                cvss: (Math.random() * 10).toFixed(1),
                published: '2023-01-15',
                severity: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'][Math.floor(Math.random() * 4)]
            } : null
        };
    }

    async simulateProductSearch(product) {
        await new Promise(resolve => setTimeout(resolve, 1800));
        
        return {
            vulnerabilities: Array.from({length: Math.floor(Math.random() * 5)}, (_, i) => ({
                cve: `CVE-2023-${1000 + i}`,
                description: `Vulnerability in ${product}`,
                severity: ['LOW', 'MEDIUM', 'HIGH'][Math.floor(Math.random() * 3)],
                score: (Math.random() * 10).toFixed(1)
            }))
        };
    }

    async simulateCustomQuery(query, type) {
        await new Promise(resolve => setTimeout(resolve, 1200));
        
        return {
            matches: Array.from({length: Math.floor(Math.random() * 8) + 1}, (_, i) => ({
                id: i + 1,
                timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
                source: `Source ${i + 1}`,
                data: `Match data for query: ${query.substring(0, 30)}...`
            }))
        };
    }

    displayShodanResults(result) {
        const container = document.getElementById('shodan-results');
        
        container.innerHTML = `
            <div class="result-panel result-safe fade-in">
                <h5><i class="fas fa-search me-2"></i>Shodan Search Results</h5>
                <p><strong>Total Results:</strong> ${result.total}</p>
                <p><strong>Query:</strong> ${document.getElementById('shodan-query').value}</p>
                
                <div class="mt-3">
                    <h6>Top Results:</h6>
                    <div class="table-responsive">
                        <table class="table table-sm">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Port</th>
                                    <th>Organization</th>
                                    <th>Location</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${result.results.map(device => `
                                    <tr>
                                        <td><code>${device.ip}</code></td>
                                        <td>${device.port}</td>
                                        <td>${device.org}</td>
                                        <td>${device.location.city}, ${device.location.country}</td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
                
                ${result.total > 5 ? `
                    <div class="alert alert-info mt-2">
                        <i class="fas fa-info-circle me-2"></i>
                        Showing 5 of ${result.total} results. Refine your search for more specific results.
                    </div>
                ` : ''}
            </div>
        `;
    }

    displayCVEResults(result) {
        const container = document.getElementById('census-results');
        
        if (result.vulnerability) {
            const vuln = result.vulnerability;
            const severityClass = this.getCVSSClass(vuln.cvss);
            
            container.innerHTML = `
                <div class="result-panel ${severityClass} fade-in">
                    <h5><i class="fas fa-bug me-2"></i>CVE Vulnerability Details</h5>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>CVE ID:</strong> ${vuln.id}</p>
                            <p><strong>CVSS Score:</strong> 
                                <span class="badge bg-${this.getCVSSColor(vuln.cvss)}">${vuln.cvss}</span>
                            </p>
                            <p><strong>Severity:</strong> ${vuln.severity}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong>Published:</strong> ${vuln.published}</p>
                            <p><strong>Status:</strong> <span class="badge bg-warning">Analyzed</span></p>
                        </div>
                    </div>
                    <div class="mt-2">
                        <strong>Description:</strong>
                        <p class="mb-0">${vuln.description}</p>
                    </div>
                </div>
            `;
        } else {
            container.innerHTML = `
                <div class="result-panel result-safe fade-in">
                    <h5><i class="fas fa-bug me-2"></i>CVE Search Results</h5>
                    <p class="text-success mb-0">
                        <i class="fas fa-check-circle me-2"></i>
                        No vulnerability information found for this CVE ID.
                    </p>
                </div>
            `;
        }
    }

    displayProductResults(result) {
        const container = document.getElementById('census-results');
        
        if (result.vulnerabilities.length > 0) {
            container.innerHTML = `
                <div class="result-panel result-suspicious fade-in">
                    <h5><i class="fas fa-cube me-2"></i>Product Vulnerability Results</h5>
                    <p><strong>Product:</strong> ${document.getElementById('census-product').value}</p>
                    <p><strong>Vulnerabilities Found:</strong> ${result.vulnerabilities.length}</p>
                    
                    <div class="mt-3">
                        <h6>Vulnerability Details:</h6>
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>CVE ID</th>
                                        <th>Severity</th>
                                        <th>CVSS Score</th>
                                        <th>Description</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${result.vulnerabilities.map(vuln => `
                                        <tr>
                                            <td><code>${vuln.cve}</code></td>
                                            <td>
                                                <span class="badge bg-${this.getSeverityColor(vuln.severity)}">
                                                    ${vuln.severity}
                                                </span>
                                            </td>
                                            <td>${vuln.score}</td>
                                            <td>${vuln.description}</td>
                                        </tr>
                                    `).join('')}
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
                    <p class="text-success mb-0">
                        <i class="fas fa-check-circle me-2"></i>
                        No known vulnerabilities found for this product.
                    </p>
                </div>
            `;
        }
    }

    displayCustomResults(result, queryType) {
        const container = document.getElementById('custom-results');
        
        container.innerHTML = `
            <div class="result-panel result-safe fade-in">
                <h5><i class="fas fa-code me-2"></i>Custom Query Results</h5>
                <p><strong>Query Type:</strong> ${queryType.toUpperCase()}</p>
                <p><strong>Matches Found:</strong> ${result.matches.length}</p>
                
                ${result.matches.length > 0 ? `
                    <div class="mt-3">
                        <h6>Query Matches:</h6>
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Timestamp</th>
                                        <th>Source</th>
                                        <th>Data</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${result.matches.map(match => `
                                        <tr>
                                            <td>${match.id}</td>
                                            <td>${new Date(match.timestamp).toLocaleString()}</td>
                                            <td>${match.source}</td>
                                            <td><code>${match.data}</code></td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ` : `
                    <div class="alert alert-info mt-2">
                        <i class="fas fa-info-circle me-2"></i>
                        No matches found for your custom query. Try refining your search criteria.
                    </div>
                `}
            </div>
        `;
    }

    getCVSSClass(score) {
        score = parseFloat(score);
        if (score >= 9.0) return 'result-malicious';
        if (score >= 7.0) return 'result-suspicious';
        if (score >= 4.0) return 'result-warning';
        return 'result-safe';
    }

    getCVSSColor(score) {
        score = parseFloat(score);
        if (score >= 9.0) return 'danger';
        if (score >= 7.0) return 'warning';
        if (score >= 4.0) return 'info';
        return 'success';
    }

    getSeverityColor(severity) {
        const colors = {
            'CRITICAL': 'danger',
            'HIGH': 'danger',
            'MEDIUM': 'warning',
            'LOW': 'info'
        };
        return colors[severity] || 'secondary';
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
        
        // Keep only last 50 queries
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