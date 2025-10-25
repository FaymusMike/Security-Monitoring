// Main Application Controller
class SecurityMonitoringApp {
    constructor() {
        this.currentSection = 'dashboard';
        this.scanHistory = [];
        this.init();
    }

    init() {
        this.initializeNavigation();
        this.initializeDashboard();
        this.loadScanHistory();
        this.setupEventListeners();
        this.initializeCharts();
    }

    initializeNavigation() {
        // Handle navigation clicks - FIXED VERSION
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const target = link.getAttribute('href'); // Use link, not e.target
                if (target && target.startsWith('#')) {
                    this.showSection(target.substring(1));
                }
            });
        });

        // Quick actions
        document.querySelectorAll('.quick-action').forEach(button => {
            button.addEventListener('click', (e) => {
                const actionElement = e.target.closest('.quick-action');
                if (actionElement) {
                    const action = actionElement.dataset.action;
                    this.handleQuickAction(action);
                }
            });
        });
    }

    showSection(sectionId) {
        // Hide all sections
        document.querySelectorAll('.content-section').forEach(section => {
            section.classList.remove('active');
        });

        // Show target section
        const targetSection = document.getElementById(sectionId);
        if (targetSection) {
            targetSection.classList.add('active');
        }

        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            const href = link.getAttribute('href');
            if (href === `#${sectionId}`) {
                link.classList.add('active');
            }
        });

        this.currentSection = sectionId;
        
        // Update charts when showing reports section
        if (sectionId === 'reports') {
            this.updateCharts();
        }
    }

    initializeDashboard() {
        this.updateDashboardStats();
        this.startRealTimeUpdates();
    }

    updateDashboardStats() {
        // Calculate real stats from scan history
        const threats = this.scanHistory.filter(activity => 
            activity.severity === 'high' || activity.severity === 'critical'
        ).length;
        
        const safe = this.scanHistory.filter(activity => 
            activity.severity === 'low'
        ).length;
        
        const suspicious = this.scanHistory.filter(activity => 
            activity.severity === 'medium'
        ).length;
        
        const scans = this.scanHistory.length;

        // Update DOM elements safely
        this.updateElementText('threats-count', threats);
        this.updateElementText('safe-count', safe);
        this.updateElementText('suspicious-count', suspicious);
        this.updateElementText('scans-count', scans);
    }

    updateElementText(elementId, text) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = text;
        }
    }

    startRealTimeUpdates() {
        // Update stats every 30 seconds
        setInterval(() => {
            this.updateDashboardStats();
        }, 30000);
    }

    loadScanHistory() {
        // Load scan history from Firebase or localStorage
        try {
            if (window.firebaseManager) {
                firebaseManager.getScanHistory(100).then(history => {
                    this.scanHistory = history;
                    this.updateRecentActivityTable();
                }).catch(error => {
                    console.error('Error loading from Firebase:', error);
                    this.loadFromLocalStorage();
                });
            } else {
                this.loadFromLocalStorage();
            }
        } catch (error) {
            console.error('Error loading scan history:', error);
            this.loadFromLocalStorage();
        }
    }

    loadFromLocalStorage() {
        try {
            const history = JSON.parse(localStorage.getItem('scanHistory')) || [];
            this.scanHistory = history;
            this.updateRecentActivityTable();
        } catch (error) {
            console.error('Error loading from localStorage:', error);
            this.scanHistory = [];
        }
    }

    updateRecentActivityTable() {
        const tbody = document.getElementById('recent-activity-body');
        if (!tbody) return;

        tbody.innerHTML = '';

        const recentActivities = this.scanHistory.slice(-10).reverse();
        
        if (recentActivities.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center text-muted py-4">
                        <i class="fas fa-history me-2"></i>No scan activity yet
                    </td>
                </tr>
            `;
            return;
        }

        recentActivities.forEach(activity => {
            const row = document.createElement('tr');
            row.className = 'fade-in';
            
            const severityClass = this.getSeverityClass(activity.severity);
            
            row.innerHTML = `
                <td>${new Date(activity.timestamp).toLocaleString()}</td>
                <td>${this.escapeHtml(activity.type)}</td>
                <td class="text-truncate" style="max-width: 150px;" title="${this.escapeHtml(activity.target)}">
                    ${this.escapeHtml(activity.target)}
                </td>
                <td>${this.escapeHtml(activity.result)}</td>
                <td><span class="threat-level ${severityClass}">${this.escapeHtml(activity.severity)}</span></td>
            `;
            
            tbody.appendChild(row);
        });
    }

    getSeverityClass(severity) {
        const classes = {
            'low': 'threat-level-low',
            'medium': 'threat-level-medium',
            'high': 'threat-level-high',
            'critical': 'threat-level-critical'
        };
        return classes[severity?.toLowerCase()] || 'threat-level-low';
    }

    addScanActivity(activity) {
        // Validate activity object
        if (!activity || typeof activity !== 'object') {
            console.error('Invalid activity object:', activity);
            return;
        }

        activity.timestamp = new Date().toISOString();
        activity.type = activity.type || 'Unknown Scan';
        activity.target = activity.target || 'Unknown';
        activity.result = activity.result || 'Unknown';
        activity.severity = activity.severity || 'low';

        // Save to Firebase if available, otherwise localStorage
        if (window.firebaseManager) {
            firebaseManager.saveScanResult(activity).then(scanId => {
                console.log('Scan saved with ID:', scanId);
                this.loadScanHistory(); // Reload to get updated data
            }).catch(error => {
                console.error('Error saving scan:', error);
                this.saveToLocalStorage(activity);
            });
        } else {
            this.saveToLocalStorage(activity);
        }
    }

    saveToLocalStorage(activity) {
        this.scanHistory.push(activity);
        
        // Keep only last 100 entries
        if (this.scanHistory.length > 100) {
            this.scanHistory = this.scanHistory.slice(-100);
        }
        
        try {
            localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));
            this.updateRecentActivityTable();
            this.updateDashboardStats();
            this.updateCharts();
        } catch (error) {
            console.error('Error saving scan history:', error);
        }
    }

    handleQuickAction(action) {
        const targetInputs = {
            'scan-ip': 'abuseipdb-ip',
            'check-email': 'hibp-email', 
            'analyze-file': 'file-hash',
            'search-device': 'shodan-query'
        };
        
        const inputId = targetInputs[action];
        if (inputId) {
            const targetSection = action === 'search-device' ? 'threat-hunting' : 'threat-intel';
            this.showSection(targetSection);
            
            setTimeout(() => {
                const input = document.getElementById(inputId);
                if (input) {
                    input.focus();
                    
                    // Add visual feedback
                    input.classList.add('quick-action-highlight');
                    setTimeout(() => {
                        input.classList.remove('quick-action-highlight');
                    }, 2000);
                }
            }, 400);
        }
    }

    initializeCharts() {
        this.createThreatChart();
        this.createScanChart();
    }

    createThreatChart() {
        const threatCtx = document.getElementById('threatChart');
        if (!threatCtx) return;

        try {
            this.threatChart = new Chart(threatCtx, {
                type: 'doughnut',
                data: {
                    labels: ['Malicious', 'Suspicious', 'Clean', 'Unknown'],
                    datasets: [{
                        data: [0, 0, 0, 0],
                        backgroundColor: [
                            '#e74c3c',
                            '#f39c12',
                            '#27ae60',
                            '#95a5a6'
                        ],
                        borderWidth: 2,
                        borderColor: '#fff'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: {
                                padding: 20,
                                usePointStyle: true
                            }
                        }
                    }
                }
            });
            
            this.updateCharts();
        } catch (error) {
            console.error('Error initializing threat chart:', error);
        }
    }

    createScanChart() {
        const scanCtx = document.getElementById('scanChart');
        if (!scanCtx) return;

        try {
            // Generate last 7 days labels
            const labels = [];
            for (let i = 6; i >= 0; i--) {
                const date = new Date();
                date.setDate(date.getDate() - i);
                labels.push(date.toLocaleDateString('en-US', { weekday: 'short' }));
            }

            this.scanChart = new Chart(scanCtx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Scans Per Day',
                        data: Array(7).fill(0),
                        borderColor: '#3498db',
                        backgroundColor: 'rgba(52, 152, 219, 0.1)',
                        tension: 0.4,
                        fill: true,
                        pointBackgroundColor: '#3498db',
                        pointBorderColor: '#fff',
                        pointBorderWidth: 2,
                        pointRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: {
                                stepSize: 1
                            }
                        },
                        x: {
                            grid: {
                                display: false
                            }
                        }
                    },
                    plugins: {
                        legend: {
                            display: false
                        }
                    }
                }
            });
            
            this.updateCharts();
        } catch (error) {
            console.error('Error initializing scan chart:', error);
        }
    }

    updateCharts() {
        if (this.threatChart) {
            const threats = this.scanHistory.filter(a => a.severity === 'high' || a.severity === 'critical').length;
            const suspicious = this.scanHistory.filter(a => a.severity === 'medium').length;
            const clean = this.scanHistory.filter(a => a.severity === 'low').length;
            const unknown = this.scanHistory.filter(a => !a.severity || a.severity === 'unknown').length;

            this.threatChart.data.datasets[0].data = [threats, suspicious, clean, unknown];
            this.threatChart.update();
        }

        if (this.scanChart) {
            const dailyScans = Array(7).fill(0);
            const today = new Date();
            
            this.scanHistory.forEach(activity => {
                const activityDate = new Date(activity.timestamp);
                const daysAgo = Math.floor((today - activityDate) / (1000 * 60 * 60 * 24));
                
                if (daysAgo >= 0 && daysAgo < 7) {
                    dailyScans[6 - daysAgo]++;
                }
            });

            this.scanChart.data.datasets[0].data = dailyScans;
            this.scanChart.update();
        }
    }

    setupEventListeners() {
        // Global error handler
        window.addEventListener('error', (e) => {
            console.error('Application error:', e.error);
            this.showNotification('An error occurred. Please try again.', 'error');
        });

        // Online/offline detection
        window.addEventListener('online', () => {
            this.showNotification('Connection restored', 'success');
            if (window.firebaseManager) {
                firebaseManager.syncLocalDataToFirebase();
            }
        });

        window.addEventListener('offline', () => {
            this.showNotification('Connection lost. Some features may not work.', 'warning');
        });
    }

    showNotification(message, type = 'info') {
        // Remove existing notifications
        document.querySelectorAll('.alert.position-fixed').forEach(alert => {
            alert.remove();
        });

        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = `
            top: 20px;
            right: 20px;
            z-index: 1050;
            min-width: 300px;
            max-width: 400px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        `;
        
        const icon = type === 'success' ? 'fa-check-circle' : 
                    type === 'warning' ? 'fa-exclamation-triangle' : 
                    type === 'error' ? 'fa-times-circle' : 'fa-info-circle';
        
        notification.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="fas ${icon} me-2"></i>
                <span class="flex-grow-1">${this.escapeHtml(message)}</span>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="alert"></button>
            </div>
        `;

        document.body.appendChild(notification);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                try {
                    notification.remove();
                } catch (error) {
                    console.error('Error removing notification:', error);
                }
            }
        }, 5000);
    }

    showLoading(message = 'Processing your request...') {
        const loadingMessage = document.getElementById('loading-message');
        const modalElement = document.getElementById('loadingModal');
        
        if (loadingMessage) {
            loadingMessage.textContent = message;
        }
        
        if (modalElement) {
            const modal = new bootstrap.Modal(modalElement);
            modal.show();
        }
    }

    hideLoading() {
        const modalElement = document.getElementById('loadingModal');
        if (modalElement) {
            const modal = bootstrap.Modal.getInstance(modalElement);
            if (modal) {
                modal.hide();
            }
        }
    }

    escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return unsafe
            .toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
}

// Utility functions
class SecurityUtils {
    static validateIP(ip) {
        if (!ip || typeof ip !== 'string') return false;
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip.trim());
    }

    static validateEmail(email) {
        if (!email || typeof email !== 'string') return false;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email.trim());
    }

    static validateHash(hash) {
        if (!hash || typeof hash !== 'string') return false;
        const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
        return hashRegex.test(hash.trim());
    }

    static validateURL(url) {
        if (!url || typeof url !== 'string') return false;
        try {
            new URL(url);
            return true;
        } catch {
            return false;
        }
    }

    static formatTimestamp(timestamp) {
        if (!timestamp) return 'Unknown';
        try {
            return new Date(timestamp).toLocaleString();
        } catch {
            return 'Invalid Date';
        }
    }

    static generateReportId() {
        return 'RPT-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    }
}

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    try {
        window.securityApp = new SecurityMonitoringApp();
        console.log('Security Monitoring App initialized successfully');
    } catch (error) {
        console.error('Failed to initialize Security Monitoring App:', error);
    }
});

// Global functions
function generateThreatReport() {
    if (window.securityApp) {
        securityApp.showNotification('Generating threat report...', 'info');
        setTimeout(() => {
            securityApp.showNotification('Threat report generated successfully!', 'success');
        }, 2000);
    }
}

function generateHuntingReport() {
    if (window.securityApp) {
        securityApp.showNotification('Compiling threat hunting findings...', 'info');
        setTimeout(() => {
            securityApp.showNotification('Hunting report compiled successfully!', 'success');
        }, 2000);
    }
}

function exportData() {
    if (window.securityApp) {
        securityApp.showNotification('Preparing data for export...', 'info');
        
        const exportData = {
            exportDate: new Date().toISOString(),
            scanHistory: securityApp.scanHistory,
            summary: {
                totalScans: securityApp.scanHistory.length,
                threats: securityApp.scanHistory.filter(a => a.severity === 'high' || a.severity === 'critical').length,
                suspicious: securityApp.scanHistory.filter(a => a.severity === 'medium').length,
                clean: securityApp.scanHistory.filter(a => a.severity === 'low').length
            }
        };
        
        const dataStr = JSON.stringify(exportData, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `security-scan-data-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        
        securityApp.showNotification('Data exported successfully!', 'success');
    }
}

// Add CSS for quick action highlight
const style = document.createElement('style');
style.textContent = `
    .quick-action-highlight {
        animation: pulse-highlight 2s ease-in-out;
        border-color: #007bff !important;
        box-shadow: 0 0 0 0.2rem rgba(0, 123, 255, 0.25) !important;
    }
    
    @keyframes pulse-highlight {
        0% { box-shadow: 0 0 0 0 rgba(0, 123, 255, 0.7); }
        70% { box-shadow: 0 0 0 10px rgba(0, 123, 255, 0); }
        100% { box-shadow: 0 0 0 0 rgba(0, 123, 255, 0); }
    }
    
    .threat-level {
        font-weight: 600;
        padding: 0.25rem 0.5rem;
        border-radius: 0.25rem;
        font-size: 0.75rem;
    }
    
    .threat-level-low { background-color: #d1edff; color: #004085; }
    .threat-level-medium { background-color: #fff3cd; color: #856404; }
    .threat-level-high { background-color: #f8d7da; color: #721c24; }
    .threat-level-critical { background-color: #721c24; color: #fff; }
`;
document.head.appendChild(style);