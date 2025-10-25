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
        // Handle navigation clicks
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => {
                e.preventDefault();
                const target = e.target.getAttribute('href').substring(1);
                this.showSection(target);
            });
        });

        // Quick actions
        document.querySelectorAll('.quick-action').forEach(button => {
            button.addEventListener('click', (e) => {
                const action = e.target.closest('.quick-action').dataset.action;
                this.handleQuickAction(action);
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
            if (link.getAttribute('href') === `#${sectionId}`) {
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
            const history = JSON.parse(localStorage.getItem('scanHistory')) || [];
            this.scanHistory = history;
            this.updateRecentActivityTable();
        } catch (error) {
            console.error('Error loading scan history:', error);
            this.scanHistory = [];
            localStorage.setItem('scanHistory', JSON.stringify([]));
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
        return classes[severity.toLowerCase()] || 'threat-level-low';
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
                        data: [0, 0, 0, 0], // Start with zeros
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
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = total > 0 ? Math.round((value / total) * 100) : 0;
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            }
                        }
                    },
                    animation: {
                        animateScale: true,
                        animateRotate: true
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
                            },
                            grid: {
                                color: 'rgba(0, 0, 0, 0.1)'
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
            // Calculate threat distribution from scan history
            const threats = this.scanHistory.filter(a => a.severity === 'high' || a.severity === 'critical').length;
            const suspicious = this.scanHistory.filter(a => a.severity === 'medium').length;
            const clean = this.scanHistory.filter(a => a.severity === 'low').length;
            const unknown = this.scanHistory.filter(a => !a.severity || a.severity === 'unknown').length;

            this.threatChart.data.datasets[0].data = [threats, suspicious, clean, unknown];
            this.threatChart.update();
        }

        if (this.scanChart) {
            // Calculate scans per day for last 7 days
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
        });

        window.addEventListener('offline', () => {
            this.showNotification('Connection lost. Some features may not work.', 'warning');
        });

        // Handle page visibility changes
        document.addEventListener('visibilitychange', () => {
            if (!document.hidden) {
                this.updateDashboardStats();
            }
        });

        // Handle beforeunload to save data
        window.addEventListener('beforeunload', () => {
            this.saveAppState();
        });
    }

    saveAppState() {
        try {
            const appState = {
                currentSection: this.currentSection,
                lastUpdated: new Date().toISOString()
            };
            localStorage.setItem('securityAppState', JSON.stringify(appState));
        } catch (error) {
            console.error('Error saving app state:', error);
        }
    }

    loadAppState() {
        try {
            const savedState = localStorage.getItem('securityAppState');
            if (savedState) {
                const state = JSON.parse(savedState);
                if (state.currentSection) {
                    this.showSection(state.currentSection);
                }
            }
        } catch (error) {
            console.error('Error loading app state:', error);
        }
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

    // Utility method to clear all data
    clearAllData() {
        if (confirm('Are you sure you want to clear all scan history and data? This action cannot be undone.')) {
            this.scanHistory = [];
            localStorage.setItem('scanHistory', JSON.stringify([]));
            this.updateRecentActivityTable();
            this.updateDashboardStats();
            this.updateCharts();
            this.showNotification('All data cleared successfully', 'success');
        }
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

    static sanitizeInput(input) {
        if (input === null || input === undefined) return '';
        const div = document.createElement('div');
        div.textContent = input.toString();
        return div.innerHTML;
    }

    static generateReportId() {
        return 'RPT-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    }

    static formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
}

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    try {
        window.securityApp = new SecurityMonitoringApp();
        console.log('Security Monitoring App initialized successfully');
    } catch (error) {
        console.error('Failed to initialize Security Monitoring App:', error);
        // Show error message to user
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger m-3';
        errorDiv.innerHTML = `
            <h4><i class="fas fa-exclamation-triangle me-2"></i>Application Error</h4>
            <p>Failed to initialize the Security Monitoring Tool. Please refresh the page.</p>
            <button class="btn btn-sm btn-outline-danger" onclick="window.location.reload()">
                <i class="fas fa-redo me-1"></i>Reload Page
            </button>
        `;
        document.body.prepend(errorDiv);
    }
});

// Global functions for HTML onclick events
function generateThreatReport() {
    if (window.securityApp) {
        securityApp.showNotification('Generating comprehensive threat report...', 'info');
        // Simulate report generation
        setTimeout(() => {
            securityApp.showNotification('Threat report generated successfully!', 'success');
        }, 2000);
    }
}

function generateHuntingReport() {
    if (window.securityApp) {
        securityApp.showNotification('Compiling threat hunting findings...', 'info');
        // Simulate report generation
        setTimeout(() => {
            securityApp.showNotification('Hunting report compiled successfully!', 'success');
        }, 2000);
    }
}

function exportData() {
    if (window.securityApp) {
        securityApp.showNotification('Preparing data for export...', 'info');
        
        // Create export data
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
        
        // Create and trigger download
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