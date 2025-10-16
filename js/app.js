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
        document.getElementById(sectionId).classList.add('active');

        // Update navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${sectionId}`) {
                link.classList.add('active');
            }
        });

        this.currentSection = sectionId;
    }

    initializeDashboard() {
        this.updateDashboardStats();
        this.startRealTimeUpdates();
    }

    updateDashboardStats() {
        // Simulate real-time data updates
        const threats = Math.floor(Math.random() * 50);
        const safe = Math.floor(Math.random() * 200);
        const suspicious = Math.floor(Math.random() * 20);
        const scans = Math.floor(Math.random() * 100);

        document.getElementById('threats-count').textContent = threats;
        document.getElementById('safe-count').textContent = safe;
        document.getElementById('suspicious-count').textContent = suspicious;
        document.getElementById('scans-count').textContent = scans;
    }

    startRealTimeUpdates() {
        // Update stats every 30 seconds
        setInterval(() => {
            this.updateDashboardStats();
        }, 30000);
    }

    loadScanHistory() {
        // Load scan history from Firebase or localStorage
        const history = JSON.parse(localStorage.getItem('scanHistory')) || [];
        this.scanHistory = history;
        this.updateRecentActivityTable();
    }

    updateRecentActivityTable() {
        const tbody = document.getElementById('recent-activity-body');
        tbody.innerHTML = '';

        this.scanHistory.slice(-10).reverse().forEach(activity => {
            const row = document.createElement('tr');
            row.className = 'fade-in';
            
            const severityClass = this.getSeverityClass(activity.severity);
            
            row.innerHTML = `
                <td>${new Date(activity.timestamp).toLocaleString()}</td>
                <td>${activity.type}</td>
                <td>${activity.target}</td>
                <td>${activity.result}</td>
                <td><span class="threat-level ${severityClass}">${activity.severity}</span></td>
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
        activity.timestamp = new Date().toISOString();
        this.scanHistory.push(activity);
        
        // Keep only last 100 entries
        if (this.scanHistory.length > 100) {
            this.scanHistory = this.scanHistory.slice(-100);
        }
        
        localStorage.setItem('scanHistory', JSON.stringify(this.scanHistory));
        this.updateRecentActivityTable();
        this.updateDashboardStats();
    }

    handleQuickAction(action) {
        switch (action) {
            case 'scan-ip':
                this.showSection('threat-intel');
                setTimeout(() => {
                    document.getElementById('abuseipdb-ip').focus();
                }, 300);
                break;
            case 'check-email':
                this.showSection('threat-intel');
                setTimeout(() => {
                    document.getElementById('hibp-email').focus();
                }, 300);
                break;
            case 'analyze-file':
                this.showSection('threat-intel');
                setTimeout(() => {
                    document.getElementById('file-hash').focus();
                }, 300);
                break;
            case 'search-device':
                this.showSection('threat-hunting');
                setTimeout(() => {
                    document.getElementById('shodan-query').focus();
                }, 300);
                break;
        }
    }

    initializeCharts() {
        // Initialize threat distribution chart
        const threatCtx = document.getElementById('threatChart').getContext('2d');
        this.threatChart = new Chart(threatCtx, {
            type: 'doughnut',
            data: {
                labels: ['Malicious', 'Suspicious', 'Clean', 'Unknown'],
                datasets: [{
                    data: [12, 8, 65, 15],
                    backgroundColor: [
                        '#e74c3c',
                        '#f39c12',
                        '#27ae60',
                        '#95a5a6'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Initialize scan activity chart
        const scanCtx = document.getElementById('scanChart').getContext('2d');
        this.scanChart = new Chart(scanCtx, {
            type: 'line',
            data: {
                labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                datasets: [{
                    label: 'Scans Per Day',
                    data: [65, 59, 80, 81, 56, 55, 40],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
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
    }

    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show position-fixed`;
        notification.style.cssText = `
            top: 20px;
            right: 20px;
            z-index: 1050;
            min-width: 300px;
        `;
        
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        document.body.appendChild(notification);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);
    }

    showLoading(message = 'Processing your request...') {
        document.getElementById('loading-message').textContent = message;
        const modal = new bootstrap.Modal(document.getElementById('loadingModal'));
        modal.show();
    }

    hideLoading() {
        const modal = bootstrap.Modal.getInstance(document.getElementById('loadingModal'));
        if (modal) {
            modal.hide();
        }
    }
}

// Utility functions
class SecurityUtils {
    static validateIP(ip) {
        const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        return ipRegex.test(ip);
    }

    static validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    static validateHash(hash) {
        const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
        return hashRegex.test(hash);
    }

    static formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString();
    }

    static sanitizeInput(input) {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }

    static generateReportId() {
        return 'RPT-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
    }
}

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.securityApp = new SecurityMonitoringApp();
});

// Export functions for global access
function generateThreatReport() {
    securityApp.showNotification('Generating threat report...', 'info');
    // Implementation for generating threat reports
}

function generateHuntingReport() {
    securityApp.showNotification('Generating hunting report...', 'info');
    // Implementation for generating hunting reports
}

function exportData() {
    securityApp.showNotification('Preparing data export...', 'info');
    // Implementation for data export
}