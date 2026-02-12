// RansomGuard Email Shield - Dashboard JavaScript

let isConnected = false;
let isScanning = false;

// API Base URL
const API_BASE = window.location.origin;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    console.log('RansomGuard Email Shield Dashboard Loaded');
    updateStats();
    
    // Auto-refresh stats every 10 seconds
    setInterval(updateStats, 10000);
});

// Connect to email server
async function connectEmail() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const imapServer = document.getElementById('imap-server').value || 'imap.gmail.com';
    
    if (!email || !password) {
        showNotification('Please enter email and password', 'error');
        return;
    }
    
    const connectBtn = document.getElementById('connect-btn');
    connectBtn.disabled = true;
    connectBtn.textContent = '🔄 Connecting...';
    
    try {
        const response = await fetch(`${API_BASE}/api/connect`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email: email,
                password: password,
                imap_server: imapServer
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            isConnected = true;
            updateConnectionStatus(true, email);
            showNotification(data.message, 'success');
            
            // Enable scan button
            document.getElementById('scan-btn').disabled = false;
            document.getElementById('disconnect-btn').disabled = false;
        } else {
            isConnected = false;
            updateConnectionStatus(false);
            showNotification(data.message || 'Connection failed', 'error');
        }
    } catch (error) {
        console.error('Connection error:', error);
        showNotification('Network error: ' + error.message, 'error');
        updateConnectionStatus(false);
    } finally {
        connectBtn.disabled = false;
        connectBtn.textContent = '🔌 Connect';
    }
}

// Disconnect from email server
async function disconnectEmail() {
    try {
        const response = await fetch(`${API_BASE}/api/disconnect`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            isConnected = false;
            updateConnectionStatus(false);
            showNotification('Disconnected from email server', 'info');
            
            document.getElementById('scan-btn').disabled = true;
            document.getElementById('disconnect-btn').disabled = true;
        }
    } catch (error) {
        console.error('Disconnect error:', error);
        showNotification('Error disconnecting: ' + error.message, 'error');
    }
}

// Update connection status indicator
function updateConnectionStatus(connected, email = null) {
    const statusBadge = document.getElementById('connection-status');
    
    if (connected) {
        statusBadge.className = 'status-badge connected';
        statusBadge.innerHTML = `
            <span class="status-dot"></span>
            <span class="status-text">Connected${email ? ' - ' + email : ''}</span>
        `;
    } else {
        statusBadge.className = 'status-badge disconnected';
        statusBadge.innerHTML = `
            <span class="status-dot"></span>
            <span class="status-text">Disconnected</span>
        `;
    }
}

// Scan emails for ransomware
async function scanEmails() {
    if (!isConnected) {
        showNotification('Please connect to email server first', 'error');
        return;
    }
    
    if (isScanning) {
        showNotification('Scan already in progress', 'warning');
        return;
    }
    
    isScanning = true;
    const scanBtn = document.getElementById('scan-btn');
    scanBtn.disabled = true;
    scanBtn.textContent = '🔄 Scanning...';
    
    // Show loading indicator
    document.getElementById('loading-indicator').style.display = 'block';
    
    try {
        const response = await fetch(`${API_BASE}/api/scan`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            displayResults(data.results);
            updateStats();
            
            if (data.results.length === 0) {
                showNotification('No unread emails with attachments found', 'info');
            } else {
                showNotification(`Scanned ${data.results.length} attachment(s)`, 'success');
            }
        } else {
            showNotification(data.message || 'Scan failed', 'error');
        }
    } catch (error) {
        console.error('Scan error:', error);
        showNotification('Network error: ' + error.message, 'error');
    } finally {
        isScanning = false;
        scanBtn.disabled = false;
        scanBtn.textContent = '🔍 Scan Emails';
        document.getElementById('loading-indicator').style.display = 'none';
    }
}

// Display scan results
function displayResults(results) {
    const container = document.getElementById('results-container');
    
    if (!results || results.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✅</div>
                <p>No threats detected</p>
                <p class="empty-subtitle">All scanned attachments appear safe</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = '';
    
    results.forEach(result => {
        const resultItem = createResultItem(result);
        container.appendChild(resultItem);
    });
}

// Create result item HTML element
function createResultItem(result) {
    const div = document.createElement('div');
    const action = result.decision.action.toLowerCase();
    div.className = `result-item ${action}`;
    
    const riskScore = result.decision.risk_score || 0;
    const riskClass = riskScore >= 0.7 ? 'risk-high' : (riskScore >= 0.5 ? 'risk-medium' : 'risk-low');
    
    div.innerHTML = `
        <div class="result-header">
            <div class="result-filename">📎 ${escapeHtml(result.attachment_name)}</div>
            <div class="action-badge ${action}">${result.decision.action}</div>
        </div>
        
        <div class="result-details">
            <div class="detail-item">
                <span class="detail-label">Email From</span>
                <span class="detail-value">${escapeHtml(result.email_from)}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Subject</span>
                <span class="detail-value">${escapeHtml(result.email_subject)}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">File Size</span>
                <span class="detail-value">${formatBytes(result.attachment_size)}</span>
            </div>
            <div class="detail-item">
                <span class="detail-label">Risk Score</span>
                <span class="detail-value">
                    <span class="risk-score ${riskClass}">${(riskScore * 100).toFixed(1)}%</span>
                </span>
            </div>
        </div>
        
        <div style="padding: 15px; background: rgba(0,0,0,0.02); border-radius: 8px; margin-top: 10px;">
            <strong>Analysis Result:</strong> ${escapeHtml(result.decision.reason)}
        </div>
        
        ${result.threat_details ? createThreatDetails(result.threat_details) : ''}
    `;
    
    return div;
}

// Create threat details section
function createThreatDetails(details) {
    return `
        <div class="threat-indicators">
            <h4>Threat Indicators</h4>
            <div class="indicator-grid">
                <div class="indicator">
                    <div class="indicator-label">Entropy</div>
                    <div class="indicator-value">${details.entropy.toFixed(2)}</div>
                </div>
                <div class="indicator">
                    <div class="indicator-label">Packed</div>
                    <div class="indicator-value">${details.is_packed ? 'Yes ⚠️' : 'No ✓'}</div>
                </div>
                <div class="indicator">
                    <div class="indicator-label">Suspicious APIs</div>
                    <div class="indicator-value">${details.suspicious_apis}</div>
                </div>
                <div class="indicator">
                    <div class="indicator-label">ML Confidence</div>
                    <div class="indicator-value">${(details.ml_confidence * 100).toFixed(1)}%</div>
                </div>
            </div>
        </div>
    `;
}

// Update statistics
async function updateStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats`);
        const data = await response.json();
        
        if (response.ok && data.status === 'success') {
            const stats = data.statistics;
            
            document.getElementById('total-scanned').textContent = stats.total_analyzed;
            document.getElementById('blocked').textContent = stats.blocked;
            document.getElementById('quarantined').textContent = stats.quarantined;
            document.getElementById('allowed').textContent = stats.allowed;
        }
    } catch (error) {
        console.error('Error updating stats:', error);
    }
}

// Export decisions
async function exportDecisions() {
    try {
        window.location.href = `${API_BASE}/api/export-decisions`;
        showNotification('Exporting decisions...', 'info');
    } catch (error) {
        console.error('Export error:', error);
        showNotification('Error exporting decisions', 'error');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: ${type === 'success' ? '#10b981' : type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : '#3b82f6'};
        color: white;
        border-radius: 8px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.3);
        z-index: 1000;
        animation: slideIn 0.3s ease-out;
        max-width: 400px;
        font-weight: 500;
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 4000);
}

// Utility functions
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(400px);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOut {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(400px);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);
