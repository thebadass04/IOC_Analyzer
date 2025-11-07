class IOCAnalyzer {
    constructor() {
        this.initializeEventListeners();
        this.results = [];
    }

    initializeEventListeners() {
        // Main page elements
        const analyzeBtn = document.getElementById('analyze-btn');
        const clearBtn = document.getElementById('clear-btn');
        const exportBtn = document.getElementById('export-btn');
        const toggleKeyBtn = document.getElementById('toggle-key');
        const formatIocsBtn = document.getElementById('format-iocs');

        if (analyzeBtn) {
            analyzeBtn.addEventListener('click', () => this.startAnalysis());
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearInput());
        }

        if (exportBtn) {
            exportBtn.addEventListener('click', () => this.exportResults());
        }

        if (toggleKeyBtn) {
            toggleKeyBtn.addEventListener('click', () => this.toggleApiKey());
        }

        if (formatIocsBtn) {
            formatIocsBtn.addEventListener('click', () => this.formatIOCs());
        }
    }

    formatIOCs() {
        const textarea = document.getElementById('ioc-input');
        const input = textarea.value.trim();
        
        if (!input) {
            this.showAlert('Please enter IOCs to format', 'error');
            return;
        }

        const lines = input.split('\n').filter(line => line.trim());
        const formattedIOCs = [];
        const invalidIOCs = [];

        for (const line of lines) {
            const ioc = line.trim();
            if (!ioc) continue;

            const type = this.detectIOCType(ioc);
            if (type) {
                formattedIOCs.push(`${ioc} (${type.toUpperCase()})`);
            } else {
                invalidIOCs.push(ioc);
            }
        }

        // Update textarea with formatted IOCs
        let formattedText = formattedIOCs.join('\n');
        
        if (invalidIOCs.length > 0) {
            formattedText += '\n\n# Invalid IOCs (will be skipped):\n';
            formattedText += invalidIOCs.map(ioc => `# ${ioc}`).join('\n');
        }

        textarea.value = formattedText;

        // Show summary
        const validCount = formattedIOCs.length;
        const invalidCount = invalidIOCs.length;
        
        if (validCount > 0 && invalidCount === 0) {
            this.showAlert(`Formatted ${validCount} valid IOCs`, 'success');
        } else if (validCount > 0 && invalidCount > 0) {
            this.showAlert(`Formatted ${validCount} valid IOCs, ${invalidCount} invalid IOCs found`, 'warning');
        } else {
            this.showAlert('No valid IOCs found', 'error');
        }
    }

    parseIOCs(input) {
        const lines = input.split('\n').filter(line => line.trim() && !line.trim().startsWith('#'));
        const iocs = [];

        for (const line of lines) {
            const ioc = line.trim().split(' ')[0]; // Take only the IOC part, ignore type annotation
            if (!ioc) continue;

            const type = this.detectIOCType(ioc);
            if (type) {
                iocs.push({ value: ioc, type: type });
            }
        }

        return iocs;
    }

    detectIOCType(ioc) {
        // Hash detection (MD5, SHA1, SHA256)
        if (/^[a-fA-F0-9]{32}$/.test(ioc)) return 'hash';
        if (/^[a-fA-F0-9]{40}$/.test(ioc)) return 'hash';
        if (/^[a-fA-F0-9]{64}$/.test(ioc)) return 'hash';
        
        // URL detection
        if (/^https?:\/\//.test(ioc)) return 'url';
        
        // IP detection
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ioc)) return 'ip';
        
        // Domain detection
        if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(ioc)) return 'domain';
        
        return null;
    }

    async startAnalysis() {
        const input = document.getElementById('ioc-input').value.trim();
        if (!input) {
            this.showAlert('Please enter IOCs to analyze', 'error');
            return;
        }

        const iocs = this.parseIOCs(input);
        if (iocs.length === 0) {
            this.showAlert('No valid IOCs found in input', 'error');
            return;
        }

        this.showProgress(true);
        this.updateProgress(0, `Preparing to analyze ${iocs.length} IOCs...`);

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ iocs: iocs })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Analysis failed');
            }

            const data = await response.json();
            console.log('Analysis results:', data.results); // Debug output
            this.results = data.results;
            this.displayResults();
            this.showAlert(`Analysis completed! Results saved to ${data.saved_to}`, 'success');

        } catch (error) {
            this.showAlert(`Error: ${error.message}`, 'error');
        } finally {
            this.showProgress(false);
        }
    }

    showProgress(show) {
        const progressSection = document.getElementById('progress-section');
        if (progressSection) {
            progressSection.style.display = show ? 'block' : 'none';
        }
    }

    updateProgress(percent, text) {
        const progressFill = document.getElementById('progress-fill');
        const progressText = document.getElementById('progress-text');
        
        if (progressFill) {
            progressFill.style.width = `${percent}%`;
        }
        
        if (progressText) {
            progressText.textContent = text;
        }
    }

    displayResults() {
        const resultsSection = document.getElementById('results-section');
        const summaryDiv = document.getElementById('results-summary');
        const tableDiv = document.getElementById('results-table');

        if (!resultsSection || !summaryDiv || !tableDiv) return;

        // Calculate summary statistics
        const stats = this.calculateStats();
        
        // Display summary
        summaryDiv.innerHTML = `
            <div class="summary-card">
                <h3>${stats.total}</h3>
                <p>Total IOCs</p>
            </div>
            <div class="summary-card">
                <h3>${stats.clean}</h3>
                <p>Clean</p>
            </div>
            <div class="summary-card">
                <h3>${stats.malicious}</h3>
                <p>Malicious</p>
            </div>
            <div class="summary-card">
                <h3>${stats.suspicious}</h3>
                <p>Suspicious</p>
            </div>
        `;

        // Display results table
        tableDiv.innerHTML = this.generateResultsTable();
        
        resultsSection.style.display = 'block';
    }

    calculateStats() {
        const stats = {
            total: this.results.length,
            clean: 0,
            malicious: 0,
            suspicious: 0,
            unknown: 0
        };

        this.results.forEach(result => {
            console.log('Processing result:', result); // Debug output
            
            if (result.error) {
                stats.unknown++;
                return;
            }

            const positives = result.positives || 0;
            const total = result.total || 0;

            if (positives === 0) {
                stats.clean++;
            } else if (positives > 0 && positives < 3) {
                stats.suspicious++;
            } else {
                stats.malicious++;
            }
        });

        console.log('Calculated stats:', stats); // Debug output
        return stats;
    }

    generateResultsTable() {
        let html = `
            <table>
                <thead>
                    <tr>
                        <th>IOC</th>
                        <th>Type</th>
                        <th>Status</th>
                        <th>Detections</th>
                        <th>Scan Date</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
        `;

        this.results.forEach(result => {
            console.log('Generating table row for:', result); // Debug output
            
            const status = this.getStatus(result);
            const detections = result.error ? 'N/A' : `${result.positives || 0}/${result.total || 0}`;
            const scanDate = result.scan_date || 'N/A';
            
            html += `
                <tr>
                    <td><code>${result.ioc}</code></td>
                    <td>${result.type.toUpperCase()}</td>
                    <td><span class="status-badge status-${status.class}">${status.text}</span></td>
                    <td>${detections}</td>
                    <td>${scanDate}</td>
                    <td>
                        ${result.permalink ? `<a href="${result.permalink}" target="_blank">View Report</a>` : 'N/A'}
                    </td>
                </tr>
            `;
        });

        html += '</tbody></table>';
        return html;
    }

    getStatus(result) {
        if (result.error) {
            return { class: 'unknown', text: 'Error' };
        }

        const positives = result.positives || 0;
        
        if (positives === 0) {
            return { class: 'clean', text: 'Clean' };
        } else if (positives < 3) {
            return { class: 'suspicious', text: 'Suspicious' };
        } else {
            return { class: 'malicious', text: 'Malicious' };
        }
    }

    clearInput() {
        const input = document.getElementById('ioc-input');
        if (input) {
            input.value = '';
        }
        
        const resultsSection = document.getElementById('results-section');
        if (resultsSection) {
            resultsSection.style.display = 'none';
        }
        
        this.results = [];
    }

    exportResults() {
        if (this.results.length === 0) {
            this.showAlert('No results to export', 'error');
            return;
        }

        const dataStr = JSON.stringify(this.results, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        
        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = `ioc_analysis_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.json`;
        link.click();
    }

    toggleApiKey() {
        const input = document.getElementById('api_key');
        const icon = document.querySelector('#toggle-key i');
        
        if (input && icon) {
            if (input.type === 'password') {
                input.type = 'text';
                icon.className = 'fas fa-eye-slash';
            } else {
                input.type = 'password';
                icon.className = 'fas fa-eye';
            }
        }
    }

    showAlert(message, type) {
        // Create alert element
        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        
        let iconClass = 'exclamation-triangle';
        if (type === 'success') iconClass = 'check-circle';
        else if (type === 'warning') iconClass = 'exclamation-triangle';
        else if (type === 'error') iconClass = 'times-circle';
        
        alert.innerHTML = `
            <i class="fas fa-${iconClass}"></i>
            ${message}
        `;

        // Insert at top of main content
        const mainContent = document.querySelector('.main-content');
        if (mainContent) {
            mainContent.insertBefore(alert, mainContent.firstChild);

            // Remove after 5 seconds
            setTimeout(() => {
                alert.remove();
            }, 5000);
        }
    }
}

// Log Viewer Functions
function openLogModal() {
    const modal = document.getElementById('log-modal');
    modal.style.display = 'block';
    loadLogs();
}

function closeLogModal() {
    const modal = document.getElementById('log-modal');
    modal.style.display = 'none';
}

async function loadLogs() {
    const logViewer = document.getElementById('log-viewer');
    const logCount = document.getElementById('log-count');

    try {
        logViewer.innerHTML = '<div class="log-loading"><i class="fas fa-spinner fa-spin"></i> Loading logs...</div>';

        const response = await fetch('/logs');
        const data = await response.json();

        if (data.error) {
            logViewer.innerHTML = `<div class="log-error"><i class="fas fa-exclamation-triangle"></i> Error loading logs: ${data.error}</div>`;
            return;
        }

        if (!data.logs || data.logs.length === 0) {
            logViewer.innerHTML = '<div class="log-empty"><i class="fas fa-info-circle"></i> No logs available yet</div>';
            logCount.textContent = 'No logs';
            return;
        }

        // Display logs
        const logsHtml = data.logs.map(line => {
            // Parse log level for styling
            let logClass = 'log-line';
            if (line.includes('| ERROR')) {
                logClass += ' log-error-line';
            } else if (line.includes('| WARNING')) {
                logClass += ' log-warning-line';
            } else if (line.includes('| INFO')) {
                logClass += ' log-info-line';
            } else if (line.includes('| DEBUG')) {
                logClass += ' log-debug-line';
            }

            return `<div class="${logClass}">${escapeHtml(line)}</div>`;
        }).join('');

        logViewer.innerHTML = logsHtml;
        logCount.textContent = `Showing ${data.logs.length} of ${data.total_lines} log entries`;

        // Auto-scroll to bottom
        logViewer.scrollTop = logViewer.scrollHeight;

    } catch (error) {
        logViewer.innerHTML = `<div class="log-error"><i class="fas fa-exclamation-triangle"></i> Error loading logs: ${error.message}</div>`;
        console.error('Error loading logs:', error);
    }
}

function clearLogsDisplay() {
    const logViewer = document.getElementById('log-viewer');
    logViewer.innerHTML = '<div class="log-empty"><i class="fas fa-info-circle"></i> Display cleared. Click Refresh to reload logs.</div>';
    document.getElementById('log-count').textContent = 'Display cleared';
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('log-modal');
    if (event.target === modal) {
        closeLogModal();
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    new IOCAnalyzer();

    // Add log viewer event listeners
    const viewLogsBtn = document.getElementById('view-logs-btn');
    const refreshLogsBtn = document.getElementById('refresh-logs-btn');
    const clearLogsDisplayBtn = document.getElementById('clear-logs-display-btn');

    if (viewLogsBtn) {
        viewLogsBtn.addEventListener('click', openLogModal);
    }

    if (refreshLogsBtn) {
        refreshLogsBtn.addEventListener('click', loadLogs);
    }

    if (clearLogsDisplayBtn) {
        clearLogsDisplayBtn.addEventListener('click', clearLogsDisplay);
    }
});