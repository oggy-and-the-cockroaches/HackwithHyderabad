/* Shipcheck Frontend JavaScript */

const API_BASE = '/api';

// State
let currentProjectId = null;
let currentScanId = null;
let scanInterval = null;

// Elements - will be initialized after DOM loads
let sections = {};

// DOM helpers
function $(id) {
    return document.getElementById(id);
}

function showSection(sectionName) {
    console.log('showSection called:', sectionName);
    const keyToFind = sectionName.endsWith('Section') ? sectionName : sectionName + 'Section';
    const section = sections[keyToFind];
    if (!section) {
        console.error('Section not found:', sectionName, 'Available:', Object.keys(sections));
        return;
    }
    Object.keys(sections).forEach(key => {
        if (key === keyToFind) {
            sections[key].classList.add('active');
            sections[key].style.display = 'block';
        } else {
            sections[key].classList.remove('active');
            sections[key].style.display = 'none';
        }
    });
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOMContentLoaded fired');
    // Initialize sections after DOM is ready
    sections = {
        projectSection: document.getElementById('project-section'),
        scanSection: document.getElementById('scan-section'),
        reportSection: document.getElementById('report-section')
    };
    console.log('Sections initialized:', Object.keys(sections));

    const rescanBtn = $('rescan-btn');
    if (rescanBtn) {
        rescanBtn.addEventListener('click', function() {
            if (currentProjectId) {
                startScan(currentProjectId);
            } else {
                showSection('projectSection');
            }
        });
    }

    const downloadBtn = $('download-btn');
    if (downloadBtn) {
        downloadBtn.addEventListener('click', downloadReport);
    }

    loadProjects();
    setupUpload();
    checkHindsightStatus();
});

// Check Hindsight Engine status
async function checkHindsightStatus() {
    const badgeText = $('hindsight-status-text');
    const badge = $('hindsight-status-badge');
    if (!badgeText || !badge) return;

    try {
        const response = await fetch(`${API_BASE}/hindsight/status`);
        const status = await response.json();
        if (status.connected) {
            badgeText.textContent = `🧠 Hindsight Cloud Active (${status.bank_id})`;
            badge.style.background = '#ecfdf5';
            badge.style.color = '#047857';
            badge.style.borderColor = '#a7f3d0';
            badge.querySelector('.status-dot').style.background = '#10b981';
        } else if (status.api_configured) {
            badgeText.textContent = '🧠 Hindsight Configured (Offline Fallback)';
            badge.style.background = '#fef3c7';
            badge.style.color = '#b45309';
            badge.style.borderColor = '#fde68a';
            badge.querySelector('.status-dot').style.background = '#f59e0b';
        } else {
            badgeText.textContent = '🧠 Hindsight Local SQLite Engine';
        }
    } catch (e) {
        console.warn('Failed to fetch Hindsight status:', e);
    }
}

// Load projects
async function loadProjects() {
    const container = $('projects-list');
    container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading projects...</div>';

    try {
        const response = await fetch(`${API_BASE}/projects`);
        const projects = await response.json();

        if (projects.length === 0) {
            container.innerHTML = '<div class="empty-state">No projects yet. Upload your first project below.</div>';
        } else {
            container.innerHTML = projects.map(p => `
                <div class="project-item" onclick="selectProject('${p.id}')">
                    <div class="project-info">
                        <div class="project-name">${p.name}</div>
                        <div class="project-meta">${new Date(p.created_at).toLocaleString()}</div>
                        ${renderTechBadges(p.project_context)}
                    </div>
                    <div class="project-actions">
                        <button class="btn btn-sm btn-primary" onclick="startScan('${p.id}'); event.stopPropagation()">Scan Now</button>
                    </div>
                </div>
            `).join('');
        }
    } catch (error) {
        container.innerHTML = `<div class="loading" style="color: var(--danger);">Failed to load projects: ${error.message}</div>`;
    }
}

function renderTechBadges(context) {
    if (!context) return '';
    const techs = [
        ...(context.languages || []),
        ...(context.frameworks || []),
        ...(context.databases || []),
        ...(context.deployment || [])
    ];
    if (techs.length === 0) return '';
    return `<div class="project-tech">${techs.slice(0, 5).map(t => `<span class="tech-badge">${t}</span>`).join('')}${techs.length > 5 ? `<span class="tech-badge">+${techs.length - 5}</span>` : ''}</div>`;
}

// Upload setup
function setupUpload() {
    const uploadArea = $('upload-area');
    const fileInput = $('zip-upload');

    uploadArea.addEventListener('click', () => fileInput.click());

    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('drag-over');
    });

    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('drag-over');
    });

    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        if (e.dataTransfer.files.length > 0) {
            handleFileUpload(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileUpload(e.target.files[0]);
        }
    });
}

async function handleFileUpload(file) {
    if (!file.name.endsWith('.zip')) {
        alert('Please upload a ZIP file.');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    // Create project first
    const projectName = file.name.replace('.zip', '');
    showSection('scanSection');
    updateScanProgress('Creating project...', 0);

    try {
        const createResp = await fetch(`${API_BASE}/projects`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name: projectName })
        });
        const project = await createResp.json();
        currentProjectId = project.id;

        updateScanProgress('Uploading project...', 10);

        // Upload ZIP
        const uploadResp = await fetch(`${API_BASE}/projects/${project.id}/upload`, {
            method: 'POST',
            body: formData
        });
        const uploadResult = await uploadResp.json();
        currentProjectId = uploadResult.project_id;

        updateScanProgress('Project uploaded! Starting scan...', 15);
        await startScan(currentProjectId);

    } catch (error) {
        console.error('Upload error:', error);
        updateScanProgress(`Error: ${error.message}`, 'failed');
    }
}

// Start scan
async function startScan(projectId) {
    currentProjectId = projectId;
    $('scan-status-badge').textContent = 'Queued';
    $('scan-status-badge').className = 'scan-status-badge queued';

    try {
        const response = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ project_id: projectId })
        });
        const scan = await response.json();
        currentScanId = scan.id;

        showSection('scanSection');
        $('scan-status-badge').textContent = 'Queued';
        $('scan-status-badge').className = 'scan-status-badge queued';

        // Start polling
        scanInterval = setInterval(() => pollScanStatus(), 1500);

    } catch (error) {
        console.error('Scan start error:', error);
        updateScanProgress(`Error: ${error.message}`, 'failed');
    }
}

// Poll scan status
async function pollScanStatus() {
    if (!currentScanId) return;

    try {
        const response = await fetch(`${API_BASE}/scans/${currentScanId}/status`);
        const status = await response.json();

        $('scan-status-badge').textContent = status.status.charAt(0).toUpperCase() + status.status.slice(1);
        $('scan-status-badge').className = `scan-status-badge ${status.status}`;

        if (status.progress !== undefined) {
            $('progress-fill').style.width = `${status.progress}%`;
        }

        if (status.message) {
            $('progress-message').textContent = status.message;
        }

        // Update steps
        updateScanSteps(status.progress);

        if (status.status === 'completed' || status.status === 'failed') {
            clearInterval(scanInterval);
            if (status.status === 'completed') {
                setTimeout(() => loadReport(), 500);
            } else {
                updateScanProgress(status.error || 'Scan failed', 'failed');
            }
        }
    } catch (error) {
        console.error('Status poll error:', error);
    }
}

function updateScanProgress(message, progress) {
    $('progress-message').textContent = message;
    if (typeof progress === 'number') {
        $('progress-fill').style.width = `${progress}%`;
    } else if (progress === 'failed') {
        $('scan-status-badge').textContent = 'Failed';
        $('scan-status-badge').className = 'scan-status-badge failed';
    }
}

function updateScanSteps(progress) {
    const steps = document.querySelectorAll('.step');
    steps.forEach((step, index) => {
        step.classList.remove('active', 'completed');
        const stepProgress = ((index + 1) / 10) * 100;
        if (progress >= stepProgress) {
            step.classList.add('completed');
        } else if (progress > 0) {
            step.classList.add('active');
        }
    });
}

// Load report
async function loadReport() {
    try {
        // Load scan report
        const reportResp = await fetch(`${API_BASE}/reports/scan/${currentScanId}`);
        const report = await reportResp.json();

        // Load comparison
        let comparison = null;
        try {
            const compResp = await fetch(`${API_BASE}/reports/scan/${currentScanId}/comparison`);
            comparison = await compResp.json();
        } catch (e) {
            // No previous scan
        }

        showSection('reportSection');

        // Set project name
        const projectResp = await fetch(`${API_BASE}/projects/${report.scan.project_id}`);
        const project = await projectResp.json();
        $('report-project-name').textContent = project.name;

        // Render summary
        renderSummary(report.scan.summary);

        // Render comparison
        if (comparison && comparison.previous_scan_id) {
            renderComparison(comparison);
        }

        // Render AI analysis
        if (report.ai_analysis && report.ai_analysis.summary) {
            renderAIAnalysis(report.ai_analysis);
        }

        // Render findings
        renderFindings(report.findings);

        // Update scan status badge
        $('scan-status-badge').textContent = 'Completed';
        $('scan-status-badge').className = 'scan-status-badge completed';

    } catch (error) {
        console.error('Report load error:', error);
    }
}

function renderSummary(summary) {
    const container = $('summary-grid');
    const bySeverity = summary.by_severity || {};
    const totalCount = summary.total_findings || 0;

    container.innerHTML = `
        <div class="summary-card total">
            <div class="summary-count">${totalCount}</div>
            <div class="summary-label">Total Findings</div>
        </div>
        <div class="summary-card critical">
            <div class="summary-count">${bySeverity.critical || 0}</div>
            <div class="summary-label">Critical</div>
        </div>
        <div class="summary-card high">
            <div class="summary-count">${bySeverity.high || 0}</div>
            <div class="summary-label">High</div>
        </div>
        <div class="summary-card medium">
            <div class="summary-count">${bySeverity.medium || 0}</div>
            <div class="summary-label">Medium</div>
        </div>
        <div class="summary-card low">
            <div class="summary-count">${bySeverity.low || 0}</div>
            <div class="summary-label">Low</div>
        </div>
        <div class="summary-card info">
            <div class="summary-count">${bySeverity.info || 0}</div>
            <div class="summary-label">Info</div>
        </div>
    `;
}

function renderComparison(comparison) {
    const card = $('comparison-card');
    card.style.display = 'block';

    const container = $('comparison-details');

    const totalFixed = comparison.fixed_count || 0;
    const totalUnresolved = comparison.unresolved_count || 0;
    const totalNew = comparison.new_count || 0;
    const totalReintroduced = comparison.reintroduced_count || 0;

    const container_inner = document.createElement('div');
    container_inner.className = 'comparison-summary';
    container_inner.innerHTML = `
        <div class="comparison-item fixed">
            <div class="comparison-count">${totalFixed}</div>
            <div class="comparison-label">Fixed</div>
        </div>
        <div class="comparison-item unresolved">
            <div class="comparison-count">${totalUnresolved}</div>
            <div class="comparison-label">Unresolved</div>
        </div>
        <div class="comparison-item new">
            <div class="comparison-count">${totalNew}</div>
            <div class="comparison-label">New</div>
        </div>
        <div class="comparison-item reintroduced">
            <div class="comparison-count">${totalReintroduced}</div>
            <div class="comparison-label">Reintroduced</div>
        </div>
    `;
    container.innerHTML = '';
    container.appendChild(container_inner);

    // Add finding details
    const detailsHtml = [];
    if (totalFixed > 0) {
        detailsHtml.push(`
            <div class="comparison-section fixed">
                <h4>Fixed (${totalFixed})</h4>
                <div class="comparison-findings">
                    ${(comparison.fixed_findings || []).map(f => `
                        <div class="comparison-finding">
                            <span>${f.title}</span>
                            <span class="badge ${f.severity}">${f.severity}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `);
    }
    if (totalUnresolved > 0) {
        detailsHtml.push(`
            <div class="comparison-section unresolved">
                <h4>Still Unresolved (${totalUnresolved})</h4>
                <div class="comparison-findings">
                    ${(comparison.unresolved_findings || []).map(f => `
                        <div class="comparison-finding">
                            <span>${f.title}</span>
                            <span class="badge ${f.severity}">${f.severity}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `);
    }
    if (totalNew > 0) {
        detailsHtml.push(`
            <div class="comparison-section new">
                <h4>New (${totalNew})</h4>
                <div class="comparison-findings">
                    ${(comparison.new_findings || []).map(f => `
                        <div class="comparison-finding">
                            <span>${f.title}</span>
                            <span class="badge ${f.severity}">${f.severity}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `);
    }

    container.innerHTML += detailsHtml.join('');
}

function renderAIAnalysis(aiReport) {
    const card = $('ai-analysis-card');
    card.style.display = 'block';

    const content = aiReport.summary || JSON.stringify(aiReport, null, 2);

    let html = '<pre class="ai-content">' + escapeHtml(content) + '</pre>';

    if (aiReport.priorities && aiReport.priorities.length > 0) {
        html += '<h4 style="margin-top: 1rem; margin-bottom: 0.75rem;">Priority Findings</h4>';
        html += '<div class="findings-list">';
        aiReport.priorities.forEach(p => {
            html += `<div class="finding-card">
                <div class="finding-header">
                    <div class="finding-title">${escapeHtml(p.title || p.issue || '')}</div>
                    <div class="finding-badges">
                        <span class="badge ${p.severity || 'medium'}">${p.severity || 'medium'}</span>
                    </div>
                </div>
                <div class="finding-description">${escapeHtml(p.explanation || p.why_it_matters || p.recommendation || '')}</div>
                ${p.action ? `<div class="finding-recommendation"><strong>Action:</strong><p>${escapeHtml(p.action)}</p></div>` : ''}
            </div>`;
        });
        html += '</div>';
    }

    $('ai-content').innerHTML = html;
}

function renderFindings(findings) {
    const container = $('findings-list');
    const allFindings = findings || [];

    // Group by category
    const byCategory = {};
    allFindings.forEach(f => {
        if (!byCategory[f.category]) byCategory[f.category] = [];
        byCategory[f.category].push(f);
    });

    if (allFindings.length === 0) {
        container.innerHTML = '<div class="empty-state">No findings! Your project looks ready to ship.</div>';
        return;
    }

    let html = '';
    Object.keys(byCategory).forEach(category => {
        const catFindings = byCategory[category];
        html += `<div class="category-section" style="margin-bottom: 2rem;">`;
        html += `<h3 style="text-transform: capitalize; margin-bottom: 1rem; color: var(--text-primary);">${category}</h3>`;
        html += catFindings.map(f => `
            <div class="finding-card">
                <div class="finding-header">
                    <div class="finding-title">${escapeHtml(f.title)}</div>
                    <div class="finding-badges">
                        <span class="badge ${f.severity}">${f.severity}</span>
                        <span class="badge category">${f.category}</span>
                    </div>
                </div>
                ${f.description ? `<div class="finding-description">${escapeHtml(f.description)}</div>` : ''}
                ${f.evidence ? `<div class="finding-evidence">${escapeHtml(f.evidence)}</div>` : ''}
                <div class="finding-meta">
                    ${f.file_path ? `<span><span style="color: var(--info);">📁</span> ${escapeHtml(f.file_path)}</span>` : ''}
                    ${f.line_number ? `<span><span style="color: var(--info);">📍</span> Line ${f.line_number}</span>` : ''}
                    ${f.confidence ? `<span><span style="color: var(--info);">🎯</span> Confidence: ${escapeHtml(f.confidence)}</span>` : ''}
                    ${f.first_detected_scan && f.last_detected_scan !== f.first_detected_scan ? `<span style="color: var(--success);">✓ Recurring</span>` : ''}
                </div>
                ${f.recommendation ? `<div class="finding-recommendation"><strong>Recommendation:</strong><p>${escapeHtml(f.recommendation)}</p></div>` : ''}
                <div class="finding-actions">
                    <button class="btn btn-sm btn-secondary" onclick="acknowledgeFinding('${f.id}')">Acknowledge</button>
                    <button class="btn btn-sm btn-secondary" onclick="markFixed('${f.id}')">Mark Fixed</button>
                </div>
            </div>
        `).join('');
        html += '</div>';
    });

    container.innerHTML = html;

    // Setup tab filtering
    setupTabs(allFindings);
}

function setupTabs(findings) {
    const tabs = document.querySelectorAll('.tab-btn');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            const category = tab.dataset.category;
            const container = $('findings-list');
            const categorySections = container.querySelectorAll('.category-section');

            categorySections.forEach(section => {
                if (category === 'all' || section.querySelector('h3').textContent.toLowerCase() === category) {
                    section.style.display = 'block';
                } else {
                    section.style.display = 'none';
                }
            });
        });
    });
}

// Actions
async function acknowledgeFinding(findingId) {
    try {
        await fetch(`${API_BASE}/reports/findings/${findingId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'acknowledged' })
        });
        alert('Finding acknowledged. Rescan to see the updated status.');
    } catch (e) {
        console.error('Failed to acknowledge finding:', e);
    }
}

async function markFixed(findingId) {
    try {
        await fetch(`${API_BASE}/reports/findings/${findingId}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'fixed' })
        });
        alert('Finding marked as fixed. Rescan to verify.');
    } catch (e) {
        console.error('Failed to mark finding:', e);
    }
}

async function selectProject(projectId) {
    currentProjectId = projectId;
    await startScan(projectId);
}

async function downloadReport() {
    try {
        const reportResp = await fetch(`${API_BASE}/reports/scan/${currentScanId}`);
        const report = await reportResp.json();

        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `shipcheck-report-${currentScanId.substring(0, 8)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (e) {
        console.error('Download error:', e);
        alert('Failed to download report.');
    }
}

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Global functions for inline onclick
function startScan(projectId) {
    if (typeof loadProjects !== 'undefined') {
        startScanInternal(projectId);
    }
}

async function startScanInternal(projectId) {
    currentProjectId = projectId;

    try {
        const response = await fetch(`${API_BASE}/scans`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ project_id: projectId })
        });
        const scan = await response.json();
        currentScanId = scan.id;

        showSection('scanSection');
        $('scan-status-badge').textContent = 'Queued';
        $('scan-status-badge').className = 'scan-status-badge queued';
        $('progress-message').textContent = 'Scan queued...';

        // Start polling
        scanInterval = setInterval(() => pollScanStatus(), 1500);

    } catch (error) {
        console.error('Scan start error:', error);
        alert('Failed to start scan: ' + error.message);
    }
}

function loadProjects() {
    loadProjectsInternal();
}

async function loadProjectsInternal() {
    const container = $('projects-list');
    container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading projects...</div>';

    try {
        const response = await fetch(`${API_BASE}/projects`);
        const projects = await response.json();

        if (projects.length === 0) {
            container.innerHTML = '<div class="empty-state">No projects yet. Upload your first project below.</div>';
        } else {
            container.innerHTML = projects.map(p => `
                <div class="project-item" onclick="selectProject('${p.id}')">
                    <div class="project-info">
                        <div class="project-name">${p.name}</div>
                        <div class="project-meta">${new Date(p.created_at).toLocaleString()}</div>
                        ${renderTechBadges(p.project_context)}
                    </div>
                    <div class="project-actions">
                        <button class="btn btn-sm btn-primary" onclick="startScan('${p.id}'); event.stopPropagation()">Scan Now</button>
                    </div>
                </div>
            `).join('');
        }
    } catch (error) {
        container.innerHTML = `<div class="loading" style="color: var(--danger);">Failed to load projects: ${error.message}</div>`;
    }
}