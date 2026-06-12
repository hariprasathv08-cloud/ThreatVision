// CyberSIEM Real-Time Frontend Scripting

document.addEventListener("DOMContentLoaded", function () {
    // 1. Live topbar clock
    updateClock();
    setInterval(updateClock, 1000);

    // Identify current page path
    const path = window.location.pathname;

    // Load page-specific functions
    if (path === "/" || path === "/dashboard") {
        initDashboard();
    } else if (path === "/events") {
        initEventsPage();
    } else if (path === "/alerts") {
        initAlertsPage();
    } else if (path === "/fim") {
        initFIMPage();
    } else if (path === "/usb") {
        initUSBPage();
    } else if (path === "/processes") {
        initProcessesPage();
    } else if (path === "/network") {
        initNetworkPage();
    } else if (path === "/firewall") {
        initFirewallPage();
    }

    // Generic sortable table helper
    setupSortableTables();

    // Initialize unified real-time event stream
    initEventStream();
});

// Clock updater
function updateClock() {
    const clockEl = document.getElementById("topbar-clock");
    if (clockEl) {
        const now = new Date();
        const options = { 
            month: 'short', 
            day: 'numeric', 
            year: 'numeric', 
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit', 
            hour12: true 
        };
        clockEl.innerText = now.toLocaleString('en-US', options);
    }
}

// ----------------- DASHBOARD VIEW LOGIC -----------------

let charts = {};

function initDashboard() {
    // Initialize Dashboard Charts
    const ctxLine = document.getElementById("eventsOverTimeChart");
    const ctxSeverity = document.getElementById("alertsSeverityChart");
    const ctxCategories = document.getElementById("eventCategoriesChart");

    // Initialize System Health Gauges
    const gaugeCPU = initGauge("cpuGaugeCanvas", "#0ea5e9");
    const gaugeMem = initGauge("memoryGaugeCanvas", "#a855f7");
    const gaugeDisk = initGauge("diskGaugeCanvas", "#f97316");
    const gaugeConn = initGauge("connGaugeCanvas", "#22c55e", true);

    window.gauges = {
        cpu: gaugeCPU,
        mem: gaugeMem,
        disk: gaugeDisk,
        conn: gaugeConn
    };

    // 1. Events Over Time Line Chart
    if (ctxLine) {
        charts.line = new Chart(ctxLine, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Total Events',
                        data: [],
                        borderColor: '#0ea5e9',
                        backgroundColor: 'rgba(14, 165, 233, 0.1)',
                        tension: 0.3,
                        fill: true
                    },
                    {
                        label: 'Critical',
                        data: [],
                        borderColor: '#ef4444',
                        backgroundColor: 'transparent',
                        tension: 0.3
                    },
                    {
                        label: 'High',
                        data: [],
                        borderColor: '#f97316',
                        backgroundColor: 'transparent',
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#94a3b8' } }
                },
                scales: {
                    x: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' } },
                    y: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' } }
                }
            }
        });
    }

    // 2. Alerts by Severity Donut Chart
    if (ctxSeverity) {
        charts.severity = new Chart(ctxSeverity, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: ['#ef4444', '#f97316', '#eab308', '#22c55e'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'right', labels: { color: '#94a3b8' } }
                },
                cutout: '70%'
            }
        });
    }

    // 3. Top Event Categories Horizontal Bar Chart
    if (ctxCategories) {
        charts.categories = new Chart(ctxCategories, {
            type: 'bar',
            data: {
                labels: ['Logon/Logoff', 'User Mgmt', 'System Logs', 'Audit Cleared', 'Policy Mods', 'Other'],
                datasets: [{
                    label: 'Event Count',
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: '#0ea5e9',
                    borderRadius: 4
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: { grid: { color: '#1e293b' }, ticks: { color: '#94a3b8' } },
                    y: { grid: { color: 'transparent' }, ticks: { color: '#94a3b8' } }
                }
            }
        });
    }

    // Initial load and start interval update (every 15 seconds as fallback backup)
    pollDashboardData(gaugeCPU, gaugeMem, gaugeDisk, gaugeConn);
    setInterval(() => {
        pollDashboardData(gaugeCPU, gaugeMem, gaugeDisk, gaugeConn);
    }, 15000);
}

function initGauge(canvasId, color, isConnections = false) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return null;
    
    return new Chart(ctx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [0, 100],
                backgroundColor: [color, '#1e293b'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '80%',
            plugins: { legend: { display: false }, tooltip: { enabled: false } }
        }
    });
}

function updateGaugeVal(gauge, val, labelId, isConnections = false) {
    if (!gauge) return;
    const cleanVal = parseFloat(val) || 0;
    const rounded = Math.round(cleanVal);
    
    if (isConnections) {
        // Connections gauge doesn't have a max of 100 limit, let's treat 250 as 100% full
        const fill = Math.min((cleanVal / 250) * 100, 100);
        gauge.data.datasets[0].data = [fill, 100 - fill];
        document.getElementById(labelId).innerText = rounded;
    } else {
        gauge.data.datasets[0].data = [rounded, 100 - rounded];
        document.getElementById(labelId).innerText = rounded + "%";
    }
    gauge.update();
}

function pollDashboardData(gaugeCPU, gaugeMem, gaugeDisk, gaugeConn) {
    // 1. Fetch Stats API (for cards and gauges)
    fetch("/api/stats")
        .then(res => res.json())
        .then(data => {
            // Update Metric Cards
            document.getElementById("stat-total-events").innerText = data.total_events.toLocaleString();
            document.getElementById("stat-critical").innerText = data.critical_alerts;
            document.getElementById("stat-high").innerText = data.high_alerts;
            document.getElementById("stat-medium").innerText = data.medium_alerts;
            document.getElementById("stat-low").innerText = data.low_alerts;
            document.getElementById("stat-active-users").innerText = data.active_users;

            // Update gauges
            updateGaugeVal(gaugeCPU, data.cpu_usage, "cpu-gauge-text");
            updateGaugeVal(gaugeMem, data.memory_usage, "mem-gauge-text");
            updateGaugeVal(gaugeDisk, data.disk_usage, "disk-gauge-text");
            updateGaugeVal(gaugeConn, data.net_connections, "conn-gauge-text", true);

            // Update donut chart
            if (charts.severity) {
                charts.severity.data.datasets[0].data = [
                    data.critical_alerts,
                    data.high_alerts,
                    data.medium_alerts,
                    data.low_alerts
                ];
                charts.severity.update();
            }
        });

    // 2. Fetch Health History (for line chart)
    fetch("/api/health_history")
        .then(res => res.json())
        .then(data => {
            if (charts.line && data.length > 0) {
                const labels = data.map(d => {
                    const t = new Date(d.timestamp);
                    return t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                });
                
                charts.line.data.labels = labels;
                charts.line.data.datasets[0].data = data.map(d => d.cpu_usage); // Use CPU usage history as a placeholder for activity
                charts.line.data.datasets[1].data = data.map(d => d.memory_usage);
                charts.line.data.datasets[2].data = data.map(d => d.network_connections);
                charts.line.update();
            }
        });

    // 3. Fetch Live Event Logs
    fetch("/api/events?limit=7")
        .then(res => res.json())
        .then(data => {
            const tableBody = document.getElementById("live-events-table-body");
            if (!tableBody) return;
            
            tableBody.innerHTML = "";
            if (data.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No Windows Event Logs gathered yet.</td></tr>`;
                return;
            }

            // Categories count breakdown calculation
            let counts = {logon: 0, user_mgmt: 0, system: 0, audit_clear: 0, policy: 0, other: 0};

            data.forEach(evt => {
                const badgeClass = {
                    "Error": "critical",
                    "Warning": "warning",
                    "Audit Success": "low",
                    "Audit Failure": "critical",
                    "Information": "info"
                }[evt.level] || "info";

                // Categorize for bar chart counts heuristic
                const id = evt.event_id;
                if (id === 4624 || id === 4625) counts.logon++;
                else if (id === 4720 || id === 4726 || id === 4723) counts.user_mgmt++;
                else if (id === 1102) counts.audit_clear++;
                else if (evt.log_name === "System") counts.system++;
                else if (evt.log_name === "Security") counts.policy++;
                else counts.other++;

                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${evt.timestamp}</td>
                    <td><span class="badge-level info">${evt.event_id}</span></td>
                    <td><span class="badge-level ${badgeClass}">${evt.level}</span></td>
                    <td>${escapeHtml(evt.source)}</td>
                    <td class="text-truncate" style="max-width: 350px;" title="${escapeHtml(evt.message)}">${escapeHtml(evt.message)}</td>
                `;
                tableBody.appendChild(tr);
            });

            // Update Categories Bar Chart
            if (charts.categories) {
                charts.categories.data.datasets[0].data = [
                    counts.logon,
                    counts.user_mgmt,
                    counts.system,
                    counts.audit_clear,
                    counts.policy,
                    counts.other
                ];
                charts.categories.update();
            }
        });

    // 4. Fetch Recent Critical/High Alerts
    fetch("/api/alerts?status=Open")
        .then(res => res.json())
        .then(data => {
            const tableBody = document.getElementById("recent-alerts-table-body");
            if (!tableBody) return;

            tableBody.innerHTML = "";
            
            // Filter critical/high
            const criticals = data.filter(a => a.severity === "Critical" || a.severity === "High").slice(0, 6);

            if (criticals.length === 0) {
                tableBody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">All systems clear. No open Critical/High alerts.</td></tr>`;
                return;
            }

            criticals.forEach(alert => {
                const tr = document.createElement("tr");
                const sevBadge = alert.severity.toLowerCase();
                const statBadge = alert.status.toLowerCase();
                
                tr.innerHTML = `
                    <td>${alert.timestamp}</td>
                    <td><span class="badge-level ${sevBadge}">${alert.severity}</span></td>
                    <td>${escapeHtml(alert.source)}</td>
                    <td class="text-truncate" style="max-width: 280px;" title="${escapeHtml(alert.details)}">${escapeHtml(alert.details)}</td>
                    <td><span class="badge-level info text-white font-monospace" style="font-size: 10px;">${escapeHtml(alert.mitre_technique || 'N/A')}</span></td>
                    <td><span class="badge-status ${statBadge}">${alert.status}</span></td>
                `;
                tableBody.appendChild(tr);
            });
        });
}

// ----------------- SECURITY EVENTS VIEW -----------------

function initEventsPage() {
    const tableBody = document.getElementById("events-table-body");
    const searchInput = document.getElementById("event-search");
    const levelFilter = document.getElementById("event-level-filter");

    function loadEvents() {
        const search = searchInput.value;
        const level = levelFilter.value;
        
        fetch(`/api/events?limit=100&search=${encodeURIComponent(search)}&level=${encodeURIComponent(level)}`)
            .then(res => res.json())
            .then(data => {
                tableBody.innerHTML = "";
                if (data.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No security events match this query.</td></tr>`;
                    return;
                }
                
                data.forEach(evt => {
                    const badgeClass = {
                        "Error": "critical",
                        "Warning": "warning",
                        "Audit Success": "low",
                        "Audit Failure": "critical",
                        "Information": "info"
                    }[evt.level] || "info";

                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${evt.id}</td>
                        <td>${evt.timestamp}</td>
                        <td><span class="badge-level info">${evt.event_id}</span></td>
                        <td><span class="badge-level ${badgeClass}">${evt.level}</span></td>
                        <td>${escapeHtml(evt.source)}</td>
                        <td>${escapeHtml(evt.message)}</td>
                    `;
                    tableBody.appendChild(tr);
                });
            });
    }

    searchInput.addEventListener("input", debounce(loadEvents, 300));
    levelFilter.addEventListener("change", loadEvents);
    loadEvents();
    
    // Auto-refresh every 20 seconds as a backup fallback
    setInterval(loadEvents, 20000);
}

// ----------------- ALERTS CENTER VIEW -----------------

function initAlertsPage() {
    const tableBody = document.getElementById("alerts-table-body");
    const sevFilter = document.getElementById("alert-severity-filter");
    const statFilter = document.getElementById("alert-status-filter");

    // Parse URL query parameters to pre-select dropdown filters
    const urlParams = new URLSearchParams(window.location.search);
    const severityParam = urlParams.get("severity");
    if (severityParam && sevFilter) {
        sevFilter.value = severityParam;
    }
    const statusParam = urlParams.get("status");
    if (statusParam && statFilter) {
        statFilter.value = statusParam;
    }

    function loadAlerts() {
        const severity = sevFilter.value;
        const status = statFilter.value;
        
        fetch(`/api/alerts?severity=${severity}&status=${status}`)
            .then(res => res.json())
            .then(data => {
                tableBody.innerHTML = "";
                if (data.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="8" class="text-center text-muted">No alerts recorded under this category.</td></tr>`;
                    return;
                }
                
                data.forEach(alert => {
                    const tr = document.createElement("tr");
                    const sevClass = alert.severity.toLowerCase();
                    const statClass = alert.status.toLowerCase();
                    
                    tr.innerHTML = `
                        <td>${alert.id}</td>
                        <td>${alert.timestamp}</td>
                        <td><span class="badge-level ${sevClass}">${alert.severity}</span></td>
                        <td><strong>${escapeHtml(alert.source)}</strong></td>
                        <td>${escapeHtml(alert.details)}</td>
                        <td><span class="badge-level info text-white font-monospace" style="font-size: 10px;">${escapeHtml(alert.mitre_technique || 'N/A')}</span></td>
                        <td><span class="text-muted">${escapeHtml(alert.recommended_action || 'N/A')}</span></td>
                        <td>
                            <select class="form-control form-control-sm border-0 bg-transparent text-white" onchange="updateAlertStatus(${alert.id}, this.value)">
                                <option class="bg-dark text-white" value="Open" ${alert.status === 'Open' ? 'selected' : ''}>Open</option>
                                <option class="bg-dark text-white" value="Investigating" ${alert.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
                                <option class="bg-dark text-white" value="Resolved" ${alert.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                            </select>
                        </td>
                    `;
                    tableBody.appendChild(tr);
                });
            });
    }

    sevFilter.addEventListener("change", loadAlerts);
    statFilter.addEventListener("change", loadAlerts);
    loadAlerts();
    
    // Auto-refresh backup
    setInterval(loadAlerts, 20000);
}

window.updateAlertStatus = function(alertId, newStatus) {
    fetch("/api/alerts/update_status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ alert_id: alertId, status: newStatus })
    }).then(res => res.json())
      .then(data => {
          if (data.status === "success") {
              logger.info(`Alert ${alertId} set to ${newStatus}`);
          }
      });
}

// ----------------- FIM VIEW LOGIC -----------------

function initFIMPage() {
    const tableBody = document.getElementById("fim-table-body");
    
    function loadFIM() {
        fetch("/api/fim")
            .then(res => res.json())
            .then(data => {
                tableBody.innerHTML = "";
                if (data.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No file events recorded yet.</td></tr>`;
                    return;
                }
                
                data.forEach(evt => {
                    const badgeClass = {
                        "Created": "low",
                        "Modified": "warning",
                        "Deleted": "critical",
                        "Renamed": "high"
                    }[evt.event_type] || "info";

                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${evt.timestamp}</td>
                        <td><strong>${escapeHtml(osPathBasename(evt.filepath))}</strong></td>
                        <td><span class="badge-level ${badgeClass}">${evt.event_type}</span></td>
                        <td class="text-muted small">${escapeHtml(evt.details || evt.filepath)}</td>
                    `;
                    tableBody.appendChild(tr);
                });
            });
    }
    
    loadFIM();
    setInterval(loadFIM, 20000);
}

// ----------------- USB VIEW LOGIC -----------------

function initUSBPage() {
    const drivesBody = document.getElementById("usb-drives-body");
    const eventsBody = document.getElementById("usb-events-body");
    
    function loadUSB() {
        fetch("/api/usb")
            .then(res => res.json())
            .then(data => {
                // Connected drives
                drivesBody.innerHTML = "";
                if (data.drives.length === 0) {
                    drivesBody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No external USB storage drives connected currently.</td></tr>`;
                } else {
                    data.drives.forEach(drv => {
                        const tr = document.createElement("tr");
                        tr.innerHTML = `
                            <td><i class="fas fa-hdd text-info mr-2"></i> ${escapeHtml(drv.model)}</td>
                            <td>${escapeHtml(drv.vendor)}</td>
                            <td><span class="badge-level low">Active</span></td>
                        `;
                        drivesBody.appendChild(tr);
                    });
                }
                
                // Historical events
                eventsBody.innerHTML = "";
                if (data.events.length === 0) {
                    eventsBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No USB insertion/removal history.</td></tr>`;
                } else {
                    data.events.forEach(evt => {
                        const actClass = evt.event_type === "Insertion" ? "low" : "critical";
                        const tr = document.createElement("tr");
                        tr.innerHTML = `
                            <td>${evt.timestamp}</td>
                            <td>${escapeHtml(evt.device_name)}</td>
                            <td>${escapeHtml(evt.vendor)}</td>
                            <td><span class="badge-level ${actClass}">${evt.event_type}</span></td>
                        `;
                        eventsBody.appendChild(tr);
                    });
                }
            });
    }
    
    loadUSB();
    setInterval(loadUSB, 20000);
}

// ----------------- PROCESS VIEW LOGIC -----------------

function initProcessesPage() {
    const tableBody = document.getElementById("processes-table-body");
    
    function loadProcesses() {
        fetch("/api/processes")
            .then(res => res.json())
            .then(data => {
                tableBody.innerHTML = "";
                if (data.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">Unable to retrieve processes list.</td></tr>`;
                    return;
                }
                
                data.forEach(proc => {
                    const rowClass = proc.suspicious ? "table-danger border-left border-danger" : "";
                    const badgeClass = proc.suspicious ? "badge-level critical" : "badge-level info";
                    
                    const tr = document.createElement("tr");
                    if (proc.suspicious) {
                        tr.style.backgroundColor = "rgba(239, 68, 68, 0.08)";
                    }
                    
                    tr.innerHTML = `
                        <td>${proc.pid}</td>
                        <td><strong>${escapeHtml(proc.name)}</strong></td>
                        <td>${escapeHtml(proc.username)}</td>
                        <td>${proc.cpu.toFixed(1)}%</td>
                        <td>${proc.memory.toFixed(2)}%</td>
                        <td class="text-truncate text-muted small" style="max-width: 280px;" title="${escapeHtml(proc.cmdline || proc.path)}">${escapeHtml(proc.cmdline || proc.path)}</td>
                        <td>
                            ${proc.suspicious ? '<span class="badge-level critical mr-2">SUSPICIOUS</span>' : ''}
                            <form action="/process/kill/${proc.pid}" method="POST" class="d-inline" onsubmit="return confirm('Are you sure you want to terminate PID ${proc.pid}?');">
                                <button type="submit" class="btn btn-sm btn-outline-danger border-0 p-1"><i class="fas fa-trash-alt"></i> Kill</button>
                            </form>
                        </td>
                    `;
                    tableBody.appendChild(tr);
                });
            });
    }
    
    loadProcesses();
    // Processes update slightly slower to reduce UI load (every 10 seconds)
    setInterval(loadProcesses, 10000);
}

// ----------------- NETWORK VIEW LOGIC -----------------

function initNetworkPage() {
    const tableBody = document.getElementById("network-table-body");
    
    function loadNetwork() {
        fetch("/api/network")
            .then(res => res.json())
            .then(data => {
                tableBody.innerHTML = "";
                if (data.length === 0) {
                    tableBody.innerHTML = `<tr><td colspan="7" class="text-center text-muted">No active network sockets active.</td></tr>`;
                    return;
                }
                
                data.forEach(conn => {
                    const statusClass = conn.state === "ESTABLISHED" ? "badge-level low" : "badge-level info";
                    const isRemote = conn.remote_ip !== "N/A" && conn.remote_ip !== "127.0.0.1";
                    
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${conn.timestamp}</td>
                        <td><span class="badge-level info">${conn.protocol}</span></td>
                        <td>${conn.local_ip}:${conn.local_port}</td>
                        <td class="${isRemote ? 'font-weight-bold text-info' : ''}">${conn.remote_ip}:${conn.remote_port}</td>
                        <td><span class="${statusClass}">${conn.state}</span></td>
                    `;
                    tableBody.appendChild(tr);
                });
            });
    }
    
    loadNetwork();
    setInterval(loadNetwork, 20000);
}

window.triggerNetworkScan = function() {
    const btn = document.getElementById("btn-start-scan");
    const loading = document.getElementById("scan-loading-message");
    const tableBody = document.getElementById("network-scanner-body");
    
    if (!btn || !loading || !tableBody) return;
    
    // Set UI to loading/processing state
    btn.disabled = true;
    loading.classList.remove("d-none");
    tableBody.innerHTML = `<tr><td colspan="4" class="text-center text-info"><i class="fas fa-spinner fa-spin mr-2"></i> Subnet sweep in progress... Gathering online hosts.</td></tr>`;
    
    fetch("/api/network/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
    })
    .then(res => res.json())
    .then(data => {
        tableBody.innerHTML = "";
        btn.disabled = false;
        loading.classList.add("d-none");
        
        if (data.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No other active devices discovered on local network interface.</td></tr>`;
            return;
        }
        
        data.forEach(dev => {
            const tr = document.createElement("tr");
            const isLocal = dev.mac === "LOCAL-INTERFACE";
            
            tr.innerHTML = `
                <td class="${isLocal ? 'font-weight-bold text-success' : 'font-weight-bold text-info'}">${dev.ip} ${isLocal ? '<span class="badge-level low ml-2" style="font-size:10px; padding:2px 6px;">Self</span>' : ''}</td>
                <td><code class="text-white">${dev.mac}</code></td>
                <td><span class="badge-level info">${dev.type}</span></td>
                <td>${escapeHtml(dev.hostname)}</td>
            `;
            tableBody.appendChild(tr);
        });
    })
    .catch(err => {
        btn.disabled = false;
        loading.classList.add("d-none");
        tableBody.innerHTML = `<tr><td colspan="4" class="text-center text-danger"><i class="fas fa-exclamation-triangle mr-2"></i> Subnet scan failed: ${escapeHtml(err.message)}</td></tr>`;
    });
}

// ----------------- FIREWALL VIEW LOGIC -----------------

function initFirewallPage() {
    const eventsBody = document.getElementById("firewall-events-body");
    
    function loadFirewall() {
        fetch("/api/firewall")
            .then(res => res.json())
            .then(data => {
                // Update profile badges
                for (const [prof, state] of Object.entries(data.profiles)) {
                    const badge = document.getElementById(`fw-${prof.toLowerCase()}-badge`);
                    if (badge) {
                        badge.innerText = state;
                        badge.className = state === "ON" ? "badge-level low" : "badge-level critical";
                    }
                }
                
                // Update events log
                eventsBody.innerHTML = "";
                if (data.events.length === 0) {
                    eventsBody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No firewall profile change logs recorded.</td></tr>`;
                } else {
                    data.events.forEach(evt => {
                        const tr = document.createElement("tr");
                        const badgeClass = evt.action.includes("Disable") ? "critical" : "low";
                        
                        tr.innerHTML = `
                            <td>${evt.timestamp}</td>
                            <td><span class="badge-level ${badgeClass}">${evt.action}</span></td>
                            <td>${escapeHtml(evt.details)}</td>
                        `;
                        eventsBody.appendChild(tr);
                    });
                }
            });
    }
    
    loadFirewall();
    setInterval(loadFirewall, 20000);
}


// ----------------- HELPER UTILITIES -----------------

function escapeHtml(text) {
    if (!text) return "";
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.toString().replace(/[&<>"']/g, function(m) { return map[m]; });
}

function osPathBasename(path) {
    return path.split(/[\\/]/).pop();
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Client-side table sorting helper
function setupSortableTables() {
    document.querySelectorAll(".sortable th").forEach(headerCell => {
        headerCell.addEventListener("click", () => {
            const tableElement = headerCell.parentElement.parentElement.parentElement;
            const headingIndex = Array.prototype.indexOf.call(headerCell.parentElement.children, headerCell);
            const isAscending = headerCell.classList.contains("th-sort-asc");
            
            sortTableByColumn(tableElement, headingIndex, !isAscending);
        });
    });
}

function sortTableByColumn(table, column, asc = true) {
    const dirModifier = asc ? 1 : -1;
    const tBody = table.tBodies[0];
    const rows = Array.from(tBody.querySelectorAll("tr"));
    
    // Sort rows
    const sortedRows = rows.sort((a, b) => {
        const aColText = a.querySelector(`td:nth-child(${column + 1})`).textContent.trim();
        const bColText = b.querySelector(`td:nth-child(${column + 1})`).textContent.trim();
        
        // Check if numeric
        const aNum = parseFloat(aColText.replace(/[^0-9.-]/g, ''));
        const bNum = parseFloat(bColText.replace(/[^0-9.-]/g, ''));
        if (!isNaN(aNum) && !isNaN(bNum)) {
            return (aNum - bNum) * dirModifier;
        }
        
        return aColText.localeCompare(bColText) * dirModifier;
    });
    
    // Remove all existing TRs
    while (tBody.firstChild) {
        tBody.removeChild(tBody.firstChild);
    }
    
    // Re-add sorted TRs
    tBody.append(...sortedRows);
    
    table.querySelectorAll("th").forEach(th => th.classList.remove("th-sort-asc", "th-sort-desc"));
    table.querySelector(`th:nth-child(${column + 1})`).classList.toggle("th-sort-asc", asc);
    table.querySelector(`th:nth-child(${column + 1})`).classList.toggle("th-sort-desc", !asc);
}

// ----------------- UNIFIED REAL-TIME SSE FEED -----------------

window.realtimeSource = null;

function initEventStream() {
    if (window.realtimeSource) {
        window.realtimeSource.close();
    }

    console.log("Connecting to CyberSIEM Real-Time Event Stream...");
    const source = new EventSource("/api/realtime/feed");
    window.realtimeSource = source;

    source.onopen = function () {
        console.log("CyberSIEM Real-Time Event Stream connected successfully.");
    };

    source.onerror = function (err) {
        console.warn("SSE connection closed or lost. Browser will auto-reconnect.", err);
    };

    // 1. New Alert Triggered
    source.addEventListener("alert", function (event) {
        const alert = JSON.parse(event.data);
        console.log("Real-time Alert:", alert);

        // Show Toast & Play Sound
        showToastNotification(alert);
        playAlertSound();

        // Increment Topbar Notification Bell
        const badge = document.getElementById("notification-badge");
        if (badge) {
            let count = parseInt(badge.innerText) || 0;
            badge.innerText = count + 1;
            badge.classList.add("pulse");
            setTimeout(() => badge.classList.remove("pulse"), 1000);
        }

        // Update dashboard numeric cards and severity charts immediately
        updateDashboardMetrics();

        // If on Dashboard page, prepend to Recent Alerts table
        const recentAlertsTable = document.getElementById("recent-alerts-table-body");
        if (recentAlertsTable) {
            // Remove empty state message
            if (recentAlertsTable.querySelector("td[colspan]")) {
                recentAlertsTable.innerHTML = "";
            }

            const tr = document.createElement("tr");
            const sevBadge = alert.severity.toLowerCase();
            const statBadge = alert.status.toLowerCase();

            tr.innerHTML = `
                <td>${alert.timestamp}</td>
                <td><span class="badge-level ${sevBadge}">${alert.severity}</span></td>
                <td>${escapeHtml(alert.source)}</td>
                <td class="text-truncate" style="max-width: 280px;" title="${escapeHtml(alert.details)}">${escapeHtml(alert.details)}</td>
                <td><span class="badge-level info text-white font-monospace" style="font-size: 10px;">${escapeHtml(alert.mitre_technique || 'N/A')}</span></td>
                <td><span class="badge-status ${statBadge}">${alert.status}</span></td>
            `;

            tr.style.opacity = 0;
            tr.style.transition = "opacity 0.4s ease";
            recentAlertsTable.insertBefore(tr, recentAlertsTable.firstChild);
            setTimeout(() => tr.style.opacity = 1, 50);

            // Cap at 6 rows
            while (recentAlertsTable.children.length > 6) {
                recentAlertsTable.removeChild(recentAlertsTable.lastChild);
            }
        }

        // If on Alerts Center, prepend to Alerts table
        const alertsTable = document.getElementById("alerts-table-body");
        if (alertsTable) {
            if (alertsTable.querySelector("td[colspan]")) {
                alertsTable.innerHTML = "";
            }

            const tr = document.createElement("tr");
            const sevClass = alert.severity.toLowerCase();
            
            tr.innerHTML = `
                <td>${alert.id}</td>
                <td>${alert.timestamp}</td>
                <td><span class="badge-level ${sevClass}">${alert.severity}</span></td>
                <td><strong>${escapeHtml(alert.source)}</strong></td>
                <td>${escapeHtml(alert.details)}</td>
                <td><span class="badge-level info text-white font-monospace" style="font-size: 10px;">${escapeHtml(alert.mitre_technique || 'N/A')}</span></td>
                <td><span class="text-muted">${escapeHtml(alert.recommended_action || 'N/A')}</span></td>
                <td>
                    <select class="form-control form-control-sm border-0 bg-transparent text-white" onchange="updateAlertStatus(${alert.id}, this.value)">
                        <option class="bg-dark text-white" value="Open" ${alert.status === 'Open' ? 'selected' : ''}>Open</option>
                        <option class="bg-dark text-white" value="Investigating" ${alert.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
                        <option class="bg-dark text-white" value="Resolved" ${alert.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                    </select>
                </td>
            `;

            tr.style.opacity = 0;
            tr.style.transition = "opacity 0.4s ease";
            alertsTable.insertBefore(tr, alertsTable.firstChild);
            setTimeout(() => tr.style.opacity = 1, 50);
        }
    });

    // 2. New Windows Event Log
    source.addEventListener("event", function (event) {
        const evt = JSON.parse(event.data);
        console.log("Real-time Event:", evt);

        // Prepend to Dashboard Live Event log
        const liveEventsTable = document.getElementById("live-events-table-body");
        if (liveEventsTable) {
            if (liveEventsTable.querySelector("td[colspan]")) {
                liveEventsTable.innerHTML = "";
            }

            const badgeClass = {
                "Error": "critical",
                "Warning": "warning",
                "Audit Success": "low",
                "Audit Failure": "critical",
                "Information": "info"
            }[evt.level] || "info";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${evt.timestamp}</td>
                <td><span class="badge-level info">${evt.event_id}</span></td>
                <td><span class="badge-level ${badgeClass}">${evt.level}</span></td>
                <td>${escapeHtml(evt.source)}</td>
                <td class="text-truncate" style="max-width: 350px;" title="${escapeHtml(evt.message)}">${escapeHtml(evt.message)}</td>
            `;

            tr.style.opacity = 0;
            tr.style.transition = "opacity 0.4s ease";
            liveEventsTable.insertBefore(tr, liveEventsTable.firstChild);
            setTimeout(() => tr.style.opacity = 1, 50);

            while (liveEventsTable.children.length > 7) {
                liveEventsTable.removeChild(liveEventsTable.lastChild);
            }

            // Dynamically increment categories chart
            incrementDashboardCategories(evt);
        }

        // Prepend to Security Events page
        const eventsTable = document.getElementById("events-table-body");
        if (eventsTable) {
            if (eventsTable.querySelector("td[colspan]")) {
                eventsTable.innerHTML = "";
            }

            const badgeClass = {
                "Error": "critical",
                "Warning": "warning",
                "Audit Success": "low",
                "Audit Failure": "critical",
                "Information": "info"
            }[evt.level] || "info";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${evt.id}</td>
                <td>${evt.timestamp}</td>
                <td><span class="badge-level info">${evt.event_id}</span></td>
                <td><span class="badge-level ${badgeClass}">${evt.level}</span></td>
                <td>${escapeHtml(evt.source)}</td>
                <td>${escapeHtml(evt.message)}</td>
            `;

            tr.style.opacity = 0;
            tr.style.transition = "opacity 0.4s ease";
            eventsTable.insertBefore(tr, eventsTable.firstChild);
            setTimeout(() => tr.style.opacity = 1, 50);
        }
    });

    // 3. New File Integrity Event
    source.addEventListener("fim", function (event) {
        const evt = JSON.parse(event.data);
        console.log("Real-time FIM:", evt);

        const fimTable = document.getElementById("fim-table-body");
        if (fimTable) {
            if (fimTable.querySelector("td[colspan]")) {
                fimTable.innerHTML = "";
            }

            const badgeClass = {
                "Created": "low",
                "Modified": "warning",
                "Deleted": "critical",
                "Renamed": "high"
            }[evt.event_type] || "info";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${evt.timestamp}</td>
                <td><strong>${escapeHtml(osPathBasename(evt.filepath))}</strong></td>
                <td><span class="badge-level ${badgeClass}">${evt.event_type}</span></td>
                <td class="text-muted small">${escapeHtml(evt.details || evt.filepath)}</td>
            `;

            tr.style.opacity = 0;
            tr.style.transition = "opacity 0.4s ease";
            fimTable.insertBefore(tr, fimTable.firstChild);
            setTimeout(() => tr.style.opacity = 1, 50);
        }
    });

    // 4. USB Interaction Event
    source.addEventListener("usb", function (event) {
        const evt = JSON.parse(event.data);
        console.log("Real-time USB Event:", evt);

        const drivesBody = document.getElementById("usb-drives-body");
        const eventsBody = document.getElementById("usb-events-body");
        if (drivesBody || eventsBody) {
            // Hot reload full USB snapshot API on-demand
            fetch("/api/usb")
                .then(res => res.json())
                .then(data => {
                    if (drivesBody) {
                        drivesBody.innerHTML = "";
                        if (data.drives.length === 0) {
                            drivesBody.innerHTML = `<tr><td colspan="3" class="text-center text-muted">No external USB storage drives connected currently.</td></tr>`;
                        } else {
                            data.drives.forEach(drv => {
                                const tr = document.createElement("tr");
                                tr.innerHTML = `
                                    <td><i class="fas fa-hdd text-info mr-2"></i> ${escapeHtml(drv.model)}</td>
                                    <td>${escapeHtml(drv.vendor)}</td>
                                    <td><span class="badge-level low">Active</span></td>
                                `;
                                drivesBody.appendChild(tr);
                            });
                        }
                    }
                    if (eventsBody) {
                        eventsBody.innerHTML = "";
                        if (data.events.length === 0) {
                            eventsBody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No USB insertion/removal history.</td></tr>`;
                        } else {
                            data.events.forEach(e => {
                                const actClass = e.event_type === "Insertion" ? "low" : "critical";
                                const tr = document.createElement("tr");
                                tr.innerHTML = `
                                    <td>${e.timestamp}</td>
                                    <td>${escapeHtml(e.device_name)}</td>
                                    <td>${escapeHtml(e.vendor)}</td>
                                    <td><span class="badge-level ${actClass}">${e.event_type}</span></td>
                                `;
                                eventsBody.appendChild(tr);
                            });
                        }
                    }
                });
        }
    });

    // 5. Firewall Change Event
    source.addEventListener("firewall", function (event) {
        const evt = JSON.parse(event.data);
        console.log("Real-time Firewall:", evt);

        const firewallEventsTable = document.getElementById("firewall-events-body");
        if (firewallEventsTable) {
            if (firewallEventsTable.querySelector("td[colspan]")) {
                firewallEventsTable.innerHTML = "";
            }

            const badgeClass = evt.action.includes("Disable") ? "critical" : "low";
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${evt.timestamp}</td>
                <td><span class="badge-level ${badgeClass}">${evt.action}</span></td>
                <td>${escapeHtml(evt.details)}</td>
            `;

            tr.style.opacity = 0;
            tr.style.transition = "opacity 0.4s ease";
            firewallEventsTable.insertBefore(tr, firewallEventsTable.firstChild);
            setTimeout(() => tr.style.opacity = 1, 50);

            // Resync status profile badges
            fetch("/api/firewall")
                .then(res => res.json())
                .then(data => {
                    for (const [prof, state] of Object.entries(data.profiles)) {
                        const badge = document.getElementById(`fw-${prof.toLowerCase()}-badge`);
                        if (badge) {
                            badge.innerText = state;
                            badge.className = state === "ON" ? "badge-level low" : "badge-level critical";
                        }
                    }
                });
        }
    });

    // 6. Network Socket Event
    source.addEventListener("network", function (event) {
        const conn = JSON.parse(event.data);
        console.log("Real-time Socket:", conn);

        const networkTable = document.getElementById("network-table-body");
        if (networkTable) {
            if (networkTable.querySelector("td[colspan]")) {
                networkTable.innerHTML = "";
            }

            const statusClass = conn.state === "ESTABLISHED" ? "badge-level low" : "badge-level info";
            const isRemote = conn.remote_ip !== "N/A" && conn.remote_ip !== "127.0.0.1";

            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${conn.timestamp}</td>
                <td><span class="badge-level info">${conn.protocol}</span></td>
                <td>${conn.local_ip}:${conn.local_port}</td>
                <td class="${isRemote ? 'font-weight-bold text-info' : ''}">${conn.remote_ip}:${conn.remote_port}</td>
                <td><span class="${statusClass}">${conn.state}</span></td>
            `;

            tr.style.opacity = 0;
            tr.style.transition = "opacity 0.4s ease";
            networkTable.insertBefore(tr, networkTable.firstChild);
            setTimeout(() => tr.style.opacity = 1, 50);
        }
    });

    // 7. System Health Pulse (Instant gauges updates!)
    source.addEventListener("health", function (event) {
        const data = JSON.parse(event.data);
        if (window.gauges) {
            updateGaugeVal(window.gauges.cpu, data.cpu_usage, "cpu-gauge-text");
            updateGaugeVal(window.gauges.mem, data.memory_usage, "mem-gauge-text");
            updateGaugeVal(window.gauges.disk, data.disk_usage, "disk-gauge-text");
            updateGaugeVal(window.gauges.conn, data.network_connections, "conn-gauge-text", true);
        }
    });
}

// ----------------- SSE HELPER DISPATCHERS -----------------

function updateDashboardMetrics() {
    fetch("/api/stats")
        .then(res => res.json())
        .then(data => {
            const elTotal = document.getElementById("stat-total-events");
            const elCritical = document.getElementById("stat-critical");
            const elHigh = document.getElementById("stat-high");
            const elMedium = document.getElementById("stat-medium");
            const elLow = document.getElementById("stat-low");
            const elUsers = document.getElementById("stat-active-users");

            if (elTotal) elTotal.innerText = data.total_events.toLocaleString();
            if (elCritical) elCritical.innerText = data.critical_alerts;
            if (elHigh) elHigh.innerText = data.high_alerts;
            if (elMedium) elMedium.innerText = data.medium_alerts;
            if (elLow) elLow.innerText = data.low_alerts;
            if (elUsers) elUsers.innerText = data.active_users;

            // Update severity donut chart values
            if (charts.severity) {
                charts.severity.data.datasets[0].data = [
                    data.critical_alerts,
                    data.high_alerts,
                    data.medium_alerts,
                    data.low_alerts
                ];
                charts.severity.update();
            }
        });
}

function incrementDashboardCategories(evt) {
    if (!charts.categories) return;

    const id = evt.event_id;
    let index = 5; // Other

    if (id === 4624 || id === 4625) index = 0; // Logon/Logoff
    else if (id === 4720 || id === 4726 || id === 4723) index = 1; // User Mgmt
    else if (evt.log_name === "System") index = 2; // System Logs
    else if (id === 1102) index = 3; // Audit Cleared
    else if (evt.log_name === "Security") index = 4; // Policy Mods

    charts.categories.data.datasets[0].data[index]++;
    charts.categories.update();
}

// ----------------- MODERN TOAST BUILDER -----------------

function showToastNotification(alert) {
    const container = document.getElementById("siem-toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    const severity = alert.severity.toLowerCase();
    toast.className = `siem-toast ${severity}`;

    let icon = "fa-circle-info";
    if (alert.severity === "Critical") icon = "fa-radiation text-danger";
    else if (alert.severity === "High") icon = "fa-fire-flame-curved text-warning";
    else if (alert.severity === "Medium") icon = "fa-circle-exclamation text-warning";

    toast.innerHTML = `
        <div class="siem-toast-header">
            <div class="siem-toast-title-box">
                <i class="fas ${icon} siem-toast-icon"></i>
                <span class="siem-toast-title">${alert.severity} Incident Raised</span>
            </div>
            <button class="siem-toast-close" onclick="this.parentElement.parentElement.remove()">&times;</button>
        </div>
        <div class="siem-toast-body">
            <strong>${escapeHtml(alert.source)}</strong>: ${escapeHtml(alert.details)}
        </div>
        <div class="siem-toast-footer">
            <span class="siem-toast-mitre">${escapeHtml(alert.mitre_technique || 'T1562')}</span>
            <span class="siem-toast-time">Just now</span>
        </div>
    `;

    container.appendChild(toast);

    // Fade and remove after 6 seconds
    setTimeout(() => {
        if (toast.parentNode) {
            toast.classList.add("fade-out");
            toast.addEventListener("animationend", () => {
                toast.remove();
            });
        }
    }, 6000);
}

// ----------------- SYNTHESIZED AUDIO ALARM CHIME -----------------

function playAlertSound() {
    try {
        const AudioContextClass = window.AudioContext || window.webkitAudioContext;
        if (!AudioContextClass) return;

        const ctx = new AudioContextClass();
        if (ctx.state === "suspended") {
            ctx.resume();
        }

        function beep(time, frequency, duration) {
            const osc = ctx.createOscillator();
            const gain = ctx.createGain();

            osc.type = "sine";
            osc.frequency.setValueAtTime(frequency, time);

            gain.gain.setValueAtTime(0, time);
            gain.gain.linearRampToValueAtTime(0.08, time + 0.02); // Max volume 0.08 (non-intrusive chime)
            gain.gain.exponentialRampToValueAtTime(0.0001, time + duration);

            osc.connect(gain);
            gain.connect(ctx.destination);

            osc.start(time);
            osc.stop(time + duration);
        }

        const now = ctx.currentTime;
        // Premium high-tech double-beep alert chime
        beep(now, 880, 0.12);
        beep(now + 0.10, 1200, 0.20);
    } catch (e) {
        console.warn("Web Audio API warning (usually blocked by browser autoplay rules):", e);
    }
}
