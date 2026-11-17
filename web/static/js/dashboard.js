/**
 * Real-Time SOC Dashboard Controller for Intelligent NIDS.
 * Manages Chart.js visualizers, live polling, and threat feed animations.
 */

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    pollData();
    setInterval(pollData, 1200); // Poll telemetry every 1.2s
});

let trafficChart = null;
let protoChart = null;
let attackersChart = null;

const MAX_TIME_POINTS = 25;
const chartLabels = [];
const ppsData = [];

function initCharts() {
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = "'Inter', sans-serif";

    // 1. Real-Time Traffic Velocity Line Chart
    const ctxTraffic = document.getElementById('trafficChart').getContext('2d');
    trafficChart = new Chart(ctxTraffic, {
        type: 'line',
        data: {
            labels: chartLabels,
            datasets: [{
                label: 'Packets / Second',
                data: ppsData,
                borderColor: '#38bdf8',
                backgroundColor: 'rgba(56, 189, 248, 0.1)',
                fill: true,
                tension: 0.35,
                borderWidth: 2,
                pointRadius: 2,
                pointHoverRadius: 5,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: { color: 'rgba(51, 65, 85, 0.4)' },
                    ticks: { maxTicksLimit: 8 }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(51, 65, 85, 0.4)' },
                    suggestedMax: 10
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });

    // 2. Protocol Distribution Doughnut Chart
    const ctxProto = document.getElementById('protoChart').getContext('2d');
    protoChart = new Chart(ctxProto, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'ARP', 'OTHER'],
            datasets: [{
                data: [0, 0, 0, 0, 0],
                backgroundColor: ['#38bdf8', '#6366f1', '#f59e0b', '#10b981', '#64748b'],
                borderColor: '#111827',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 12, padding: 14 } }
            },
            cutout: '65%'
        }
    });

    // 3. Top Threat Sources Bar Chart
    const ctxAttackers = document.getElementById('attackersChart').getContext('2d');
    attackersChart = new Chart(ctxAttackers, {
        type: 'bar',
        data: {
            labels: ['None'],
            datasets: [{
                label: 'Incidents Detected',
                data: [0],
                backgroundColor: 'rgba(239, 68, 68, 0.8)',
                borderColor: '#ef4444',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    grid: { color: 'rgba(51, 65, 85, 0.4)' }
                },
                y: {
                    grid: { display: false }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

async function pollData() {
    try {
        // 1. Fetch Realtime Telemetry
        const statsRes = await fetch('/api/stats/realtime');
        const stats = await statsRes.json();

        if (stats.success) {
            updateMetrics(stats);
            updateTrafficChart(stats.current_pps);
            updateProtoChart(stats.protocol_distribution);
        }

        // 2. Fetch Alerts Summary for Threat Sources Chart
        const summaryRes = await fetch('/api/alerts/summary');
        const summary = await summaryRes.json();
        if (summary.success && summary.statistics) {
            updateAttackersChart(summary.statistics.top_attackers);
        }

        // 3. Fetch Live Alert Feed (latest 5)
        const alertsRes = await fetch('/api/alerts?limit=5');
        const alertsData = await alertsRes.json();
        if (alertsData.success) {
            updateAlertsFeed(alertsData.alerts);
        }

    } catch (err) {
        console.debug("Telemetry poll error:", err);
    }
}

function updateMetrics(stats) {
    document.getElementById('metric-pps').textContent = stats.current_pps.toFixed(1);
    document.getElementById('metric-total-pkts').textContent = stats.total_packets.toLocaleString();

    const kb = (stats.total_bytes / 1024).toFixed(1);
    document.getElementById('metric-total-bytes').textContent = `${kb} KB processed`;

    document.getElementById('metric-total-alerts').textContent = stats.total_alerts;

    const crit = (stats.alerts_severity && stats.alerts_severity.CRITICAL) || 0;
    document.getElementById('metric-critical-alerts').textContent = crit;
}

function updateTrafficChart(pps) {
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];

    chartLabels.push(timeStr);
    ppsData.push(pps);

    if (chartLabels.length > MAX_TIME_POINTS) {
        chartLabels.shift();
        ppsData.shift();
    }

    trafficChart.update('none'); // Update without full layout animation for smooth flow
}

function updateProtoChart(dist) {
    if (!dist) return;

    protoChart.data.datasets[0].data = [
        dist.TCP || 0,
        dist.UDP || 0,
        (dist.ICMP || 0) + (dist.ICMPv6 || 0),
        dist.ARP || 0,
        dist.OTHER || 0
    ];
    protoChart.update();
}

function updateAttackersChart(topAttackers) {
    if (!topAttackers || topAttackers.length === 0) {
        attackersChart.data.labels = ['No Active Threats'];
        attackersChart.data.datasets[0].data = [0];
    } else {
        attackersChart.data.labels = topAttackers.map(a => a.source_ip);
        attackersChart.data.datasets[0].data = topAttackers.map(a => a.incident_count);
    }
    attackersChart.update();
}

function updateAlertsFeed(alerts) {
    const ticker = document.getElementById('alerts-ticker');

    if (!alerts || alerts.length === 0) {
        ticker.innerHTML = `
            <p style="text-align: center; color: var(--text-muted); font-size: 13px; padding-top: 30px;">
                No security incidents detected. System is secure.
            </p>
        `;
        return;
    }

    ticker.innerHTML = alerts.map(a => {
        const sevClass = a.severity.toLowerCase();
        return `
            <div class="alert-item ${sevClass}">
                <div class="alert-info">
                    <h4>
                        <span class="badge badge-${sevClass}">${a.severity}</span>
                        <span>${a.attack_type}</span>
                    </h4>
                    <p>
                        <code>${a.source_ip}:${a.source_port || ''}</code> &rarr; 
                        <code>${a.destination_ip}:${a.destination_port || ''}</code> &bull; 
                        <strong>${a.packet_count} packets</strong>
                    </p>
                </div>
                <div class="alert-meta">
                    <div>${a.timestamp.split(' ')[1] || a.timestamp}</div>
                    <span class="badge" style="background-color: var(--bg-surface); margin-top: 4px;">${a.status}</span>
                </div>
            </div>
        `;
    }).join('');
}
