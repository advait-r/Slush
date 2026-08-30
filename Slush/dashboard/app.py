import json
import os
import time
from collections import Counter
from datetime import datetime

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ALERTS_PATH = os.path.join(REPO_ROOT, "alerts.jsonl")
ACTIVITY_PATH = os.path.join(REPO_ROOT, "activity.jsonl")

MAX_FEED_ROWS = 50
ACTIVE_WINDOW_SECONDS = 60          # "Active Alerts" = alerts in the last minute
ENCLAVE_ALIVE_WINDOW_SECONDS = 5    # LIVE dot goes gray if no activity ping in this long
TIMELINE_WINDOW_SECONDS = 600       # 10-minute alert timeline
TIMELINE_BUCKET_SECONDS = 30        # bucketed into 30s slices -> 20 points


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def enclave_is_active():
    """True if the passive ingest pipeline has pinged activity.jsonl recently —
    i.e. it's actually observing live traffic right now, not just running."""
    rows = read_jsonl(ACTIVITY_PATH)
    if not rows:
        return False
    last_ts = rows[-1].get("timestamp", 0)
    return (time.time() - last_ts) < ENCLAVE_ALIVE_WINDOW_SECONDS


def build_dashboard_data():
    alerts = read_jsonl(ALERTS_PATH)
    now = time.time()

    active_alerts = [a for a in alerts if now - a.get("timestamp", 0) <= ACTIVE_WINDOW_SECONDS]
    critical_alerts = [a for a in alerts if str(a.get("severity", "")).lower() == "critical"]

    threat_mix = Counter(a.get("threat_class", "unknown") for a in alerts)
    severity_mix = Counter(str(a.get("severity", "unknown")).upper() for a in alerts)

    # Alert timeline: how many alerts landed in each 30s bucket over the last 10 minutes.
    # This is real activity from your own alert log — NOT a flows/sec measurement, which
    # needs bench/throughput_test.py to produce honestly.
    n_buckets = TIMELINE_WINDOW_SECONDS // TIMELINE_BUCKET_SECONDS
    buckets = [0] * n_buckets
    for a in alerts:
        age = now - a.get("timestamp", 0)
        if 0 <= age <= TIMELINE_WINDOW_SECONDS:
            idx = n_buckets - 1 - int(age // TIMELINE_BUCKET_SECONDS)
            idx = max(0, min(idx, n_buckets - 1))
            buckets[idx] += 1

    feed_source = sorted(alerts, key=lambda a: a.get("timestamp", 0), reverse=True)[:MAX_FEED_ROWS]
    feed = []
    for a in feed_source:
        ts = a.get("timestamp", 0)
        feed.append({
            "time": datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "N/A",
            "src_ip": a.get("src_ip", "N/A"),
            "dst_ip": a.get("dst_ip", "N/A"),
            "threat_class": a.get("threat_class", "unknown"),
            "confidence": f"{float(a.get('confidence', 0)):.2f}",
            "severity": str(a.get("severity", "low")).upper(),
        })

    return {
        "kpis": {
            "total_alerts": len(alerts),
            "active_alerts": len(active_alerts),
            "critical_alerts": len(critical_alerts),
            "enclave_active": enclave_is_active(),
        },
        "threat_mix": dict(threat_mix),
        "severity_mix": dict(severity_mix),
        "timeline": buckets,
        "feed": feed,
    }


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <title>Passive Threat Intelligence Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background: #0B1021; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-thumb { background: #2A3355; border-radius: 4px; }
    </style>
</head>
<body class="bg-[#0B1021] text-white font-sans p-6 min-h-screen">
    <header class="flex justify-between items-center pb-4 mb-6 border-b border-slate-800">
        <div>
            <h1 class="text-lg font-semibold">SLUSH — Passive Threat Intelligence Dashboard</h1>
            <p class="text-xs text-slate-500 mt-0.5">Read-only enclave · no mitigation path · alerts only</p>
        </div>
        <div class="flex items-center gap-2">
            <span id="live-label" class="text-xs font-bold text-slate-400">CHECKING...</span>
            <div id="live-dot" class="w-3 h-3 rounded-full bg-slate-600"></div>
        </div>
    </header>

    <!-- KPIs -->
    <div class="grid grid-cols-4 gap-4 mb-6">
        <div class="bg-[#131A32] p-4 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400">Total Alerts (session)</div>
            <div id="kpi-total" class="text-2xl font-bold mt-1">0</div>
        </div>
        <div class="bg-[#131A32] p-4 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400">Active (last 60s)</div>
            <div id="kpi-active" class="text-2xl font-bold mt-1">0</div>
        </div>
        <div class="bg-[#131A32] p-4 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400">Critical Alerts</div>
            <div id="kpi-critical" class="text-2xl font-bold text-red-500 mt-1">0</div>
        </div>
        <div class="bg-[#131A32] p-4 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400">Enclave Status</div>
            <div id="kpi-status" class="text-2xl font-bold mt-1 text-slate-400">—</div>
        </div>
    </div>

    <!-- Main layout -->
    <div class="flex gap-6">
        <!-- Live Alert Feed -->
        <div class="flex-1 bg-[#131A32] p-5 rounded-lg border border-slate-800">
            <h2 class="text-base font-medium mb-4">Live Alert Feed</h2>
            <div class="overflow-y-auto max-h-[520px]">
                <table class="w-full text-left text-sm">
                    <thead class="sticky top-0 bg-[#131A32]">
                        <tr class="text-slate-400 border-b border-slate-800">
                            <th class="pb-2">TIME</th>
                            <th class="pb-2">SRC IP</th>
                            <th class="pb-2">DST IP</th>
                            <th class="pb-2">THREAT CLASS</th>
                            <th class="pb-2">CONF.</th>
                            <th class="pb-2">SEVERITY</th>
                        </tr>
                    </thead>
                    <tbody id="logs-body"></tbody>
                </table>
                <div id="empty-state" class="hidden text-center text-slate-500 text-sm py-10">
                    No alerts yet — monitoring active.
                </div>
            </div>
        </div>

        <!-- Sidebar -->
        <div class="w-96 flex flex-col gap-6">
            <div class="bg-[#131A32] p-5 rounded-lg border border-slate-800">
                <h3 class="text-sm font-medium mb-3">Threat Mix</h3>
                <canvas id="threatChart" height="160"></canvas>
            </div>
            <div class="bg-[#131A32] p-5 rounded-lg border border-slate-800">
                <h3 class="text-sm font-medium mb-3">Alerts over Time (10 min)</h3>
                <canvas id="timelineChart" height="140"></canvas>
            </div>
            <div class="bg-[#131A32] p-5 rounded-lg border border-slate-800 text-xs space-y-2">
                <div class="flex justify-between">
                    <span class="text-slate-400">Detection</span>
                    <span class="font-semibold">Adaptive gate + Random Forest + rule-based detectors</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-slate-400">Throughput benchmark</span>
                    <span class="font-semibold text-slate-500">not yet run</span>
                </div>
            </div>
        </div>
    </div>

    <script>
        const SEVERITY_COLORS = {
            'CRITICAL': 'bg-red-600',
            'HIGH': 'bg-amber-600',
            'MEDIUM': 'bg-yellow-700',
            'LOW': 'bg-emerald-600'
        };
        const THREAT_COLORS = {
            'ddos': '#ef4444',
            'recon_scan': '#f59e0b',
            'exfiltration': '#a855f7',
            'dns_tunnel': '#14b8a6',
            'dga_dns': '#eab308',
            'c2_beacon': '#64748b',
            'encrypted_malware': '#3b82f6',
        };

        function badge(sev) {
            return `<span class="${SEVERITY_COLORS[sev] || 'bg-slate-600'} text-white text-xs px-2 py-0.5 rounded font-bold">${sev}</span>`;
        }

        const threatCtx = document.getElementById('threatChart').getContext('2d');
        const threatChart = new Chart(threatCtx, {
            type: 'bar',
            data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
            options: {
                indexAxis: 'y',
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#94a3b8' }, grid: { color: '#1e293b' } },
                    y: { ticks: { color: '#94a3b8' }, grid: { display: false } }
                }
            }
        });

        const timelineCtx = document.getElementById('timelineChart').getContext('2d');
        const timelineChart = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: Array.from({length: 20}, (_, i) => `${(20 - i) * 30}s`),
                datasets: [{
                    data: [],
                    borderColor: '#14b8a6',
                    backgroundColor: 'rgba(20,184,166,0.15)',
                    fill: true,
                    tension: 0.35,
                    pointRadius: 0,
                }]
            },
            options: {
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#64748b', maxTicksLimit: 6 }, grid: { display: false } },
                    y: { ticks: { color: '#94a3b8', precision: 0 }, grid: { color: '#1e293b' }, beginAtZero: true }
                }
            }
        });

        async function refresh() {
            const res = await fetch('/api/dashboard');
            const data = await res.json();

            document.getElementById('kpi-total').innerText = data.kpis.total_alerts;
            document.getElementById('kpi-active').innerText = data.kpis.active_alerts;
            document.getElementById('kpi-critical').innerText = data.kpis.critical_alerts;

            const statusEl = document.getElementById('kpi-status');
            const dotEl = document.getElementById('live-dot');
            const labelEl = document.getElementById('live-label');
            if (data.kpis.enclave_active) {
                statusEl.innerText = 'ACTIVE';
                statusEl.className = 'text-2xl font-bold mt-1 text-emerald-500';
                dotEl.className = 'w-3 h-3 rounded-full bg-emerald-500 animate-pulse';
                labelEl.innerText = 'LIVE';
            } else {
                statusEl.innerText = 'IDLE';
                statusEl.className = 'text-2xl font-bold mt-1 text-slate-500';
                dotEl.className = 'w-3 h-3 rounded-full bg-slate-600';
                labelEl.innerText = 'IDLE';
            }

            const tbody = document.getElementById('logs-body');
            const emptyState = document.getElementById('empty-state');
            if (data.feed.length === 0) {
                tbody.innerHTML = '';
                emptyState.classList.remove('hidden');
            } else {
                emptyState.classList.add('hidden');
                tbody.innerHTML = data.feed.map(r => `
                    <tr class="border-b border-slate-800/50">
                        <td class="py-2.5">${r.time}</td>
                        <td>${r.src_ip}</td>
                        <td>${r.dst_ip}</td>
                        <td>${r.threat_class}</td>
                        <td>${r.confidence}</td>
                        <td>${badge(r.severity)}</td>
                    </tr>
                `).join('');
            }

            const threatLabels = Object.keys(data.threat_mix);
            threatChart.data.labels = threatLabels;
            threatChart.data.datasets[0].data = threatLabels.map(k => data.threat_mix[k]);
            threatChart.data.datasets[0].backgroundColor = threatLabels.map(k => THREAT_COLORS[k] || '#64748b');
            threatChart.update();

            timelineChart.data.datasets[0].data = data.timeline;
            timelineChart.update();
        }

        setInterval(refresh, 1500);
        refresh();
    </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/api/dashboard")
def api_dashboard():
    return jsonify(build_dashboard_data())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
