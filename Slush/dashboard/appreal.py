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

# Session scoping — unchanged from the working version. Every KPI/chart/feed row is
# scoped to "since this dashboard process started", matching what the UI labels them
# ("Total Alerts (session)"), instead of the entire lifetime of alerts.jsonl.
SESSION_START = time.time()

MAX_FEED_ROWS = 50
ACTIVE_WINDOW_SECONDS = 60          # "Active Alerts" = alerts in the last minute
ENCLAVE_ALIVE_WINDOW_SECONDS = 15   # widened past controller.py's 5s POLL_INTERVAL so
                                     # scheduling jitter doesn't flicker LIVE -> IDLE
#TIMELINE_WINDOW_SECONDS = 600       # 10-minute alert timeline
TIMELINE_BUCKET_SECONDS = 30        # bucketed into 30s slices -> 20 points
TIMELINE_MAX_BUCKETS = 1440

# ---------------------------------------------------------------------------
# Single source of truth for the attack taxonomy. Previously this lived twice
# (once as Python keyword-matching rules, once as three parallel JS objects
# keyed by hand-picked codes) and the two could drift apart silently. Now it's
# defined once, here, and shipped to the frontend via /api/meta on load.
#
# `implemented: True`  -> threat_class values controller.py actually raises today
#                          (see PassiveThreatController.LABEL_MAP / _raise_alert
#                          call sites: dga_dns, dns_tunnel, recon_scan, c2_beacon,
#                          ddos, exfiltration).
# `implemented: False` -> reserved slot for a detector that doesn't exist yet.
#                          Always rendered in the breakdown chart, always at zero,
#                          greyed out and labeled "not wired up yet". Flip this
#                          flag once the detector ships and it lights up with zero
#                          other changes anywhere in this file.
#
# To add a new attack class later: add one entry here. Nothing else to touch.
# ---------------------------------------------------------------------------
ATTACK_META = {
    "ddos":               {"label": "DDoS",            "color": "#ef4444", "icon": "\U0001F30A", "implemented": True},
    "exfiltration":       {"label": "Exfiltration",     "color": "#a855f7", "icon": "\U0001F4E4", "implemented": True},
    "recon_scan":         {"label": "Recon Scan",       "color": "#f59e0b", "icon": "\U0001F50D", "implemented": True},
    "dns_tunnel":         {"label": "DNS Tunneling",    "color": "#14b8a6", "icon": "\U0001F573\uFE0F", "implemented": True},
    "dga_dns":            {"label": "DGA DNS",          "color": "#eab308", "icon": "\U0001F3B2", "implemented": True},
    "c2_beacon":          {"label": "C2 Beaconing",     "color": "#22d3ee", "icon": "\U0001F4E1", "implemented": True},
    # Not yet implemented in controller.py — reserved slots.
    "slowloris":          {"label": "Slowloris",        "color": "#94a3b8", "icon": "\U0001F40C", "implemented": False},
    "encrypted_malware":  {"label": "Encrypted Malware","color": "#94a3b8", "icon": "\U0001F9A0", "implemented": False},
    # Catch-all for anything that doesn't match a known threat_class.
    "unknown":            {"label": "Unknown",          "color": "#64748b", "icon": "\u2753", "implemented": True},
}


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


def classify(threat_class):
    """Map a raw threat_class string from alerts.jsonl onto an ATTACK_META key.
    Falls back to 'unknown' for anything not in the taxonomy rather than
    dropping the alert."""
    key = str(threat_class or "").strip().lower()
    if key in ATTACK_META:
        return key
    return "unknown"


def build_dashboard_data():
    all_alerts = read_jsonl(ALERTS_PATH)
    now = time.time()

    alerts = [a for a in all_alerts if a.get("timestamp", 0) >= SESSION_START]

    active_alerts = [a for a in alerts if now - a.get("timestamp", 0) <= ACTIVE_WINDOW_SECONDS]
    critical_alerts = [a for a in alerts if str(a.get("severity", "")).lower() == "critical"]

    threat_mix = Counter(classify(a.get("threat_class")) for a in alerts)
    severity_mix = Counter(str(a.get("severity", "unknown")).upper() for a in alerts)

    dominant_attack = None
    if threat_mix:
        top_code, top_count = threat_mix.most_common(1)[0]
        if top_count > 0:
            dominant_attack = top_code

    # Alert timeline: full-session history in fixed 30s buckets, anchored to
    # SESSION_START instead of "now" — buckets accumulate for the life of the
    # session instead of scrolling out of a fixed rolling window, so an attack
    # from 15 minutes ago stays visible instead of disappearing off the chart.
    elapsed = max(0.0, now - SESSION_START)
    n_buckets = min(TIMELINE_MAX_BUCKETS, int(elapsed // TIMELINE_BUCKET_SECONDS) + 1)
    bucket_totals = [0] * n_buckets
    bucket_critical = [0] * n_buckets
    bucket_breakdown = [Counter() for _ in range(n_buckets)]

    for a in alerts:
        offset = a.get("timestamp", 0) - SESSION_START
        if offset < 0:
            continue
        idx = int(offset // TIMELINE_BUCKET_SECONDS)
        idx = max(0, min(idx, n_buckets - 1))
        bucket_totals[idx] += 1
        bucket_breakdown[idx][classify(a.get("threat_class"))] += 1
        if str(a.get("severity", "")).lower() == "critical":
            bucket_critical[idx] += 1

    timeline_labels = []
    for i in range(n_buckets):
        bucket_time = SESSION_START + i * TIMELINE_BUCKET_SECONDS
        timeline_labels.append(datetime.fromtimestamp(bucket_time).strftime("%H:%M:%S"))

    feed_source = sorted(alerts, key=lambda a: a.get("timestamp", 0), reverse=True)[:MAX_FEED_ROWS]
    feed = []
    for a in feed_source:
        ts = a.get("timestamp", 0)
        feed.append({
            "time": datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "N/A",
            "src_ip": a.get("src_ip", "N/A"),
            "dst_ip": a.get("dst_ip", "N/A"),
            "threat_class": a.get("threat_class", "unknown"),
            "attack_type": classify(a.get("threat_class")),
            "confidence": f"{float(a.get('confidence', 0)):.2f}",
            "severity": str(a.get("severity", "low")).upper(),
        })

    return {
        "kpis": {
            "total_alerts": len(alerts),
            "active_alerts": len(active_alerts),
            "critical_alerts": len(critical_alerts),
            "dominant_attack": dominant_attack,
            "enclave_active": enclave_is_active(),
        },
        "threat_mix": dict(threat_mix),
        "severity_mix": dict(severity_mix),
        "timeline": {
            "labels": timeline_labels,
            "totals": bucket_totals,
            "critical": bucket_critical,
            "breakdown": [dict(b) for b in bucket_breakdown],
        },
        "feed": feed,
    }


# Inline SVG so the dashboard stays a single self-contained file — pink badge, white
# to-go cup, purple slush swirl + drip, matching the SLUSH logo.
LOGO_SVG = """
<svg width="40" height="40" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <circle cx="50" cy="50" r="48" fill="#EC1279"/>
  <path d="M40 30 L60 30 L57 46 L43 46 Z" fill="#FFFFFF" stroke="#111827" stroke-width="2.2" stroke-linejoin="round"/>
  <rect x="41" y="46" width="18" height="9" fill="#FFFFFF" stroke="#111827" stroke-width="2.2"/>
  <path d="M43 55 L57 55 L53 80 L47 80 Z" fill="#FFFFFF" stroke="#111827" stroke-width="2.2" stroke-linejoin="round"/>
  <path d="M39 30 Q50 20 61 30 Q60 35 55 37 Q50 39 45 37 Q40 35 39 30 Z" fill="#9333EA" stroke="#111827" stroke-width="2.2" stroke-linejoin="round"/>
  <path d="M58 34 Q61 40 57 44 Q54 47 56 51" fill="none" stroke="#9333EA" stroke-width="3" stroke-linecap="round"/>
</svg>
"""

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
        .custom-scroll { scrollbar-width: thin; scrollbar-color: #334155 transparent; }
    </style>
</head>
<body class="bg-[#0B1021] text-white font-sans p-6 min-h-screen">
    <header class="flex justify-between items-center pb-4 mb-6 border-b border-slate-800">
        <div class="flex items-center gap-3">
            """ + LOGO_SVG + """
            <div>
                <h1 class="text-lg font-semibold">SLUSH — Passive Threat Intelligence Dashboard</h1>
                <p class="text-xs text-slate-500 mt-0.5">Read-only enclave · no mitigation path · alerts only</p>
            </div>
        </div>
        <div class="flex items-center gap-2">
            <span id="live-label" class="text-xs font-bold text-slate-400">CHECKING...</span>
            <div id="live-dot" class="w-3 h-3 rounded-full bg-slate-600"></div>
        </div>
    </header>

    <!-- KPIs -->
    <div class="grid grid-cols-5 gap-4 mb-6">
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
            <div class="text-xs text-slate-400">Dominant Attack</div>
            <div id="kpi-dominant" class="text-2xl font-bold mt-1">—</div>
        </div>
        <div class="bg-[#131A32] p-4 rounded-lg border border-slate-800">
            <div class="text-xs text-slate-400">Enclave Status</div>
            <div id="kpi-status" class="text-2xl font-bold mt-1 text-slate-400">—</div>
        </div>
    </div>

    <!-- Attack Activity Timeline (hover for a breakdown at that moment) -->
    <div class="bg-[#131A32] p-5 rounded-lg border border-slate-800 mb-6">
        <div class="flex items-center justify-between mb-3">
            <h2 class="text-base font-medium">Attack Activity (10 min)</h2>
            <span class="text-xs text-slate-500">hover to inspect a moment in time</span>
        </div>
        <div style="height: 200px;">
            <canvas id="timelineChart"></canvas>
        </div>
    </div>

    <!-- Main layout -->
    <div class="flex gap-6">
        <!-- Live Alert Feed -->
        <div class="flex-1 bg-[#131A32] p-5 rounded-lg border border-slate-800">
            <h2 class="text-base font-medium mb-4">Live Alert Feed</h2>
            <div class="overflow-y-auto max-h-[480px] custom-scroll">
                <table class="w-full text-left text-sm">
                    <thead class="sticky top-0 bg-[#131A32]">
                        <tr class="text-slate-400 border-b border-slate-800">
                            <th class="pb-2">TIME</th>
                            <th class="pb-2">SRC IP</th>
                            <th class="pb-2">DST IP</th>
                            <th class="pb-2">ATTACK TYPE</th>
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
                <div class="flex items-center justify-between mb-3">
                    <h3 class="text-sm font-medium">Attack Type Breakdown</h3>
                    <span class="text-[10px] text-slate-500">greyed = not wired up yet</span>
                </div>
                <canvas id="attackTypeChart" height="180"></canvas>
            </div>
            <div class="bg-[#131A32] p-5 rounded-lg border border-slate-800 text-xs space-y-2">
                <div class="flex justify-between">
                    <span class="text-slate-400">Detection</span>
                    <span class="font-semibold text-right">Adaptive gate + Random Forest + rule-based detectors</span>
                </div>
                <div class="flex justify-between">
                    <span class="text-slate-400">Throughput benchmark</span>
                    <span class="font-semibold text-slate-500">not yet run</span>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Attack taxonomy is fetched once from /api/meta rather than duplicated
        // in JS — this IS the ATTACK_META dict from app.py, serialized.
        let ATTACK_META = {};

        function metaFor(code) {
            return ATTACK_META[code] || { label: code, color: '#64748b', icon: '\u2753', implemented: true };
        }

        function severityBadge(sev) {
            const colors = {
                'CRITICAL': 'bg-red-600', 'HIGH': 'bg-amber-600',
                'MEDIUM': 'bg-yellow-700', 'LOW': 'bg-emerald-600'
            };
            return `<span class="${colors[sev] || 'bg-slate-600'} text-white text-xs px-2 py-0.5 rounded font-bold">${sev}</span>`;
        }

        function attackBadge(code) {
            const m = metaFor(code);
            const dimmed = m.implemented ? '' : 'opacity-50';
            return `<span class="inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-0.5 rounded ${dimmed}" style="background:${m.color}22; color:${m.color};">
                <span>${m.icon}</span>${m.label}
            </span>`;
        }

        // Vertical crosshair line that tracks the hovered point on the timeline.
        const crosshairPlugin = {
            id: 'crosshair',
            afterDraw(chart) {
                const active = chart.tooltip && chart.tooltip._active;
                if (active && active.length) {
                    const x = active[0].element.x;
                    const { top, bottom } = chart.scales.y;
                    const ctx = chart.ctx;
                    ctx.save();
                    ctx.beginPath();
                    ctx.moveTo(x, top);
                    ctx.lineTo(x, bottom);
                    ctx.lineWidth = 1;
                    ctx.setLineDash([4, 4]);
                    ctx.strokeStyle = 'rgba(239, 68, 68, 0.6)';
                    ctx.stroke();
                    ctx.restore();
                }
            }
        };

        let timelineChart, attackTypeChart, lastTimeline = null;

        function initCharts() {
            const timelineCtx = document.getElementById('timelineChart').getContext('2d');
            timelineChart = new Chart(timelineCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Alerts',
                        data: [],
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.12)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true,
                        pointRadius: [],
                        pointBackgroundColor: [],
                        pointHoverRadius: 6
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    interaction: { mode: 'index', intersect: false },
                    scales: {
                        x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b', maxRotation: 0, autoSkip: true, maxTicksLimit: 8 } },
                        y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b', precision: 0 } }
                    },
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: '#0B1021', borderColor: '#1e293b', borderWidth: 1, padding: 10,
                            titleColor: '#e2e8f0', bodyColor: '#cbd5e1',
                            callbacks: {
                                title: (items) => `Time  ${items[0].label}`,
                                label: (item) => `Alerts: ${item.formattedValue}`,
                                afterBody: (items) => {
                                    if (!lastTimeline) return [];
                                    const idx = items[0].dataIndex;
                                    const lines = [];
                                    const crit = lastTimeline.critical[idx];
                                    if (crit > 0) lines.push(`Critical: ${crit}`);
                                    const breakdown = lastTimeline.breakdown[idx] || {};
                                    Object.entries(breakdown)
                                        .sort((a, b) => b[1] - a[1])
                                        .forEach(([code, count]) => lines.push(`${metaFor(code).label}: ${count}`));
                                    return lines;
                                }
                            }
                        }
                    }
                },
                plugins: [crosshairPlugin]
            });

            const attackTypeCtx = document.getElementById('attackTypeChart').getContext('2d');
            attackTypeChart = new Chart(attackTypeCtx, {
                type: 'bar',
                data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    plugins: {
                        legend: { display: false },
                        tooltip: {
                            backgroundColor: '#0B1021', borderColor: '#1e293b', borderWidth: 1,
                            callbacks: {
                                afterLabel: (item) => {
                                    const code = attackTypeChart._codes[item.dataIndex];
                                    return metaFor(code).implemented ? '' : '(not wired up yet)';
                                }
                            }
                        }
                    },
                    scales: {
                        x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b', precision: 0 } },
                        y: { grid: { display: false }, ticks: { color: '#94a3b8', font: { size: 11 } } }
                    }
                }
            });
        }

        function updateTimelineChart(timeline) {
            lastTimeline = timeline;
            timelineChart.data.labels = timeline.labels;
            timelineChart.data.datasets[0].data = timeline.totals;
            timelineChart.data.datasets[0].pointRadius = timeline.critical.map(c => c > 0 ? 5 : 2);
            timelineChart.data.datasets[0].pointBackgroundColor = timeline.critical.map(c => c > 0 ? '#ef4444' : '#38bdf8');
            timelineChart.update();
        }

        function updateAttackTypeChart(threatMix) {
            // Every known attack code always appears — implemented ones show real
            // counts, reserved (not-yet-implemented) ones always render at zero,
            // greyed out via reduced opacity on their bar color.
            const codes = Object.keys(ATTACK_META).filter(c => c !== 'unknown');
            const counts = codes.map(c => threatMix[c] || 0);
            const colors = codes.map(c => {
                const m = metaFor(c);
                return m.implemented ? m.color : (m.color + '55');
            });
            attackTypeChart.data.labels = codes.map(c => metaFor(c).label + (metaFor(c).implemented ? '' : ' •'));
            attackTypeChart.data.datasets[0].data = counts;
            attackTypeChart.data.datasets[0].backgroundColor = colors;
            attackTypeChart._codes = codes;
            attackTypeChart.update();
        }

        function updateDominantAttack(code) {
            const el = document.getElementById('kpi-dominant');
            if (code) {
                const m = metaFor(code);
                el.textContent = m.icon + ' ' + m.label;
                el.style.color = m.color;
            } else {
                el.textContent = '—';
                el.style.color = '';
            }
        }

        async function loadMeta() {
            const res = await fetch('/api/meta');
            ATTACK_META = await res.json();
        }

        async function refresh() {
            const res = await fetch('/api/dashboard');
            const data = await res.json();

            document.getElementById('kpi-total').innerText = data.kpis.total_alerts;
            document.getElementById('kpi-active').innerText = data.kpis.active_alerts;
            document.getElementById('kpi-critical').innerText = data.kpis.critical_alerts;
            updateDominantAttack(data.kpis.dominant_attack);

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
                        <td>${attackBadge(r.attack_type)}</td>
                        <td>${r.confidence}</td>
                        <td>${severityBadge(r.severity)}</td>
                    </tr>
                `).join('');
            }

            updateTimelineChart(data.timeline);
            updateAttackTypeChart(data.threat_mix);
        }

        (async function start() {
            await loadMeta();
            initCharts();
            refresh();
            setInterval(refresh, 1500);
        })();
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


@app.route("/api/meta")
def api_meta():
    return jsonify(ATTACK_META)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
