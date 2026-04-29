// --- TAB LOGIC ---
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
        
        btn.classList.add('active');
        document.getElementById(btn.dataset.target).classList.add('active');
        
        // Refresh map if it was hidden
        if(btn.dataset.target === 'tab-live') {
            setTimeout(() => map.invalidateSize(), 100);
        }
    });
});

// --- TOGGLE LIVE MODE ---
const liveToggle = document.getElementById('live-mode-toggle');
if (liveToggle) {
    liveToggle.addEventListener('change', (e) => {
        const enabled = e.target.checked;
        fetch('/api/toggle_live', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({enabled: enabled})
        }).then(res => res.json()).then(data => {
            const modeText = document.getElementById('mode-text');
            if (data.live_mode) {
                modeText.textContent = "LIVE API";
                modeText.style.color = "var(--accent-green)";
                liveToggle.checked = true;
            } else {
                modeText.textContent = "MOCK (Simulated)";
                modeText.style.color = "var(--text-muted)";
                liveToggle.checked = false;
                if (enabled) alert("Live Mode Failed. Missing ABUSEIPDB_KEY or VT_KEY in .env");
            }
        });
    });
}

// --- MAP LOGIC ---
const map = L.map('map', {
    center: [20, 0],
    zoom: 2,
    zoomControl: false,
    attributionControl: false
});

L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
    subdomains: 'abcd',
    maxZoom: 19
}).addTo(map);

// Define Target Server Location (Default to Jacksonville, FL)
let SERVER_LAT = 30.3322;
let SERVER_LON = -81.6557;
let serverMarker = null;

// Fetch client location to make dashboard dynamic per viewer
fetch('https://ipapi.co/json/')
    .then(res => res.json())
    .then(data => {
        if (data.latitude && data.longitude) {
            SERVER_LAT = data.latitude;
            SERVER_LON = data.longitude;
        }
        initServerMarker(data.city || "Jacksonville");
    })
    .catch(() => {
        initServerMarker("Jacksonville"); // fallback
    });

function initServerMarker(cityName) {
    if (serverMarker) map.removeLayer(serverMarker);
    serverMarker = L.circleMarker([SERVER_LAT, SERVER_LON], {
        radius: 8,
        fillColor: "#00ff88",
        color: "#fff",
        weight: 2,
        opacity: 1,
        fillOpacity: 1
    }).bindPopup(`Target Server: ${cityName}`).addTo(map);
}

function drawArc(lat, lon, payload) {
    if (lat && lon) {
        // Draw standard marker
        const marker = L.circleMarker([lat, lon], {
            radius: 5, fillColor: "#ff3366", color: "#fff", weight: 1, opacity: 1, fillOpacity: 0.8
        }).addTo(map);
        marker.bindPopup(`<div style="font-family: monospace; color: #000;">${payload.substring(0, 50)}</div>`);
        
        // Draw curve to server using leaflet.curve
        // Svg path: M (start), Q (control point), (end)
        const latlngs = [
            'M', [lat, lon],
            'Q', [(lat + SERVER_LAT)/2 + 20, (lon + SERVER_LON)/2],
            [SERVER_LAT, SERVER_LON]
        ];
        
        const path = L.curve(latlngs, {
            color: 'rgba(255, 51, 102, 0.6)',
            fill: false,
            weight: 2,
            dashArray: '5, 5',
            animate: {duration: 1500, iterations: 1}
        }).addTo(map);

        setTimeout(() => {
            map.removeLayer(marker);
            map.removeLayer(path);
        }, 15000); // 15 seconds to disappear
    }
}

// --- FEED & STATS LOGIC ---
let lastSeenId = 0;
let mitreCounts = {};

function updateFeed(attacks) {
    const tbody = document.getElementById('attack-feed-body');
    attacks.sort((a, b) => a.id - b.id);

    attacks.forEach(attack => {
        if (attack.id > lastSeenId) {
            lastSeenId = attack.id;
            
            if (attack.latitude && attack.longitude) {
                drawArc(attack.latitude, attack.longitude, attack.payload);
            }
            
            const tr = document.createElement('tr');
            const protoClass = attack.protocol.toLowerCase();
            const protoBadge = `<span class="tag ${protoClass}">${attack.protocol}:${attack.port}</span>`;
            
            const riskClass = attack.risk_score > 60 ? 'risk-high' : 'risk-low';
            const riskBadge = `<span class="tag ${riskClass}">${attack.risk_score} ${attack.threat_label ? `(${attack.threat_label})` : ''}</span>`;
            
            const actionClass = attack.action_taken === "BLOCKED" ? "risk-high" : "risk-low";
            const actionBadge = `<span class="tag ${actionClass}">${attack.action_taken}</span>`;
            
            let payloadText = attack.payload.length > 50 ? attack.payload.substring(0, 50) + '...' : attack.payload;
            if(attack.file_hash) {
                payloadText += `<br><span style="color:var(--text-muted); font-size:0.75rem;">SHA256: ${attack.file_hash}</span>`;
            }

            tr.innerHTML = `
                <td style="white-space: nowrap; color: var(--text-muted);">${attack.timestamp.split(' ')[1]}</td>
                <td style="font-family: var(--font-mono); color: var(--text-primary);">${attack.source_ip}</td>
                <td>${attack.geo_location}</td>
                <td>${riskBadge}</td>
                <td>${actionBadge}</td>
                <td>${protoBadge}</td>
                <td title="${attack.payload}">${payloadText}</td>
            `;
            
            tbody.insertBefore(tr, tbody.firstChild);
            while (tbody.children.length > 50) tbody.removeChild(tbody.lastChild);
            
            if (attack.mitre_tags) {
                attack.mitre_tags.split(',').forEach(tag => {
                    const cleanTag = tag.trim();
                    mitreCounts[cleanTag] = (mitreCounts[cleanTag] || 0) + 1;
                });
            }
        }
    });
    updateMitreSidebar();
}

function updateMitreSidebar() {
    const mitreList = document.getElementById('mitre-list');
    mitreList.innerHTML = '';
    const sorted = Object.entries(mitreCounts).sort((a, b) => b[1] - a[1]).slice(0, 8);
    sorted.forEach(([tag, count]) => {
        const li = document.createElement('li');
        li.style.display = 'flex'; li.style.justifyContent = 'space-between';
        li.style.padding = '8px'; li.style.background = 'rgba(255,255,255,0.02)'; li.style.borderRadius = '4px'; li.style.fontSize = '0.8rem';
        li.innerHTML = `<span style="color: var(--text-primary);">${tag}</span><span style="color: var(--accent-red); font-weight: bold;">${count}</span>`;
        mitreList.appendChild(li);
    });
}

// --- SESSIONS LOGIC ---
function loadSessions() {
    fetch('/api/sessions').then(res => res.json()).then(data => {
        const tbody = document.getElementById('sessions-list-body');
        tbody.innerHTML = '';
        data.forEach(s => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td style="font-family: var(--font-mono); color: var(--accent-blue);">${s.source_ip}</td>
                <td>${s.cmd_count} cmds</td>
                <td style="color: var(--text-muted);">${s.start_time}</td>
                <td><button class="btn replay-btn" data-cmds='${JSON.stringify(s.commands).replace(/'/g, "&apos;")}'>Replay</button></td>
            `;
            tbody.appendChild(tr);
        });
        
        document.querySelectorAll('.replay-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const cmds = JSON.parse(e.target.dataset.cmds);
                playTerminal(cmds);
            });
        });
    });
}

function playTerminal(commands) {
    const term = document.getElementById('terminal-replay');
    term.innerHTML = 'root@server:~# ';
    let i = 0;
    
    function typeCommand() {
        if(i >= commands.length) return;
        
        term.innerHTML += `<span class="terminal-cmd">${commands[i]}</span><br>`;
        // Simulate response delay
        setTimeout(() => {
            term.innerHTML += `bash: command not found<br>root@server:~# `;
            term.scrollTop = term.scrollHeight;
            i++;
            setTimeout(typeCommand, 800); // 800ms between commands
        }, 500);
    }
    
    typeCommand();
}

// --- CHART.JS LOGIC ---
let analyticsChart = null;
function initChart() {
    fetch('/api/analytics').then(res => res.json()).then(data => {
        const ctx = document.getElementById('analyticsChart').getContext('2d');
        if(analyticsChart) analyticsChart.destroy();
        
        analyticsChart = new Chart(ctx, {
            type: 'line',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } },
                    x: { grid: { color: 'rgba(255,255,255,0.05)' } }
                },
                plugins: {
                    legend: { labels: { color: '#f0f0f5' } }
                }
            }
        });
    });
}

// --- POLLING ---
function fetchAttacks() {
    fetch('/api/attacks').then(res => res.json()).then(data => updateFeed(data));
    fetch('/api/stats').then(res => res.json()).then(data => {
        document.getElementById('total-attacks-counter').textContent = data.total_attacks.toLocaleString();
        const ipList = document.getElementById('top-ips-list');
        ipList.innerHTML = '';
        data.top_ips.forEach(item => {
            ipList.innerHTML += `<li><span class="ip-addr" style="font-family:monospace; color:#33aaff;">${item.ip}</span><span class="hit-count">${item.count} hits</span></li>`;
        });
    });
}

fetchAttacks();
initChart();
loadSessions();

setInterval(() => {
    fetchAttacks();
}, 3000);

// Load sessions and chart every 10 seconds
setInterval(() => {
    loadSessions();
    if(document.getElementById('tab-analytics').classList.contains('active')){
        initChart();
    }
}, 10000);
