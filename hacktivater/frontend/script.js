const API_URL = 'http://localhost:5000';

async function analyzeIP() {
    const ipInput = document.getElementById('ipInput');
    const ip = ipInput.value.trim();
    
    if (!isValidIP(ip)) {
        showError('Please enter a valid IP address');
        return;
    }
    
    document.getElementById('loading').classList.remove('hidden');
    document.getElementById('results').classList.add('hidden');
    document.getElementById('error').classList.add('hidden');
    
    try {
        const response = await fetch(`${API_URL}/analyze/${ip}`);
        const data = await response.json();
        
        if (response.ok) {
            displayResults(data);
        } else {
            showError(data.error || 'Failed to analyze IP address');
        }
    } catch (error) {
        showError('Connection error. Make sure the backend server is running on port 5000.');
    } finally {
        document.getElementById('loading').classList.add('hidden');
    }
}

function isValidIP(ip) {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipv4Regex.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => parseInt(part) >= 0 && parseInt(part) <= 255);
}

function displayResults(data) {
    // Verdict Summary
    const verdictDiv = document.getElementById('verdict');
    let verdictText = '';
    let verdictClass = '';
    
    if (data.risk_level === 'CRITICAL' || data.risk_level === 'HIGH') {
        verdictText = `⚠️ MALICIOUS - This IP address poses a significant threat`;
        verdictClass = 'verdict-malicious';
    } else if (data.risk_level === 'MEDIUM') {
        verdictText = `⚡ SUSPICIOUS - This IP address shows indicators of compromise`;
        verdictClass = 'verdict-suspicious';
    } else {
        verdictText = `✓ BENIGN - No significant threats detected`;
        verdictClass = 'verdict-benign';
    }
    
    verdictDiv.textContent = verdictText;
    verdictDiv.className = 'verdict ' + verdictClass;
    
    // Risk Level
    const riskLevel = document.getElementById('riskLevel');
    riskLevel.textContent = data.risk_level;
    riskLevel.className = 'risk-badge risk-' + data.risk_level.toLowerCase();
    
    // Threat Score
    document.getElementById('threatScore').textContent = data.threat_score + '/100';
    
    // Country
    document.getElementById('country').textContent = data.ip_info.country || 'Unknown';
    
    // NEW: Display Geolocation & ASN
    displayGeolocation(data.ip_info);
    
    // Display Threat Categories
    displayThreatCategories(data);
    
    // Sources
    const sourcesDiv = document.getElementById('sources');
    sourcesDiv.innerHTML = data.sources.map(source => `
        <div class="source-item">
            <strong>${source.name}</strong>: 
            <span class="status-${source.status === 'Clean' ? 'clean' : 'malicious'}">
                ${source.status}
            </span>
            ${source.detections ? `<br><small>${source.detections} detections</small>` : ''}
        </div>
    `).join('');
    
    // Threats
    const threatsDiv = document.getElementById('threats');
    if (data.threats.length > 0) {
        threatsDiv.innerHTML = data.threats.map(threat => `
            <div class="threat-item">
                <strong>${threat.type}</strong>: ${threat.description}
                <br><small>Severity: ${threat.severity}</small>
            </div>
        `).join('');
    } else {
        threatsDiv.innerHTML = '<p class="status-clean">✓ No threats detected</p>';
    }
    
    // IP Info
    const ipInfoDiv = document.getElementById('ipInfo');
    ipInfoDiv.innerHTML = `
        <p><strong>IP Address:</strong> ${data.ip_info.ip}</p>
        <p><strong>ISP:</strong> ${data.ip_info.isp || 'Unknown'}</p>
        <p><strong>Organization:</strong> ${data.ip_info.organization || 'Unknown'}</p>
        <p><strong>ASN:</strong> ${data.ip_info.asn || 'Unknown'}</p>
        <p><strong>Country:</strong> ${data.ip_info.country || 'Unknown'}</p>
        <p><strong>City:</strong> ${data.ip_info.city || 'Unknown'}</p>
        <p><strong>Timezone:</strong> ${data.ip_info.timezone || 'Unknown'}</p>
    `;
    
    // Timeline
    const timelineDiv = document.getElementById('timeline');
    timelineDiv.innerHTML = data.activity.map(activity => `
        <div class="timeline-item">
            <strong>${activity.date}</strong>: ${activity.description}
        </div>
    `).join('');
    
    document.getElementById('results').classList.remove('hidden');
}

// NEW: Display Geolocation & ASN Function
function displayGeolocation(ipInfo) {
    // IP Address
    document.getElementById('geoIP').textContent = ipInfo.ip || 'Unknown';
    
    // Country
    const country = ipInfo.country || 'Unknown';
    document.getElementById('geoCountry').textContent = country;
    
    // City
    document.getElementById('geoCity').textContent = ipInfo.city || 'Unknown';
    
    // ASN - Prominently displayed
    const asn = ipInfo.asn || 'Unknown';
    document.getElementById('geoASN').textContent = asn;
    
    // ISP
    document.getElementById('geoISP').textContent = ipInfo.isp || 'Unknown';
    
    // Organization
    document.getElementById('geoOrg').textContent = ipInfo.organization || 'Unknown';
    
    // Timezone
    document.getElementById('geoTimezone').textContent = ipInfo.timezone || 'Unknown';
    
    // Coordinates
    const lat = ipInfo.latitude;
    const lon = ipInfo.longitude;
    let coordsText = 'Unknown';
    
    if (lat && lon) {
        coordsText = `${lat.toFixed(4)}°, ${lon.toFixed(4)}°`;
    }
    document.getElementById('geoCoords').textContent = coordsText;
    
    // Map Info
    const mapInfo = document.getElementById('mapInfo');
    if (lat && lon) {
        mapInfo.innerHTML = `
            <strong>${country}</strong><br>
            ${ipInfo.city || 'Unknown City'}<br>
            Coordinates: ${lat.toFixed(4)}°N, ${lon.toFixed(4)}°E
        `;
    } else {
        mapInfo.textContent = `${country} - Location data unavailable`;
    }
}

// Display Threat Categories Function
function displayThreatCategories(data) {
    const categoriesDiv = document.getElementById('threatCategories');
    
    const categories = [
        { name: 'Botnet', icon: '🤖', keywords: ['botnet', 'bot'] },
        { name: 'C2 Server', icon: '🎛️', keywords: ['c2', 'command', 'control'] },
        { name: 'Phishing', icon: '🎣', keywords: ['phishing', 'phish'] },
        { name: 'Spam', icon: '📧', keywords: ['spam', 'abuse', 'mail'] },
        { name: 'Proxy/VPN', icon: '🔒', keywords: ['proxy', 'vpn', 'anonymizer', 'tor'] },
        { name: 'Malware', icon: '🦠', keywords: ['malware', 'trojan', 'virus', 'emotet', 'trickbot'] },
        { name: 'DDoS', icon: '💥', keywords: ['ddos', 'dos', 'flood'] },
        { name: 'Scanner', icon: '🔍', keywords: ['scan', 'scanner', 'probe'] }
    ];
    
    const detectedCategories = [];
    
    categories.forEach(category => {
        let isDetected = false;
        let severity = 'clean';
        
        data.threats.forEach(threat => {
            const threatText = (threat.type + ' ' + threat.description).toLowerCase();
            if (category.keywords.some(keyword => threatText.includes(keyword))) {
                isDetected = true;
                if (threat.severity === 'Critical') severity = 'detected';
                else if (threat.severity === 'High') severity = 'detected';
                else if (severity !== 'detected') severity = 'warning';
            }
        });
        
        if (data.raw_data && data.raw_data.shodan) {
            const tags = data.raw_data.shodan.tags || [];
            if (tags.some(tag => category.keywords.some(keyword => tag.toLowerCase().includes(keyword)))) {
                isDetected = true;
                severity = 'warning';
            }
        }
        
        if (data.raw_data && data.raw_data.threatfox) {
            const threatTypes = data.raw_data.threatfox.threat_types || [];
            const malware = data.raw_data.threatfox.malware_families || [];
            const allThreats = [...threatTypes, ...malware].join(' ').toLowerCase();
            
            if (category.keywords.some(keyword => allThreats.includes(keyword))) {
                isDetected = true;
                severity = 'detected';
            }
        }
        
        detectedCategories.push({
            ...category,
            detected: isDetected,
            severity: severity
        });
    });
    
    categoriesDiv.innerHTML = detectedCategories.map(cat => `
        <div class="category-card category-${cat.detected ? cat.severity : 'clean'}">
            <div class="category-icon">${cat.icon}</div>
            <div class="category-name">${cat.name}</div>
            <div class="category-status">
                ${cat.detected ? 'DETECTED' : 'Clean'}
            </div>
        </div>
    `).join('');
}

function showError(message) {
    const errorDiv = document.getElementById('error');
    errorDiv.textContent = '❌ ' + message;
    errorDiv.classList.remove('hidden');
}

document.getElementById('ipInput').addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        analyzeIP();
    }
});
