document.addEventListener("DOMContentLoaded", function(){
    const headings = [
        "Phishing Detection System",
        "Real-Time Phishing Intelligence",
        "Detect & Analyze",
    ];
    const speed = 100;
    const eraseSpeed = 50;
    const delay = 1500;
    let textIndex = 0;
    let charIndex = 0;
    let isDeleting = false;
    const headingElement = document.querySelector(".container0 h1");
    
    function typeEffect(){
        if(headingElement){
            const currentText = headings[textIndex];
            headingElement.innerHTML = currentText.substring(0, charIndex) + "<span class='cursor'>|</span>";
            
            if (!isDeleting && charIndex < currentText.length){
                charIndex++;
                setTimeout(typeEffect, eraseSpeed);
            }
            else if(isDeleting && charIndex > 0){
                charIndex--;
                setTimeout(typeEffect, eraseSpeed);
            }
            else if(!isDeleting && charIndex === currentText.length){
                setTimeout(() => { isDeleting = true; typeEffect(); }, delay);
            }
            else if(isDeleting && charIndex ===0){
                isDeleting = false;
                textIndex = (textIndex + 1)%headings.length;
                setTimeout(typeEffect, speed); 
            }
        }
    }
    typeEffect();
});
const dashboard = {
    charts: {
        industryChart: null,
        trendChart: null
    },

    data: {
        activeThreats: [
            { id: 1, text: "NEW: AI-generated CEO impersonation campaign detected" },
            { id: 2, text: "ALERT: Massive crypto scam targeting finance departments" },
            { id: 3, text: "WARNING: Novel QR code phishing technique emerging" },
            { id: 4, text: "PHISHING ALERT: Fake job offers targeting professionals on LinkedIn" },
            { id: 5, text: "URGENT: Fake tax refund emails spreading before tax season" },
            { id: 6, text: "THREAT: Banking Trojan malware disguised as security updates" },
            { id: 7, text: "WARNING: Spear-phishing attacks on executives using deepfake voice calls" }
        ],
        emergingAttacks: [
            {
                title: "AI-Powered Social Engineering",
                description: "Advanced language models are being used to create highly convincing phishing messages that bypass traditional detection methods."
            },
            {
                title: "Multi-Channel Attacks",
                description: "Attackers coordinate across email, SMS, and voice channels to increase credibility and success rates."
            },
            {
                title: "Supply Chain Compromises",
                description: "Targeting trusted third-party vendors to gain access to multiple organizations simultaneously."
            }
        ],
        chartData: {
            industry: {
                labels: ['Finance', 'Healthcare', 'Tech', 'Retail', 'Mfg'],
                values: [5.85, 4.35, 3.86, 3.27, 2.98]
            },
            trends: {
                labels: ['19', '20', '21', '22', '23'],
                values: [150, 280, 420, 580, 750]
            }
        }
    },

    chartConfig: {
        common: {
            responsive: false, // Make charts static
            maintainAspectRatio: true,
            scales: {
                x: { grid: { display: false } },
                y: { beginAtZero: true, grid: { color: 'rgba(0, 0, 0, 0.1)' } }
            },
            plugins: {
                legend: { position: 'top' }
            }
        }
    },

    init() {
        this.populateThreats();
        this.populateAttacks();
        this.initIndustryChart();
        this.initTrendChart();
    },

    populateThreats() {
        const ticker = document.getElementById('threatTicker');
        if (!ticker) return;
        this.data.activeThreats.forEach(threat => {
            const el = document.createElement('div');
            el.className = 'threat-item';
            el.textContent = threat.text;
            ticker.appendChild(el);
        });
    },

    populateAttacks() {
        const attackList = document.getElementById('attackList');
        if (!attackList) return;
        this.data.emergingAttacks.forEach(attack => {
            const li = document.createElement('li');
            li.innerHTML = `<h3>${attack.title}</h3><p>${attack.description}</p>`;
            attackList.appendChild(li);
        });
    },

    initIndustryChart() {
        const ctx = document.getElementById('industryChart')?.getContext('2d');
        if (!ctx) return;
        this.charts.industryChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: this.data.chartData.industry.labels,
                datasets: [{
                    label: 'Avg Loss/Breach ($M)',
                    data: this.data.chartData.industry.values,
                    backgroundColor: '#3b82f6',
                    maxBarThickness: 30
                }]
            },
            options: this.chartConfig.common
        });
    },

    initTrendChart() {
        const ctx = document.getElementById('trendChart')?.getContext('2d');
        if (!ctx) return;
        this.charts.trendChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.data.chartData.trends.labels,
                datasets: [{
                    label: 'Attacks (K)',
                    data: this.data.chartData.trends.values,
                    borderColor: '#dc2626',
                    fill: false
                }]
            },
            options: this.chartConfig.common
        });
    }
};

document.addEventListener('DOMContentLoaded', () => dashboard.init());