from pathlib import Path

path = Path('dashboard/index.html')
text = path.read_text(encoding='utf-8')
marker = '<!-- NIDS_ML_EXTENSION -->'

if marker in text:
    print('ML dashboard extension already installed.')
    raise SystemExit(0)

css = r'''
<style id="nids-ml-extension-style">
.nids-ml-extension{margin:24px 0;padding:20px;border:1px solid #334155;border-radius:14px;background:#0f172a;color:#e2e8f0}
.nids-ml-head{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:16px}
.nids-ml-head h2{margin:0;font-size:20px}
.nids-ml-head p{margin:4px 0 0;color:#94a3b8;font-size:13px}
.nids-ml-link{display:inline-block;padding:9px 14px;border-radius:8px;text-decoration:none;background:#2563eb;color:#fff;font-size:13px}
.nids-ml-cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px}
.nids-ml-card{padding:14px;border:1px solid #334155;border-radius:10px;background:#1e293b}
.nids-ml-label{font-size:12px;color:#94a3b8;margin-bottom:7px}
.nids-ml-value{font-size:24px;font-weight:700}
.nids-ml-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.nids-ml-table{width:100%;border-collapse:collapse}
.nids-ml-table th,.nids-ml-table td{padding:9px 7px;border-bottom:1px solid #334155;text-align:left;font-size:12px}
.nids-ml-table th{color:#94a3b8}
.nids-ml-status{margin-top:12px;color:#94a3b8;font-size:12px}
@media (max-width:900px){.nids-ml-cards{grid-template-columns:repeat(2,1fr)}.nids-ml-grid{grid-template-columns:1fr}}
@media (max-width:600px){.nids-ml-cards{grid-template-columns:1fr}.nids-ml-head{align-items:flex-start;flex-direction:column}}
</style>
'''

html = r'''
<!-- NIDS_ML_EXTENSION -->
<section class="nids-ml-extension" id="nidsMlSection">
  <div class="nids-ml-head">
    <div>
      <h2>Machine Learning Anomaly Detection</h2>
      <p>Isolation Forest analysis of 5-second traffic windows</p>
    </div>
    <a class="nids-ml-link" href="ml.html">Open ML Dashboard</a>
  </div>
  <div class="nids-ml-cards">
    <div class="nids-ml-card"><div class="nids-ml-label">Feature Windows</div><div class="nids-ml-value" id="nidsMlFeatureWindows">-</div></div>
    <div class="nids-ml-card"><div class="nids-ml-label">ML Anomalies</div><div class="nids-ml-value" id="nidsMlAnomalies">-</div></div>
    <div class="nids-ml-card"><div class="nids-ml-label">Anomaly Rate</div><div class="nids-ml-value" id="nidsMlRate">-</div></div>
    <div class="nids-ml-card"><div class="nids-ml-label">Rule → ML Coverage</div><div class="nids-ml-value" id="nidsMlCoverage">-</div></div>
  </div>
  <div class="nids-ml-grid">
    <table class="nids-ml-table">
      <tbody>
        <tr><th>Rule Alert Windows</th><td id="nidsMlRuleWindows">-</td></tr>
        <tr><th>Overlapping Windows</th><td id="nidsMlOverlap">-</td></tr>
        <tr><th>ML → Rule Overlap</th><td id="nidsMlAnomalyOverlap">-</td></tr>
      </tbody>
    </table>
    <table class="nids-ml-table">
      <thead><tr><th>Pattern</th><th>Windows</th></tr></thead>
      <tbody id="nidsMlPatterns"></tbody>
    </table>
  </div>
  <div class="nids-ml-status" id="nidsMlStatus">Loading ML data...</div>
</section>
<script id="nids-ml-extension-script">
(async function(){
  const api='http://127.0.0.1:8000';
  const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v};
  const esc=v=>String(v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&#039;');
  async function load(){
    try{
      const response=await fetch(api+'/ml/stats');
      const data=await response.json();
      set('nidsMlFeatureWindows',data.feature_windows);
      set('nidsMlAnomalies',data.anomaly_windows);
      set('nidsMlRate',data.anomaly_rate+'%');
      set('nidsMlCoverage',data.alert_coverage_rate+'%');
      set('nidsMlRuleWindows',data.rule_alert_windows);
      set('nidsMlOverlap',data.overlapping_windows);
      set('nidsMlAnomalyOverlap',data.anomaly_overlap_rate+'%');
      const body=document.getElementById('nidsMlPatterns');
      body.innerHTML='';
      Object.entries(data.anomaly_patterns).sort((a,b)=>b[1]-a[1]).forEach(([name,count])=>{
        body.innerHTML+=`<tr><td>${esc(name)}</td><td>${count}</td></tr>`;
      });
      set('nidsMlStatus','Last update: '+new Date().toLocaleTimeString());
    }catch(error){
      set('nidsMlStatus','ML data unavailable: '+error.message);
    }
  }
  load();
  setInterval(load,5000);
})();
</script>
'''

if '</style>' not in text or '<body' not in text:
    raise SystemExit('Expected HTML markers were not found.')

text = text.replace('</style>', '</style>' + css, 1)
text = text.replace('<body>', '<body>' + html, 1)
path.write_text(text, encoding='utf-8')
print('Installed ML summary section in dashboard/index.html')
