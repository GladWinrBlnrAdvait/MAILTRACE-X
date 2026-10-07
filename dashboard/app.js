const form = document.querySelector('#upload-form');
const fileInput = document.querySelector('#email-file');
const message = document.querySelector('#message');
form.addEventListener('submit', async event => {
  event.preventDefault();
  const file = fileInput.files[0]; if (!file) return;
  const button = form.querySelector('button'); button.disabled = true; button.textContent = 'Analyzing evidence…';
  message.textContent = '';
  try {
    const data = new FormData(); data.append('file', file);
    const response = await fetch('/api/analyze/email', {method:'POST', body:data});
    if (!response.ok) throw new Error((await response.json()).detail || 'Analysis failed');
    render(await response.json());
  } catch (error) { message.textContent = error.message; }
  finally { button.disabled = false; button.innerHTML = 'Analyze email <span>→</span>'; }
});
function render(result) {
  document.querySelector('#empty').hidden = true; document.querySelector('#results').hidden = false;
  document.querySelector('#case-id').textContent = result.case_id;
  document.querySelector('#risk-score').textContent = `${result.risk.score}/100`;
  document.querySelector('#risk-level').textContent = result.risk.level.toUpperCase() + ' RISK';
  document.querySelector('#classification').textContent = result.detection.classification.toUpperCase();
  document.querySelector('#probability').textContent = `${Math.round(result.detection.phishing_probability * 100)}% phishing probability`;
  document.querySelector('#confidence').textContent = `${Math.round(result.risk.confidence * 100)}%`;
  document.querySelector('#reasons').innerHTML = result.risk.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('');
  const auth = result.evidence.authentication;
  document.querySelector('#auth').innerHTML = Object.entries(auth).map(([key, value]) => `<div>${key.toUpperCase()}<b>${escapeHtml(value).toUpperCase()}</b></div>`).join('');
  const iocs = Object.values(result.evidence.iocs).flat();
  document.querySelector('#iocs').innerHTML = iocs.length ? iocs.map(i => `<code>${escapeHtml(i)}</code>`).join('') : '<p>No IOCs extracted.</p>';
  const related = result.correlation.related_cases.length;
  document.querySelector('#relationships').textContent = related ? `${related} related case(s) share infrastructure.` : 'No prior shared infrastructure found for this case.';
  document.querySelector('#report-link').href = `/api/report/${result.case_id}`;
  document.querySelector('#results').scrollIntoView({behavior:'smooth', block:'start'});
}
function escapeHtml(value) { const d = document.createElement('div'); d.textContent = value; return d.innerHTML; }
