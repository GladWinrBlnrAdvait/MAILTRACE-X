const form = document.querySelector('#upload-form');
const fileInput = document.querySelector('#email-file');
const message = document.querySelector('#message');
const login = document.querySelector('#login');
const consoleView = document.querySelector('#console');
let apiKey = sessionStorage.getItem('mailtrace_api_key') || '';
function showConsole() { login.hidden = true; consoleView.hidden = false; }
if (apiKey) showConsole();
document.querySelector('#login-form').addEventListener('submit', event => {
  event.preventDefault(); apiKey = document.querySelector('#api-key').value.trim();
  sessionStorage.setItem('mailtrace_api_key', apiKey); showConsole();
});
form.addEventListener('submit', async event => {
  event.preventDefault();
  const file = fileInput.files[0]; if (!file) return;
  const button = form.querySelector('button'); button.disabled = true; button.textContent = 'Analyzing evidence…';
  message.textContent = '';
  try {
    const data = new FormData(); data.append('file', file);
    const response = await fetch('/api/analyze/email', {method:'POST', body:data, headers:{'X-API-Key': apiKey}});
    if (!response.ok) { const detail = (await response.json()).detail; throw new Error(detail?.message || detail || 'Analysis failed'); }
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
  document.querySelector('#auth').innerHTML = Object.entries(auth).map(([key, value]) => `<div>${escapeHtml(key).toUpperCase()}<b>${escapeHtml(value).toUpperCase()}</b></div>`).join('');
  const iocs = Object.values(result.evidence.iocs).flat();
  document.querySelector('#iocs').innerHTML = iocs.length ? iocs.map(i => `<code>${escapeHtml(i)}</code>`).join('') : '<p>No IOCs extracted.</p>';
  const related = result.correlation?.related_cases?.length || 0;
  document.querySelector('#relationships').textContent = related ? `${related} related case(s) share infrastructure.` : 'No prior shared infrastructure found for this case.';
  document.querySelector('#timeline').textContent = `Case created ${new Date(result.created_at).toLocaleString()}. Email evidence parsed, detection evaluated, and correlation graph refreshed.`;
  const attachments = result.evidence.attachments || [];
  document.querySelector('#attachments').innerHTML = attachments.length ? attachments.map(a => `<p><b>${escapeHtml(a.filename)}</b><br><small>${escapeHtml(a.mime_type)} · SHA-256 ${escapeHtml(a.sha256)}</small></p>`).join('') : '<p>No attachments found. No sandbox execution was performed.</p>';
  const terms = result.detection.term_contributions || {};
  document.querySelector('#terms').innerHTML = Object.keys(terms).length ? Object.entries(terms).map(([term, weight]) => `<code>${escapeHtml(term)} ${Number(weight) >= 0 ? '+' : ''}${Number(weight).toFixed(2)}</code>`).join('') : '<p>No lexical contributions available.</p>';
  const reportLink = document.querySelector('#report-link');
  const pdfLink = document.querySelector('#pdf-link');
  reportLink.href = `/api/report/${encodeURIComponent(result.case_id)}`;
  pdfLink.href = `/api/report/${encodeURIComponent(result.case_id)}/pdf`;
  reportLink.onclick = event => { event.preventDefault(); openAuthenticatedReport(reportLink.href); };
  pdfLink.onclick = event => { event.preventDefault(); downloadAuthenticatedReport(pdfLink.href, `${result.case_id}-report.pdf`); };
  document.querySelector('#results').scrollIntoView({behavior:'smooth', block:'start'});
}
function escapeHtml(value) { const d = document.createElement('div'); d.textContent = value; return d.innerHTML; }


async function openAuthenticatedReport(url) {
  const reportWindow = window.open('about:blank', '_blank');
  if (!reportWindow) { message.textContent = 'Allow pop-ups to open the report.'; return; }
  try {
    const response = await fetch(url, {headers: {'X-API-Key': apiKey}});
    if (!response.ok) throw new Error('Could not open report. Check your API key.');
    const objectUrl = URL.createObjectURL(await response.blob());
    reportWindow.opener = null;
    reportWindow.location.href = objectUrl;
  } catch (error) { reportWindow.close(); message.textContent = error.message; }
}

async function downloadAuthenticatedReport(url, filename) {
  try {
    const response = await fetch(url, {headers: {'X-API-Key': apiKey}});
    if (!response.ok) throw new Error('Could not download report. Check your API key.');
    const objectUrl = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(objectUrl);
  } catch (error) { message.textContent = error.message; }
}
