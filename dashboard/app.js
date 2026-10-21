const form = document.querySelector('#upload-form');
const fileInput = document.querySelector('#email-file');
const message = document.querySelector('#message');
const login = document.querySelector('#login');
const consoleView = document.querySelector('#console');
const uploadLabel = document.querySelector('label[for="email-file"]');
const defaultUploadLabel = uploadLabel.innerHTML;
const loginMessage = login.querySelector('p');
const defaultLoginMessage = loginMessage.textContent;

let apiKey = sessionStorage.getItem('mailtrace_api_key') || '';

function showConsole() {
  login.hidden = true;
  consoleView.hidden = false;
}

function showLoginAgain() {
  apiKey = '';
  sessionStorage.removeItem('mailtrace_api_key');
  consoleView.hidden = true;
  login.hidden = false;
  loginMessage.textContent =
    'Your saved API key was rejected. Enter the current key printed in PowerShell.';
}

if (apiKey) showConsole();

fileInput.addEventListener('change', () => {
  const file = fileInput.files[0];

  if (!file) {
    uploadLabel.innerHTML = defaultUploadLabel;
    message.textContent = '';
    delete message.dataset.state;
    return;
  }

  if (!file.name.toLowerCase().endsWith('.eml')) {
    fileInput.value = '';
    uploadLabel.innerHTML = defaultUploadLabel;
    message.dataset.state = 'error';
    message.textContent = 'Invalid file. Please select an .eml email file.';
    return;
  }

  if (file.size === 0 || file.size > 10 * 1024 * 1024) {
    fileInput.value = '';
    uploadLabel.innerHTML = defaultUploadLabel;
    message.dataset.state = 'error';
    message.textContent = file.size === 0
      ? 'The selected email file is empty.'
      : 'File is too large. Maximum size is 10 MB.';
    return;
  }

  const size = file.size >= 1024 * 1024
    ? `${(file.size / (1024 * 1024)).toFixed(2)} MB`
    : `${(file.size / 1024).toFixed(1)} KB`;

  uploadLabel.innerHTML =
    `<strong>${escapeHtml(file.name)}</strong><small>${size} · Selected, ready to analyze</small>`;

  message.dataset.state = 'success';
  message.textContent =
    `File selected successfully: ${file.name}. Click Analyze email to upload it.`;
});

document.querySelector('#login-form').addEventListener('submit', event => {
  event.preventDefault();

  const enteredKey = document.querySelector('#api-key').value.trim();

  if (!enteredKey) {
    loginMessage.textContent = 'Enter your API key.';
    return;
  }

  apiKey = enteredKey;
  sessionStorage.setItem('mailtrace_api_key', apiKey);
  loginMessage.textContent = defaultLoginMessage;
  showConsole();
});

form.addEventListener('submit', async event => {
  event.preventDefault();

  const file = fileInput.files[0];

  if (!file) {
    message.dataset.state = 'error';
    message.textContent = 'Select an .eml file first.';
    return;
  }

  const button = form.querySelector('button');
  button.disabled = true;
  button.textContent = 'Uploading and analyzing...';

  message.dataset.state = 'info';
  message.textContent = `Uploading ${file.name} to MAILTRACE-X. Analysis is in progress.`;

  try {
    const data = new FormData();
    data.append('file', file);

    const response = await fetch('/api/analyze/email', {
      method: 'POST',
      body: data,
      headers: { 'X-API-Key': apiKey }
    });

    let body = null;

    try {
      body = await response.json();
    } catch (_) {
      body = null;
    }

    if (!response.ok) {
      const detail = body?.detail;
      const errorText = typeof detail === 'object'
        ? detail?.message
        : detail;

      if (response.status === 401) {
        showLoginAgain();
        throw new Error('API key rejected. Sign in again with the key printed in PowerShell.');
      }

      throw new Error(errorText || `Request failed with HTTP ${response.status}.`);
    }

    render(body);

    message.dataset.state = 'success';
    message.textContent =
      `Email received and analyzed successfully. Case ID: ${body.case_id}.`;
  } catch (error) {
    message.dataset.state = 'error';
    message.textContent = error.message || 'Analysis failed. Check the server logs.';
  } finally {
    button.disabled = false;
    button.innerHTML = 'Analyze email <span>→</span>';
  }
});

function render(result) {
  document.querySelector('#empty').hidden = true;
  document.querySelector('#results').hidden = false;

  document.querySelector('#case-id').textContent = result.case_id;
  document.querySelector('#risk-score').textContent = `${result.risk.score}/100`;
  document.querySelector('#risk-level').textContent =
    result.risk.level.toUpperCase() + ' RISK';

  document.querySelector('#classification').textContent =
    result.detection.classification.toUpperCase();

  document.querySelector('#probability').textContent =
    `${Math.round(result.detection.phishing_probability * 100)}% phishing probability`;

  document.querySelector('#confidence').textContent =
    `${Math.round(result.risk.confidence * 100)}%`;

  document.querySelector('#reasons').innerHTML =
    result.risk.reasons.map(r => `<li>${escapeHtml(r)}</li>`).join('');

  const auth = result.evidence.authentication || {};

  document.querySelector('#auth').innerHTML =
    Object.entries(auth).map(([key, value]) =>
      `<div>${escapeHtml(key).toUpperCase()}<b>${escapeHtml(value).toUpperCase()}</b></div>`
    ).join('');

  const iocs = Object.values(result.evidence.iocs || {}).flat();

  document.querySelector('#iocs').innerHTML = iocs.length
    ? iocs.map(i => `<code>${escapeHtml(i)}</code>`).join('')
    : '<p>No IOCs extracted.</p>';

  const related = result.correlation?.related_cases?.length || 0;

  document.querySelector('#relationships').textContent = related
    ? `${related} related case(s) share infrastructure.`
    : 'No prior shared infrastructure found for this case.';

  document.querySelector('#timeline').textContent =
    `Case created ${new Date(result.created_at).toLocaleString()}. Email evidence parsed, detection evaluated, and correlation graph refreshed.`;

  const attachments = result.evidence.attachments || [];

  document.querySelector('#attachments').innerHTML = attachments.length
    ? attachments.map(a =>
        `<p><b>${escapeHtml(a.filename)}</b><br><small>${escapeHtml(a.mime_type)} · SHA-256 ${escapeHtml(a.sha256)}</small></p>`
      ).join('')
    : '<p>No attachments found. No sandbox execution was performed.</p>';

  const terms = result.detection.term_contributions || {};

  document.querySelector('#terms').innerHTML = Object.keys(terms).length
    ? Object.entries(terms).map(([term, weight]) =>
        `<code>${escapeHtml(term)} ${Number(weight) >= 0 ? '+' : ''}${Number(weight).toFixed(2)}</code>`
      ).join('')
    : '<p>No lexical contributions available.</p>';

  const reportLink = document.querySelector('#report-link');
  const pdfLink = document.querySelector('#pdf-link');

  reportLink.href = `/api/report/${encodeURIComponent(result.case_id)}`;
  pdfLink.href = `/api/report/${encodeURIComponent(result.case_id)}/pdf`;

  reportLink.onclick = event => {
    event.preventDefault();
    openAuthenticatedReport(reportLink.href);
  };

  pdfLink.onclick = event => {
    event.preventDefault();
    downloadAuthenticatedReport(pdfLink.href, `${result.case_id}-report.pdf`);
  };

  document.querySelector('#results').scrollIntoView({
    behavior: 'smooth',
    block: 'start'
  });
}

function escapeHtml(value) {
  const element = document.createElement('div');
  element.textContent = String(value ?? '');
  return element.innerHTML;
}

async function openAuthenticatedReport(url) {
  const reportWindow = window.open('about:blank', '_blank');

  if (!reportWindow) {
    message.dataset.state = 'error';
    message.textContent = 'Allow pop-ups to open the report.';
    return;
  }

  try {
    const response = await fetch(url, {
      headers: { 'X-API-Key': apiKey }
    });

    if (!response.ok) {
      throw new Error('Could not open report. Check your API key.');
    }

    const objectUrl = URL.createObjectURL(await response.blob());
    reportWindow.opener = null;
    reportWindow.location.href = objectUrl;
  } catch (error) {
    reportWindow.close();
    message.dataset.state = 'error';
    message.textContent = error.message;
  }
}

async function downloadAuthenticatedReport(url, filename) {
  try {
    const response = await fetch(url, {
      headers: { 'X-API-Key': apiKey }
    });

    if (!response.ok) {
      throw new Error('Could not download report. Check your API key.');
    }

    const objectUrl = URL.createObjectURL(await response.blob());
    const link = document.createElement('a');

    link.href = objectUrl;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();

    setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
  } catch (error) {
    message.dataset.state = 'error';
    message.textContent = error.message;
  }
}