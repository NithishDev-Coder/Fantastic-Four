const form = document.getElementById('scan-form');
const button = document.getElementById('scan-button');
const authorizedCheckbox = document.getElementById('authorized');
const targetInput = document.getElementById('target');
const loadingState = document.getElementById('loading-state');
const errorState = document.getElementById('error-state');
const resultsPanel = document.getElementById('results-panel');
const loadingTarget = document.getElementById('loading-target');

const resultTarget = document.getElementById('result-target');
const resultIp = document.getElementById('result-ip');
const resultStatus = document.getElementById('result-status');
const subdomainList = document.getElementById('subdomain-list');
const subdomainCount = document.getElementById('subdomain-count');
const portTableBody = document.getElementById('port-table-body');
const portCount = document.getElementById('port-count');

function toggleButton() {
  button.disabled = !authorizedCheckbox.checked || !targetInput.value.trim();
}

authorizedCheckbox.addEventListener('change', toggleButton);
targetInput.addEventListener('input', toggleButton);

toggleButton();

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const target = targetInput.value.trim();
  loadingTarget.textContent = target;
  loadingState.classList.remove('d-none');
  errorState.classList.add('d-none');
  resultsPanel.classList.add('d-none');

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, authorized: authorizedCheckbox.checked })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Scan request failed.');
    }

    renderResults(data);
  } catch (error) {
    errorState.textContent = error.message;
    errorState.classList.remove('d-none');
  } finally {
    loadingState.classList.add('d-none');
  }
});

function renderResults(data) {
  resultTarget.textContent = data.target || 'N/A';
  resultIp.textContent = data.ip || 'N/A';
  resultStatus.textContent = data.status || 'Unknown';

  subdomainList.innerHTML = '';
  if (data.subdomains && data.subdomains.length) {
    data.subdomains.forEach((item) => {
      const li = document.createElement('li');
      li.className = 'list-group-item';
      li.textContent = `${item.hostname} (${item.ip || 'No record'})`;
      subdomainList.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.className = 'list-group-item text-muted';
    li.textContent = 'No resolvable subdomains were found.';
    subdomainList.appendChild(li);
  }
  subdomainCount.textContent = `Total: ${data.summary?.subdomains_found ?? 0}`;

  portTableBody.innerHTML = '';
  if (data.ports && data.ports.length) {
    data.ports.forEach((item) => {
      const row = document.createElement('tr');
      row.innerHTML = `<td>${item.port}</td><td>${item.service}</td><td><span class="badge bg-success">OPEN</span></td>`;
      portTableBody.appendChild(row);
    });
  } else {
    const row = document.createElement('tr');
    row.innerHTML = '<td colspan="3" class="text-muted">No open ports detected.</td>';
    portTableBody.appendChild(row);
  }
  portCount.textContent = `Total open ports: ${data.summary?.open_ports ?? 0}`;

  resultsPanel.classList.remove('d-none');
}
