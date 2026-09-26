(() => {
  const esc = (v) => String(v ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

  const targetSwitch = document.querySelector('[data-target-switch]');
  if (targetSwitch) {
    targetSwitch.addEventListener('change', () => {
      const url = targetSwitch.value;
      if (url && url.startsWith('/t/')) window.location.assign(url);
    });
  }

  const jobsRoot = document.querySelector('[data-jobs]');
  if (jobsRoot) {
    const jobsUrl = jobsRoot.dataset.jobsUrl;
    const refreshJobs = async () => {
      if (!jobsUrl) return;
      try {
        const res = await fetch(jobsUrl, {headers:{'Accept':'application/json'}});
        if (!res.ok) return;
        const data = await res.json();
        const jobs = data.jobs || [];
        if (!jobs.length) return;
        jobsRoot.innerHTML = jobs.map(j => `<div class="job"><span class="status-dot ${esc(j.status)}"></span><div><strong>${esc(j.label)}</strong><small>${esc(j.status)} · ${esc(j.started_at)}</small>${j.error ? `<small class="error">${esc(j.error)}</small>` : ''}</div></div>`).join('');
      } catch (_) {}
    };
    refreshJobs();
    setInterval(refreshJobs, 3000);
  }

  const summaryRoot = document.querySelector('[data-summary-url]');
  if (summaryRoot) {
    const summaryUrl = summaryRoot.dataset.summaryUrl;
    const refreshSummary = async () => {
      try {
        const res = await fetch(summaryUrl, {headers:{'Accept':'application/json'}});
        if (!res.ok) return;
        const data = await res.json();
        document.querySelectorAll('[data-stat-key]').forEach(node => {
          const key = node.dataset.statKey;
          if (Object.prototype.hasOwnProperty.call(data, key)) node.textContent = String(data[key]);
        });
      } catch (_) {}
    };
    setInterval(refreshSummary, 5000);
  }

  const inspectForm = document.querySelector('[data-inspect-form]');
  if (inspectForm) {
    const button = inspectForm.querySelector('[data-inspect-button]');
    const status = document.querySelector('[data-inspect-status]');
    let polling = false;

    const setStatus = (message, kind='') => {
      if (!status) return;
      status.className = `inspect-status ${kind}`.trim();
      status.textContent = message;
    };

    const pollJob = async (jobUrl, refreshUrl) => {
      if (polling) return;
      polling = true;
      for (;;) {
        try {
          const res = await fetch(jobUrl, {headers:{'Accept':'application/json'}});
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const job = await res.json();
          if (job.status === 'done') {
            setStatus('Inspección terminada. Actualizando resultados…', 'done');
            window.setTimeout(() => window.location.assign(refreshUrl), 350);
            return;
          }
          if (job.status === 'error') {
            setStatus(`La inspección falló: ${job.error || 'error desconocido'}`, 'error');
            if (button) button.disabled = false;
            polling = false;
            return;
          }
          setStatus('Inspeccionando DNS, TLS y HTTP/HTTPS…', 'running');
        } catch (err) {
          setStatus(`No pude consultar el estado: ${err.message}`, 'error');
          if (button) button.disabled = false;
          polling = false;
          return;
        }
        await new Promise(resolve => setTimeout(resolve, 1500));
      }
    };

    inspectForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (polling) return;
      if (button) button.disabled = true;
      setStatus('Iniciando inspección…', 'running');
      try {
        const res = await fetch(inspectForm.action, {
          method: 'POST',
          body: new FormData(inspectForm),
          headers: {'Accept':'application/json', 'X-Requested-With':'NegroFetch'}
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        await pollJob(data.job_url, data.refresh_url);
      } catch (err) {
        setStatus(`No pude iniciar la inspección: ${err.message}`, 'error');
        if (button) button.disabled = false;
      }
    });
  }
})();

// v0.7 directed intelligence actions + AI cost confirmation
(() => {
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  const pollJob = async (jobUrl, refreshUrl, statusNode, button) => {
    for (;;) {
      try {
        const res = await fetch(jobUrl, {headers:{'Accept':'application/json'}});
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const job = await res.json();
        if (statusNode) statusNode.textContent = `${job.label || 'Trabajo'} · ${job.status}`;
        if (job.status === 'done') {
          if (statusNode) statusNode.textContent = 'Terminado. Actualizando…';
          window.setTimeout(() => window.location.assign(refreshUrl), 350);
          return;
        }
        if (job.status === 'error') {
          if (statusNode) statusNode.textContent = `Error: ${job.error || 'desconocido'}`;
          if (button) button.disabled = false;
          return;
        }
      } catch (err) {
        if (statusNode) statusNode.textContent = `Error consultando job: ${err.message}`;
        if (button) button.disabled = false;
        return;
      }
      await sleep(1400);
    }
  };

  document.querySelectorAll('form[data-job-form]').forEach(form => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = form.querySelector('button[type="submit"]');
      if (button?.disabled) return;
      if (button) button.disabled = true;
      let statusNode = form.parentElement?.querySelector('.inline-job-status');
      if (!statusNode) {
        statusNode = document.createElement('span');
        statusNode.className = 'inline-job-status muted small';
        form.insertAdjacentElement('afterend', statusNode);
      }
      statusNode.textContent = 'Iniciando…';
      try {
        const res = await fetch(form.action, {
          method:'POST', body:new FormData(form),
          headers:{'Accept':'application/json','X-Requested-With':'NegroFetch'}
        });
        if (!res.ok) {
          let detail = `HTTP ${res.status}`;
          try { const j = await res.json(); detail = j.detail || detail; } catch (_) {}
          throw new Error(detail);
        }
        const data = await res.json();
        await pollJob(data.job_url, data.refresh_url, statusNode, button);
      } catch (err) {
        statusNode.textContent = `No pude iniciar: ${err.message}`;
        if (button) button.disabled = false;
      }
    });
  });

  const money = (value, currency) => {
    const n = Number(value || 0);
    if (currency === 'COP') return new Intl.NumberFormat('es-CO',{style:'currency',currency:'COP',maximumFractionDigits:0}).format(n);
    return new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',minimumFractionDigits:4,maximumFractionDigits:4}).format(n);
  };

  document.querySelectorAll('[data-ai-box]').forEach(box => {
    const estimateButton = box.querySelector('[data-ai-estimate]');
    const modelSelect = box.querySelector('[data-ai-model]');
    const output = box.querySelector('[data-ai-estimate-output]');
    const runForm = box.querySelector('[data-ai-run-form]');
    const runModel = box.querySelector('[data-ai-run-model]');

    estimateButton?.addEventListener('click', async () => {
      estimateButton.disabled = true;
      output.textContent = 'Estimando tokens y costo localmente…';
      try {
        const url = `${box.dataset.estimateUrl}?model=${encodeURIComponent(modelSelect.value)}`;
        const res = await fetch(url, {headers:{'Accept':'application/json'}});
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        output.innerHTML = `≈ <b>${Number(data.input_tokens_est).toLocaleString('es-CO')}</b> tokens de entrada · tope salida <b>${Number(data.output_tokens_budget).toLocaleString('es-CO')}</b> · máximo estimado <b>${money(data.max_total_usd_est,'USD')}</b> ≈ <b>${money(data.max_total_cop_est,'COP')}</b> <span class="muted">(USD/COP ${Number(data.usd_cop_rate).toLocaleString('es-CO')}, precios ${data.pricing_snapshot}${data.long_context ? ', contexto largo' : ''})</span>`;
        runModel.value = data.model;
        runForm.action = box.dataset.runUrl;
        runForm.hidden = false;
      } catch (err) {
        output.textContent = `No pude estimar: ${err.message}`;
        runForm.hidden = true;
      } finally {
        estimateButton.disabled = false;
      }
    });

    runForm?.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = runForm.querySelector('button[type="submit"]');
      if (button) button.disabled = true;
      output.textContent = 'Enviando únicamente la evidencia seleccionada a OpenAI…';
      try {
        const res = await fetch(runForm.action, {
          method:'POST', body:new FormData(runForm),
          headers:{'Accept':'application/json','X-Requested-With':'NegroFetch'}
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        await pollJob(data.job_url, data.refresh_url, output, button);
      } catch (err) {
        output.textContent = `No pude iniciar IA: ${err.message}`;
        if (button) button.disabled = false;
      }
    });
  });
})();
