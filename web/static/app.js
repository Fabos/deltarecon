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
        jobsRoot.innerHTML = jobs.map(j => `<div class="job"><span class="status-dot ${esc(j.status)}"></span><div><strong>${esc(j.label)}</strong><small>${esc(j.status)} · ${esc(j.started_at || j.queued_at)}</small>${j.error ? `<small class="error">${esc(j.error)}</small>` : ''}</div></div>`).join('');
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
// v0.7.2 directed intelligence actions + clear AI cost + honest activity progress
(() => {
  const esc = (v) => String(v ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

  const formatElapsed = (seconds) => {
    const s = Math.max(0, Math.floor(seconds));
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    const r = s % 60;
    return `${m}m ${String(r).padStart(2,'0')}s`;
  };

  const progressMarkup = (message) => `
    <div class="job-progress-top">
      <strong data-job-message>${esc(message)}</strong>
      <span data-job-elapsed>0s</span>
    </div>
    <div class="job-progress-track" aria-hidden="true"><span class="job-progress-bar"></span></div>
    <small class="job-progress-note">Actividad indeterminada: Negro sigue trabajando; no mostramos un porcentaje falso.</small>`;

  const ensureProgress = (form, label='Procesando…') => {
    let root = form.nextElementSibling;
    if (!root || !root.classList.contains('inline-job-progress')) {
      root = document.createElement('div');
      root.className = 'inline-job-progress';
      root.setAttribute('aria-live','polite');
      form.insertAdjacentElement('afterend', root);
    }
    root.classList.remove('done','error');
    root.innerHTML = progressMarkup(label);
    return root;
  };

  const setProgressMessage = (root, message, kind='') => {
    if (!root) return;
    root.classList.toggle('done', kind === 'done');
    root.classList.toggle('error', kind === 'error');
    const node = root.querySelector('[data-job-message]');
    if (node) node.textContent = message;
  };

  const pollJob = async (jobUrl, refreshUrl, progressRoot, button, startedAt=Date.now()) => {
    let stopped = false;
    const elapsedNode = progressRoot?.querySelector('[data-job-elapsed]');
    const timer = window.setInterval(() => {
      if (!stopped && elapsedNode) elapsedNode.textContent = formatElapsed((Date.now() - startedAt) / 1000);
    }, 1000);
    try {
      for (;;) {
        try {
          const res = await fetch(jobUrl, {headers:{'Accept':'application/json'}});
          if (!res.ok) throw new Error(`HTTP ${res.status}`);
          const job = await res.json();
          const label = job.label || 'Trabajo';
          if (job.status === 'queued') {
            setProgressMessage(progressRoot, `${label} · en cola (máximo 3 trabajos simultáneos)`);
          } else {
            setProgressMessage(progressRoot, `${label} · en ejecución`);
          }
          if (job.status === 'done') {
            setProgressMessage(progressRoot, 'Terminado. Actualizando resultados…', 'done');
            stopped = true;
            window.clearInterval(timer);
            window.setTimeout(() => window.location.assign(refreshUrl), 500);
            return;
          }
          if (job.status === 'error') {
            setProgressMessage(progressRoot, `Error: ${job.error || 'desconocido'}`, 'error');
            stopped = true;
            window.clearInterval(timer);
            if (button) button.disabled = false;
            return;
          }
        } catch (err) {
          setProgressMessage(progressRoot, `Error consultando job: ${err.message}`, 'error');
          stopped = true;
          window.clearInterval(timer);
          if (button) button.disabled = false;
          return;
        }
        await sleep(1400);
      }
    } finally {
      if (!stopped) window.clearInterval(timer);
    }
  };

  document.querySelectorAll('form[data-job-form]').forEach(form => {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const button = form.querySelector('button[type="submit"]');
      if (button?.disabled) return;
      if (button) button.disabled = true;
      const label = form.dataset.jobLabel || button?.textContent?.trim() || 'Procesando';
      const progressRoot = ensureProgress(form, `${label}: iniciando…`);
      const startedAt = Date.now();
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
        await pollJob(data.job_url, data.refresh_url, progressRoot, button, startedAt);
      } catch (err) {
        setProgressMessage(progressRoot, `No pude iniciar: ${err.message}`, 'error');
        if (button) button.disabled = false;
      }
    });
  });

  const formatUsd = (value) => {
    const n = Number(value || 0);
    return `USD $${n.toLocaleString('en-US',{minimumFractionDigits:4,maximumFractionDigits:6})}`;
  };

  const formatCop = (value) => {
    const n = Number(value || 0);
    const digits = Math.abs(n) < 100 ? 2 : 0;
    return `COP $${n.toLocaleString('es-CO',{minimumFractionDigits:digits,maximumFractionDigits:2})}`;
  };

  const roundedCopWords = (value) => {
    const rounded = Math.round(Number(value || 0));
    return `${rounded.toLocaleString('es-CO')} ${rounded === 1 ? 'peso colombiano' : 'pesos colombianos'}`;
  };

  document.querySelectorAll('[data-ai-box]').forEach(box => {
    const estimateButton = box.querySelector('[data-ai-estimate]');
    const modelSelect = box.querySelector('[data-ai-model]');
    const output = box.querySelector('[data-ai-estimate-output]');
    const runForm = box.querySelector('[data-ai-run-form]');
    const runModel = box.querySelector('[data-ai-run-model]');

    estimateButton?.addEventListener('click', async () => {
      estimateButton.disabled = true;
      output.innerHTML = '<div class="ai-estimate-loading">Estimando tokens y costo localmente…</div>';
      try {
        const url = `${box.dataset.estimateUrl}?model=${encodeURIComponent(modelSelect.value)}`;
        const res = await fetch(url, {headers:{'Accept':'application/json'}});
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        const cop = Number(data.max_total_cop_est || 0);
        output.innerHTML = `
          <div class="ai-cost-grid">
            <div class="ai-cost-main">
              <span>Costo máximo estimado</span>
              <strong>${formatCop(cop)}</strong>
              <small>≈ ${roundedCopWords(cop)}</small>
            </div>
            <div class="ai-cost-detail"><span>Equivalente USD</span><strong>${formatUsd(data.max_total_usd_est)}</strong></div>
            <div class="ai-cost-detail"><span>Entrada estimada</span><strong>${Number(data.input_tokens_est).toLocaleString('es-CO')} tokens</strong></div>
            <div class="ai-cost-detail"><span>Salida presupuestada</span><strong>máx. ${Number(data.output_tokens_budget).toLocaleString('es-CO')} tokens</strong></div>
          </div>
          <div class="ai-cost-foot">Es un <b>tope estimado</b>; el costo real puede ser menor. Conversión usada: 1 USD = ${Number(data.usd_cop_rate).toLocaleString('es-CO',{maximumFractionDigits:2})} COP · precios ${esc(data.pricing_snapshot)}${data.long_context ? ' · contexto largo' : ''}.</div>
          <div class="ai-evidence-note">${data.source_map_included ? `✓ La evidencia de IA incluirá el <b>source map confirmado</b>${data.source_map_application_sources !== undefined ? ` · ${Number(data.source_map_application_sources).toLocaleString('es-CO')} fuentes de aplicación` : ''}${data.source_map_sources_with_content !== undefined ? ` · ${Number(data.source_map_sources_with_content).toLocaleString('es-CO')} con contenido` : ''}.` : 'La estimación usa sólo el análisis local del bundle; no hay source map confirmado asociado.'}</div>`;
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
      const progressRoot = document.createElement('div');
      progressRoot.className = 'inline-job-progress ai-job-progress';
      progressRoot.innerHTML = progressMarkup('OpenAI: preparando evidencia seleccionada…');
      output.replaceChildren(progressRoot);
      const startedAt = Date.now();
      try {
        const res = await fetch(runForm.action, {
          method:'POST', body:new FormData(runForm),
          headers:{'Accept':'application/json','X-Requested-With':'NegroFetch'}
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
        await pollJob(data.job_url, data.refresh_url, progressRoot, button, startedAt);
      } catch (err) {
        setProgressMessage(progressRoot, `No pude iniciar IA: ${err.message}`, 'error');
        if (button) button.disabled = false;
      }
    });
  });
})();
