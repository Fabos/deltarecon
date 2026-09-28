(() => {
  const esc = (v) => String(v ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

  const showJobToast = (payload) => {
    if (!payload) return;
    const root = document.createElement('div');
    root.className = 'negro-toast';
    const delta = payload.summary?.delta || payload.delta || {};
    const labels = {hosts:'hosts',resources:'recursos',operations:'métodos',http_exchanges:'solicitudes HTTP',js_assets:'JS',observations:'observaciones'};
    const changes = Object.entries(labels).filter(([k]) => Number(delta[k] || 0) !== 0).map(([k,l]) => `+${delta[k]} ${l}`);
    let result = changes.length ? changes.join(' · ') : 'Sin elementos nuevos';
    const detail = payload.summary?.result || payload.result || {};
    if (detail && typeof detail === 'object') {
      if (detail.error) result = `Error de prueba: ${detail.error}`;
      else if (detail.likely_credentialed_cors) result = `⚠ CORS interesante: Origin reflejado + credenciales · HTTP ${detail.status ?? '—'}`;
      else if (detail.origin_reflected) result = `CORS: Origin reflejado · HTTP ${detail.status ?? '—'}`;
      else if (Object.prototype.hasOwnProperty.call(detail, 'allow_origin')) result = `CORS sin reflexión detectada · HTTP ${detail.status ?? '—'} · ACAO ${detail.allow_origin || '—'}`;
    }
    root.innerHTML = `<button type="button" aria-label="Cerrar">×</button><strong>${esc(payload.label || 'Trabajo terminado')}</strong><span>${esc(result)}</span>`;
    root.querySelector('button')?.addEventListener('click', () => root.remove());
    document.body.appendChild(root);
    window.setTimeout(() => root.remove(), 9000);
  };

  try {
    const pendingToast = JSON.parse(sessionStorage.getItem('negroJobToast') || 'null');
    if (pendingToast) {
      sessionStorage.removeItem('negroJobToast');
      window.setTimeout(() => showJobToast(pendingToast), 150);
    }
  } catch (_) {}

  const targetSwitch = document.querySelector('[data-target-switch]');
  if (targetSwitch) {
    targetSwitch.addEventListener('change', () => {
      const url = targetSwitch.value;
      if (url && url.startsWith('/t/')) window.location.assign(url);
    });
  }


  const notificationBell = document.querySelector('[data-notifications-bell]');
  if (notificationBell) {
    const notificationUrl = notificationBell.dataset.notificationsUrl;
    const targetKey = notificationBell.dataset.targetKey || 'target';
    const countNode = notificationBell.querySelector('[data-notification-count]');
    const lastKey = `negro.notification.last:${targetKey}`;
    let initialized = false;
    let lastId = 0;
    try { lastId = Number(sessionStorage.getItem(lastKey) || 0) || 0; } catch (_) {}

    const severityRank = {critical:5,high:4,medium:3,low:2,info:1};
    const severityLabel = {critical:'Crítica',high:'Alta',medium:'Media',low:'Baja',info:'Informativa'};
    const showSignalToast = (item) => {
      if (!item || (severityRank[item.severity] || 0) < 3) return;
      const root = document.createElement('a');
      root.className = `negro-toast signal-toast severity-${esc(item.severity || 'medium')}`;
      root.href = item.href || '#';
      root.innerHTML = `<span class="signal-toast-kicker">Nueva señal · ${esc(severityLabel[item.severity] || item.severity || 'Media')}</span><strong>${esc(item.title || 'Alerta de inteligencia')}</strong><span>${esc(item.message || '')}</span>`;
      document.body.appendChild(root);
      window.setTimeout(() => root.remove(), item.severity === 'high' || item.severity === 'critical' ? 14000 : 10000);
    };

    const refreshNotifications = async () => {
      if (!notificationUrl) return;
      try {
        const sep = notificationUrl.includes('?') ? '&' : '?';
        const res = await fetch(`${notificationUrl}${sep}after_id=${lastId}&limit=50`, {headers:{'Accept':'application/json'}});
        if (!res.ok) return;
        const data = await res.json();
        if (countNode) {
          const unread = Number(data.unread || 0);
          countNode.textContent = String(unread > 99 ? '99+' : unread);
          countNode.hidden = unread <= 0;
          notificationBell.classList.toggle('has-unread', unread > 0);
        }
        const items = data.items || [];
        if (initialized || lastId > 0) items.forEach(showSignalToast);
        lastId = Math.max(lastId, Number(data.latest_id || 0));
        try { sessionStorage.setItem(lastKey, String(lastId)); } catch (_) {}
        initialized = true;
      } catch (_) {}
    };
    refreshNotifications();
    setInterval(refreshNotifications, 4000);
  }

  const jobsRoot = document.querySelector('[data-jobs]');
  if (jobsRoot) {
    const jobsUrl = jobsRoot.dataset.jobsUrl;
    const knownJobStatus = new Map();
    let jobsInitialized = false;
    const refreshJobs = async () => {
      if (!jobsUrl) return;
      try {
        const res = await fetch(jobsUrl, {headers:{'Accept':'application/json'}});
        if (!res.ok) return;
        const data = await res.json();
        const jobs = data.jobs || [];
        if (!jobs.length) return;
        for (const j of jobs) {
          const previous = knownJobStatus.get(j.id);
          if (jobsInitialized && previous && previous !== 'done' && j.status === 'done') showJobToast(j);
          knownJobStatus.set(j.id, j.status);
        }
        jobsInitialized = true;
        jobsRoot.innerHTML = jobs.map(j => `<div class="job"><span class="status-dot ${esc(j.status)}"></span><div><strong>${esc(j.label)}</strong><small>${esc(uiStatus(j.status))} · ${esc(j.started_at || j.queued_at)}</small>${j.error ? `<small class="error">${esc(j.error)}</small>` : ''}</div></div>`).join('');
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
        document.querySelectorAll('[data-progress-key]').forEach(node => {
          const key = node.dataset.progressKey;
          if (Object.prototype.hasOwnProperty.call(data, key)) {
            const pct = Math.max(0, Math.min(100, Number(data[key]) || 0));
            node.style.width = `${pct}%`;
          }
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
            sessionStorage.setItem('negroJobToast', JSON.stringify({label: job.label || 'Inspección básica', summary: job.summary || {delta:{}}}));
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
            try {
              sessionStorage.setItem('negroJobToast', JSON.stringify({label, summary: job.summary || {delta:{}}}));
            } catch (_) {
              // A full job result may exceed browser storage. Never leave the UI stuck
              // just because the completion toast could not be persisted.
            }
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
        const cacheHit = Boolean(data.cached);
        const effectiveCop = cacheHit ? 0 : cop;
        const effectiveUsd = cacheHit ? 0 : Number(data.max_total_usd_est || 0);
        output.innerHTML = `
          <div class="ai-cost-grid">
            <div class="ai-cost-main">
              <span>${cacheHit ? 'Costo nueva ejecución (cache)' : 'Costo máximo estimado'}</span>
              <strong>${formatCop(effectiveCop)}</strong>
              <small>${cacheHit ? 'resultado ya analizado' : `≈ ${roundedCopWords(effectiveCop)}`}</small>
            </div>
            <div class="ai-cost-detail"><span>Equivalente USD</span><strong>${formatUsd(effectiveUsd)}</strong></div>
            <div class="ai-cost-detail"><span>Entrada estimada</span><strong>${Number(data.input_tokens_est).toLocaleString('es-CO')} tokens</strong></div>
            <div class="ai-cost-detail"><span>Salida presupuestada</span><strong>máx. ${Number(data.output_tokens_budget).toLocaleString('es-CO')} tokens</strong></div>
          </div>
          <div class="ai-cost-foot">${cacheHit ? `Cache hit: no se hará una nueva llamada billable. El análisis original tendría un tope teórico de ${formatCop(cop)}.` : 'Es un <b>tope estimado</b>; el costo real puede ser menor.'} Conversión usada: 1 USD = ${Number(data.usd_cop_rate).toLocaleString('es-CO',{maximumFractionDigits:2})} COP · precios ${esc(data.pricing_snapshot)}${data.long_context ? ' · contexto largo' : ''}.</div>
          <div class="ai-evidence-note">${data.task_type === 'target_triage' ? (data.cached ? `✓ Cache hit: esta evidencia ya fue analizada con ${esc(data.model)}. Se reutilizará el resultado con costo estimado COP $0.` : `✓ Triage global: Negro enviará sólo leads/evidencia correlacionada, fingerprints e histórico filtrado. Evidence hash: ${esc((data.evidence_hash || '').slice(0,12))}…`) : (data.source_map_included ? `✓ La evidencia de IA incluirá el <b>source map confirmado</b>${data.source_map_application_sources !== undefined ? ` · ${Number(data.source_map_application_sources).toLocaleString('es-CO')} fuentes de aplicación` : ''}${data.source_map_sources_with_content !== undefined ? ` · ${Number(data.source_map_sources_with_content).toLocaleString('es-CO')} con contenido` : ''}.` : 'La estimación usa sólo el análisis local del bundle; no hay source map confirmado asociado.')}</div>`;
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
