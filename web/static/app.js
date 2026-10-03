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

    let notificationsInFlight = false;
    let notificationTimer = null;
    const scheduleNotifications = (ms) => {
      if (notificationTimer) window.clearTimeout(notificationTimer);
      notificationTimer = window.setTimeout(refreshNotifications, ms);
    };
    const refreshNotifications = async () => {
      if (!notificationUrl || notificationsInFlight) return;
      notificationsInFlight = true;
      let nextDelay = document.hidden ? 20000 : 5000;
      try {
        const sep = notificationUrl.includes('?') ? '&' : '?';
        const res = await fetch(`${notificationUrl}${sep}after_id=${lastId}&limit=50`, {headers:{'Accept':'application/json'}});
        if (!res.ok) { nextDelay = 10000; return; }
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
        // Back off when nothing changed; foreground activity still feels realtime.
        if (!items.length) nextDelay = document.hidden ? 30000 : 8000;
      } catch (_) {
        nextDelay = 12000;
      } finally {
        notificationsInFlight = false;
        scheduleNotifications(nextDelay);
      }
    };
    refreshNotifications();
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) scheduleNotifications(250);
    });
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

  document.querySelectorAll('[data-auto-job-url]').forEach((node) => {
    const jobUrl = node.dataset.autoJobUrl;
    const refreshUrl = node.dataset.autoJobRefresh || window.location.pathname;
    if (!jobUrl) return;
    const startedAt = Date.now();
    pollJob(jobUrl, refreshUrl, node, null, startedAt).catch((err) => {
      setProgressMessage(node, `No pude revisar el historial: ${err.message}`, 'error');
    });
  });

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
          <div class="ai-cost-foot">${cacheHit ? `Acierto de caché: no se hará una nueva llamada facturable. El análisis original tendría un tope teórico de ${formatCop(cop)}.` : 'Es un <b>tope estimado</b>; el costo real puede ser menor.'} Conversión usada: 1 USD = ${Number(data.usd_cop_rate).toLocaleString('es-CO',{maximumFractionDigits:2})} COP · precios ${esc(data.pricing_snapshot)}${data.long_context ? ' · contexto largo' : ''}.</div>
          <div class="ai-evidence-note">${data.task_type === 'target_triage' ? (data.cached ? `✓ Acierto de caché: esta evidencia ya fue analizada con ${esc(data.model)}. Se reutilizará el resultado con costo estimado COP $0.` : `✓ Priorización global: Negro enviará sólo leads/evidencia correlacionada, fingerprints e histórico filtrado. Hash de evidencia: ${esc((data.evidence_hash || '').slice(0,12))}…`) : (data.source_map_included ? `✓ La evidencia de IA incluirá el <b>source map confirmado</b>${data.source_map_application_sources !== undefined ? ` · ${Number(data.source_map_application_sources).toLocaleString('es-CO')} fuentes de aplicación` : ''}${data.source_map_sources_with_content !== undefined ? ` · ${Number(data.source_map_sources_with_content).toLocaleString('es-CO')} con contenido` : ''}.` : 'La estimación usa sólo el análisis local del bundle; no hay source map confirmado asociado.')}</div>`;
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

// v0.16.2 — Repeater hand-off observable in the UI.
(() => {
  const bindRepeaterForms = () => {
    document.querySelectorAll('form[data-repeater-form]').forEach((form) => {
      if (form.dataset.repeaterBound === '1') return;
      form.dataset.repeaterBound = '1';
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const button = form.querySelector('button[type="submit"]');
        const status = form.querySelector('[data-repeater-status]');
        if (button?.disabled) return;
        if (button) button.disabled = true;
        if (status) { status.textContent = 'Encolando…'; status.className = 'repeater-inline-status pending'; }
        try {
          const res = await fetch(form.action, {
            method: 'POST',
            body: new FormData(form),
            headers: {'Accept':'application/json','X-Requested-With':'NegroFetch'}
          });
          let data = {};
          try { data = await res.json(); } catch (_) {}
          if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
          const bytes = Number(data.request_bytes || 0);
          const qid = Number(data.queue_id || 0);
          if (status) {
            status.textContent = `Encolada #${qid || '?'} · ${bytes} B · esperando Burp…`;
            status.className = 'repeater-inline-status ok';
          }
          if (button) button.textContent = 'Encolada ✓';
        } catch (err) {
          if (status) { status.textContent = `Error: ${err.message}`; status.className = 'repeater-inline-status error'; }
          if (button) button.disabled = false;
        }
      });
    });
  };
  bindRepeaterForms();
})();

// v0.28 guided Business Object teaching: suggestions never overwrite silently.
document.querySelectorAll('[data-fill-object-type]').forEach((button) => {
  button.addEventListener('click', () => {
    const card = button.closest('[data-object-candidate]');
    const input = card?.querySelector('[data-object-type-input]');
    if (!input) return;
    input.value = button.dataset.fillObjectType || '';
    input.focus();
    input.select();
  });
});

// v0.41 — Request Workbench: readable HTTP, syntax cues, local search, copy and focus mode.
(() => {
  const escapeRegExp = (value) => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  const appendPiece = (parent, text, className, query) => {
    const value = String(text ?? '');
    const q = String(query || '').trim();
    const token = document.createElement('span');
    if (className) token.className = className;
    if (!q) {
      token.textContent = value;
      parent.appendChild(token);
      return;
    }
    const re = new RegExp(escapeRegExp(q), 'gi');
    let last = 0, match, guard = 0;
    while ((match = re.exec(value)) && guard < 5000) {
      if (match.index > last) token.appendChild(document.createTextNode(value.slice(last, match.index)));
      const mark = document.createElement('mark');
      mark.className = 'http-match';
      mark.textContent = match[0];
      token.appendChild(mark);
      last = match.index + match[0].length;
      if (!match[0].length) re.lastIndex += 1;
      guard += 1;
    }
    if (last < value.length) token.appendChild(document.createTextNode(value.slice(last)));
    parent.appendChild(token);
  };

  const appendBodySyntax = (parent, line, query) => {
    // Lightweight lexer: JSON strings/keys, numbers/booleans and form/query keys.
    const tokenRe = /("(?:\\.|[^"\\])*")(\s*:)?|(-?\b\d+(?:\.\d+)?\b)|\b(true|false|null)\b|\b([A-Za-z_][A-Za-z0-9_.-]*)(=)/g;
    let last = 0, match, guard = 0;
    while ((match = tokenRe.exec(line)) && guard < 2000) {
      if (match.index > last) appendPiece(parent, line.slice(last, match.index), '', query);
      if (match[1] !== undefined) {
        appendPiece(parent, match[1], match[2] ? 'http-token-key' : 'http-token-string', query);
        if (match[2]) appendPiece(parent, match[2], 'http-token-punctuation', query);
      } else if (match[3] !== undefined) {
        appendPiece(parent, match[3], 'http-token-number', query);
      } else if (match[4] !== undefined) {
        appendPiece(parent, match[4], 'http-token-literal', query);
      } else if (match[5] !== undefined) {
        appendPiece(parent, match[5], 'http-token-key', query);
        appendPiece(parent, match[6], 'http-token-punctuation', query);
      }
      last = match.index + match[0].length;
      guard += 1;
    }
    if (last < line.length) appendPiece(parent, line.slice(last), '', query);
  };

  const renderHttp = (pane, query = '') => {
    const content = pane?.querySelector('[data-http-content]');
    const countEl = pane?.querySelector('[data-http-count]');
    if (!content) return [];
    if (content.dataset.rawHttp === undefined) content.dataset.rawHttp = content.textContent || '';
    const raw = String(content.dataset.rawHttp || '').replace(/\r\n/g, '\n');
    const lines = raw.split('\n');
    content.replaceChildren();
    let inHeaders = true;

    lines.forEach((line, index) => {
      const row = document.createElement('span');
      row.className = 'http-line';
      row.dataset.line = String(index + 1);
      const code = document.createElement('span');
      code.className = 'http-line-code';
      row.appendChild(code);

      if (index === 0) {
        const req = line.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/\S+)$/);
        const res = line.match(/^(HTTP\/\S+)\s+(\d{3})(?:\s+(.*))?$/);
        if (req) {
          appendPiece(code, req[1], 'http-token-method', query); appendPiece(code, ' ', '', query);
          appendPiece(code, req[2], 'http-token-target', query); appendPiece(code, ' ', '', query);
          appendPiece(code, req[3], 'http-token-protocol', query);
        } else if (res) {
          const status = Number(res[2]);
          appendPiece(code, res[1], 'http-token-protocol', query); appendPiece(code, ' ', '', query);
          appendPiece(code, res[2], status < 300 ? 'http-token-status-ok' : status < 400 ? 'http-token-status-redirect' : 'http-token-status-error', query);
          if (res[3]) { appendPiece(code, ' ', '', query); appendPiece(code, res[3], 'http-token-status-text', query); }
        } else appendPiece(code, line, '', query);
      } else if (inHeaders && line === '') {
        inHeaders = false;
        row.classList.add('http-separator-line');
        appendPiece(code, ' ', '', query);
      } else if (inHeaders && line.includes(':')) {
        const pos = line.indexOf(':');
        const name = line.slice(0, pos);
        const value = line.slice(pos + 1);
        const sensitive = /^(authorization|cookie|set-cookie|x-api-key|api-key)$/i.test(name.trim());
        appendPiece(code, name, sensitive ? 'http-token-header-name http-token-sensitive' : 'http-token-header-name', query);
        appendPiece(code, ':', 'http-token-punctuation', query);
        appendPiece(code, value, sensitive ? 'http-token-header-value http-token-sensitive-value' : 'http-token-header-value', query);
      } else {
        appendBodySyntax(code, line, query);
      }
      content.appendChild(row);
    });

    const marks = [...content.querySelectorAll('.http-match')];
    if (countEl) countEl.textContent = `${marks.length} coincidencia${marks.length === 1 ? '' : 's'}`;
    pane.dataset.httpMatchIndex = '0';
    return marks;
  };

  document.querySelectorAll('[data-http-pane]').forEach((pane) => {
    const input = pane.querySelector('[data-http-search]');
    const next = pane.querySelector('[data-http-next]');
    const copy = pane.querySelector('[data-http-copy]');
    const wrap = pane.querySelector('[data-http-wrap]');
    const expand = pane.querySelector('[data-http-expand]');
    const content = pane.querySelector('[data-http-content]');
    if (content && content.dataset.rawHttp === undefined) content.dataset.rawHttp = content.textContent || '';
    renderHttp(pane, '');

    input?.addEventListener('input', () => {
      const marks = renderHttp(pane, input.value);
      if (marks[0]) {
        marks[0].classList.add('current');
        marks[0].scrollIntoView({block:'center'});
      }
    });
    next?.addEventListener('click', () => {
      const marks = [...pane.querySelectorAll('.http-match')];
      if (!marks.length) return;
      marks.forEach(m => m.classList.remove('current'));
      let idx = Number(pane.dataset.httpMatchIndex || 0);
      idx = (idx + 1) % marks.length;
      pane.dataset.httpMatchIndex = String(idx);
      marks[idx].classList.add('current');
      marks[idx].scrollIntoView({block:'center',behavior:'smooth'});
    });
    copy?.addEventListener('click', async () => {
      const raw = content?.dataset.rawHttp ?? content?.textContent ?? '';
      try {
        await navigator.clipboard.writeText(raw);
        const old = copy.textContent;
        copy.textContent = 'Copiado ✓';
        window.setTimeout(() => { copy.textContent = old; }, 1200);
      } catch (_) {
        copy.textContent = 'No se pudo copiar';
      }
    });
    wrap?.addEventListener('click', () => {
      pane.classList.toggle('wrap');
      wrap.textContent = pane.classList.contains('wrap') ? 'Líneas exactas' : 'Ajustar líneas';
    });
    expand?.addEventListener('click', () => {
      pane.classList.toggle('fullscreen-pane');
      expand.textContent = pane.classList.contains('fullscreen-pane') ? 'Cerrar pantalla completa' : 'Pantalla completa';
    });
  });
})();

// v0.39 · Flow Intelligence + Runner UX
(()=>{
  const root=document.querySelector('[data-flow-logic]');
  if(root){
    const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const flowId=Number(root.dataset.flowId||0);
    const base=(location.pathname.match(/^\/t\/[^/]+/)||[''])[0];
    const estimateBtn=root.querySelector('[data-flow-ai-estimate]');
    const runBtn=root.querySelector('[data-flow-ai-run]');
    const model=root.querySelector('[data-flow-ai-model]');
    const status=root.querySelector('[data-flow-ai-status]');
    const results=root.querySelector('[data-flow-ai-results]');
    const csrf=document.querySelector('input[name="csrf"]')?.value||'';
    const money=n=>new Intl.NumberFormat('es-CO',{style:'currency',currency:'COP',maximumFractionDigits:0}).format(Number(n||0));
    const ideaCard=(idea,idx)=>{
      const facts=(idea.facts||[]).map(x=>`<li>${esc(x)}</li>`).join('');
      const unknowns=(idea.unknowns||[]).map(x=>`<li>${esc(x)}</li>`).join('');
      const review=(idea.runner?.review_before_run||[]).map(x=>`<li>${esc(x)}</li>`).join('');
      const steps=(idea.runner?.step_actions||[]).filter(x=>x.action!=='keep').map(x=>`<span class="runner-draft-change">Paso ${Number(x.position||0)} · ${esc(({omit:'omitir',repeat:'repetir'}[x.action]||x.action))}${x.action==='repeat'?` ×${Number(x.repeat_count||1)}`:''}</span>`).join('');
      const vars=(idea.runner?.variables||[]).map(x=>`<span class="runner-draft-change">${esc(x.target_name)} · ${esc(x.mode)}</span>`).join('');
      const payload=esc(JSON.stringify(idea));
      return `<article class="flow-idea-card priority-${esc(idea.priority||'medium')}">
        <div class="flow-idea-top"><div><span class="badge">${esc(idea.category||'lógica')}</span><span class="badge">${esc(idea.priority||'medium')}</span></div><small>Idea ${idx+1}</small></div>
        <h3>${esc(idea.question||idea.alias||'Pregunta de lógica')}</h3>
        <p class="flow-idea-rationale">${esc(idea.rationale||'')}</p>
        <div class="flow-idea-goal"><b>Qué intentamos comprobar</b><span>${esc(idea.test_goal||'')}</span></div>
        ${steps||vars?`<div class="runner-draft-preview"><b>Runner sugerido · ${esc(idea.alias||'Borrador')}</b><div>${steps}${vars}</div></div>`:''}
        <details><summary>Por qué / qué falta</summary><div class="grid two"><div><b>Hechos</b><ul>${facts||'<li>Sin hechos adicionales.</li>'}</ul></div><div><b>Incógnitas</b><ul>${unknowns||'<li>Sin incógnitas listadas.</li>'}</ul></div></div>${review?`<div><b>Revisar antes de ejecutar</b><ul>${review}</ul></div>`:''}<p><b>Confirmaría interés si:</b> ${esc(idea.confirm_if||'')}</p><p><b>Descartaría si:</b> ${esc(idea.discard_if||'')}</p></details>
        <div class="flow-idea-actions">
          <form action="${base}/flows/${flowId}/hypothesis/from-ai" method="post"><input type="hidden" name="csrf" value="${esc(csrf)}"><textarea name="idea_json" hidden>${payload}</textarea><button class="btn-secondary" type="submit">◆ Convertir en Hipótesis</button></form>
        </div>
      </article>`;
    };
    const render=data=>{
      if(!results) return;
      const ideas=Array.isArray(data?.ideas)?data.ideas:[];
      const covered=(data?.already_covered||[]).map(x=>`<span class="badge">✓ ${esc(x)}</span>`).join('');
      const gaps=(data?.context_gaps||[]).map(x=>`<li>${esc(x)}</li>`).join('');
      results.innerHTML=`${data?.summary?`<div class="flow-ai-summary">${esc(data.summary)}</div>`:''}${covered?`<details class="flow-ai-memory"><summary>Lo que Negro evitó repetir</summary><div class="badges">${covered}</div></details>`:''}<div class="flow-idea-grid">${ideas.map(ideaCard).join('')}</div>${!ideas.length?'<div class="empty-state"><strong>No encontré una pregunta nueva suficientemente anclada en evidencia.</strong><span>Eso también es útil: sigue navegando o captura más estado del proceso y vuelve a intentarlo.</span></div>':''}${gaps?`<details><summary>Contexto que ayudaría a pensar mejor</summary><ul>${gaps}</ul></details>`:''}`;
    };
    try{
      const initial=JSON.parse(root.querySelector('[data-flow-ai-initial]')?.textContent||'{}');
      if(initial && Array.isArray(initial.ideas) && initial.ideas.length){status.textContent=`Historial disponible${initial.created_at?' · última exploración '+initial.created_at:''}. Las Ideas persistentes están debajo.`;}
    }catch(_e){}
    estimateBtn?.addEventListener('click',async()=>{
      estimateBtn.disabled=true; status.textContent='Construyendo contexto del Flow y de los Runners previos…';
      try{
        const u=new URL(root.dataset.estimateUrl,location.origin);u.searchParams.set('model',model?.value||'');
        const r=await fetch(u,{headers:{Accept:'application/json'}});const d=await r.json();if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);
        status.innerHTML=`<b>${d.cached?'Análisis cacheado':'Costo máximo estimado'}</b> · ${d.cached?'COP $0':money(d.max_total_cop_est)} · entrada ≈ ${Number(d.input_tokens_est||0).toLocaleString('es-CO')} tokens<br><small>Incluye secuencia, HTTP sanitizado, Signals, estados y memoria de Runners previos con muestras de Runs recientes.</small>`;
        runBtn?.removeAttribute('hidden');
      }catch(err){status.textContent=`No pude estimar: ${err.message}`;}finally{estimateBtn.disabled=false;}
    });
    runBtn?.addEventListener('click',async()=>{
      runBtn.disabled=true;status.textContent='IA pensando sobre el Flow y evitando repetir lo ya probado…';
      try{
        const fd=new FormData();fd.set('csrf',csrf);fd.set('confirm_cost','yes');fd.set('model',model?.value||'');
        const r=await fetch(root.dataset.runUrl,{method:'POST',body:fd,headers:{Accept:'application/json'}});const d=await r.json();if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);
        while(true){await new Promise(x=>setTimeout(x,1200));const jr=await fetch(d.job_url,{headers:{Accept:'application/json'}});const job=await jr.json();if(job.status==='done'){status.textContent='Ideas guardadas en el historial. Actualizando…';location.href=location.pathname+'#ai-ideas-history';break;}if(job.status==='error')throw new Error(job.error||'La IA falló');status.textContent='IA analizando Requests/Responses, Runners anteriores y estado del Flow…';}
      }catch(err){status.textContent=`Error: ${err.message}`;}finally{runBtn.disabled=false;}
    });
  }

  const jobBox=document.querySelector('[data-runner-job]');
  if(jobBox){
    const id=jobBox.dataset.jobId;const text=jobBox.querySelector('[data-runner-job-status]');
    const poll=async()=>{try{const r=await fetch(`/api/jobs/${encodeURIComponent(id)}`,{headers:{Accept:'application/json'}});const d=await r.json();if(d.status==='done'){if(text)text.textContent='Runner terminado. Actualizando evidencia…';setTimeout(()=>{const u=new URL(location.href);u.searchParams.delete('job');location.href=u.toString()+'#runner-history';},450);return;}if(d.status==='error'){if(text)text.textContent=`Error: ${d.error||'Runner falló'}`;return;}if(text)text.textContent='Ejecutando secuencialmente…';setTimeout(poll,1200);}catch(err){if(text)text.textContent=`No pude consultar el estado: ${err.message}`;}};poll();
  }
})();

// v0.41 · Runner transport diagnostic (explicit, one HEAD request)
(()=>{
  document.querySelectorAll('[data-transport-diagnose]').forEach(btn=>{
    btn.addEventListener('click',async()=>{
      const out=btn.closest('.transport-diagnostic')?.querySelector('[data-transport-result]');
      btn.disabled=true;if(out)out.textContent='Comprobando transporte del Runner…';
      try{
        const r=await fetch(btn.dataset.url,{headers:{Accept:'application/json'}});
        const d=await r.json();if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);
        if(out)out.textContent=JSON.stringify(d,null,2);
      }catch(err){if(out)out.textContent=`Error de diagnóstico: ${err.message}`;}
      finally{btn.disabled=false;}
    });
  });
})();
