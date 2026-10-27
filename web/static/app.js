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
    if (content.dataset.rawHttp === undefined) {
      content.dataset.rawHttp = content.textContent || '';
      if (content.querySelector('.http-annotation')) content.dataset.annotatedHtml = content.innerHTML;
    }
    if (!String(query || '').trim() && content.dataset.annotatedHtml) {
      content.innerHTML = content.dataset.annotatedHtml;
      if (countEl) countEl.textContent = 'contexto resaltado';
      return [];
    }
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

  const wrapPrefKey = 'negro.http.wrap';
  const wrapDefault = localStorage.getItem(wrapPrefKey) !== 'off';
  document.querySelectorAll('[data-http-pane]').forEach((pane) => {
    const input = pane.querySelector('[data-http-search]');
    const next = pane.querySelector('[data-http-next]');
    const copy = pane.querySelector('[data-http-copy]');
    const wrap = pane.querySelector('[data-http-wrap]');
    const expand = pane.querySelector('[data-http-expand]');
    const content = pane.querySelector('[data-http-content]');
    if (wrapDefault) pane.classList.add('wrap');
    else pane.classList.remove('wrap');
    if (wrap) wrap.textContent = pane.classList.contains('wrap') ? 'Líneas exactas' : 'Ajustar líneas';
    if (content && content.dataset.rawHttp === undefined) {
      content.dataset.rawHttp = content.textContent || '';
      if (content.querySelector('.http-annotation')) content.dataset.annotatedHtml = content.innerHTML;
    } else if (content && !content.dataset.annotatedHtml && content.querySelector('.http-annotation')) {
      content.dataset.annotatedHtml = content.innerHTML;
    }
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
      const enabled = pane.classList.contains('wrap');
      localStorage.setItem(wrapPrefKey, enabled ? 'on' : 'off');
      document.querySelectorAll('[data-http-pane]').forEach(p => p.classList.toggle('wrap', enabled));
      document.querySelectorAll('[data-http-wrap]').forEach(b => { b.textContent = enabled ? 'Líneas exactas' : 'Ajustar líneas'; });
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
        ${steps||vars?`<div class="runner-draft-preview"><b>Escenario sugerido · ${esc(idea.alias||'Borrador')}</b><div>${steps}${vars}</div></div>`:''}
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
      estimateBtn.disabled=true; status.textContent='Construyendo contexto del Flow y de las pruebas previas…';
      try{
        const u=new URL(root.dataset.estimateUrl,location.origin);u.searchParams.set('model',model?.value||'');
        const r=await fetch(u,{headers:{Accept:'application/json'}});const d=await r.json();if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);
        status.innerHTML=`<b>${d.cached?'Análisis cacheado':'Costo máximo estimado'}</b> · ${d.cached?'COP $0':money(d.max_total_cop_est)} · entrada ≈ ${Number(d.input_tokens_est||0).toLocaleString('es-CO')} tokens<br><small>Incluye secuencia, HTTP sanitizado, Signals, estados y memoria de pruebas previas con muestras de Runs recientes.</small>`;
        runBtn?.removeAttribute('hidden');
      }catch(err){status.textContent=`No pude estimar: ${err.message}`;}finally{estimateBtn.disabled=false;}
    });
    runBtn?.addEventListener('click',async()=>{
      runBtn.disabled=true;status.textContent='IA pensando sobre el Flow y evitando repetir lo ya probado…';
      try{
        const fd=new FormData();fd.set('csrf',csrf);fd.set('confirm_cost','yes');fd.set('model',model?.value||'');
        const r=await fetch(root.dataset.runUrl,{method:'POST',body:fd,headers:{Accept:'application/json'}});const d=await r.json();if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);
        while(true){await new Promise(x=>setTimeout(x,1200));const jr=await fetch(d.job_url,{headers:{Accept:'application/json'}});const job=await jr.json();if(job.status==='done'){status.textContent='Ideas guardadas en el historial. Actualizando…';location.href=location.pathname+'#ai-ideas-history';break;}if(job.status==='error')throw new Error(job.error||'La IA falló');status.textContent='IA analizando Requests/Responses, pruebas anteriores y estado del Flow…';}
      }catch(err){status.textContent=`Error: ${err.message}`;}finally{runBtn.disabled=false;}
    });
  }

  const jobBox=document.querySelector('[data-runner-job]');
  if(jobBox){
    const id=jobBox.dataset.jobId;const text=jobBox.querySelector('[data-runner-job-status]');
    const poll=async()=>{try{const r=await fetch(`/api/jobs/${encodeURIComponent(id)}`,{headers:{Accept:'application/json'}});const d=await r.json();if(d.status==='done'){if(text)text.textContent='Prueba terminada. Actualizando evidencia…';setTimeout(()=>{const u=new URL(location.href);u.searchParams.delete('job');location.href=u.toString()+'#runner-history';},450);return;}if(d.status==='error'){if(text)text.textContent=`Error: ${d.error||'La prueba falló'}`;return;}if(text)text.textContent='Ejecutando secuencialmente…';setTimeout(poll,1200);}catch(err){if(text)text.textContent=`No pude consultar el estado: ${err.message}`;}};poll();
  }
})();

// v0.41 · Runner transport diagnostic (explicit, one HEAD request)
(()=>{
  document.querySelectorAll('[data-transport-diagnose]').forEach(btn=>{
    btn.addEventListener('click',async()=>{
      const out=btn.closest('.transport-diagnostic')?.querySelector('[data-transport-result]');
      btn.disabled=true;if(out)out.textContent='Comprobando transporte de la prueba…';
      try{
        const r=await fetch(btn.dataset.url,{headers:{Accept:'application/json'}});
        const d=await r.json();if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);
        if(out)out.textContent=JSON.stringify(d,null,2);
      }catch(err){if(out)out.textContent=`Error de diagnóstico: ${err.message}`;}
      finally{btn.disabled=false;}
    });
  });
})();

// v0.47.2 · persistent HTTP context visibility toggles across every HTTP viewer
(()=>{
  const roots=[...document.querySelectorAll('[data-http-highlight-root]')];
  if(!roots.length) return;
  const specs=[
    ['[data-highlight-identity]','negro.http.identity',true,'hide-identity-highlights'],
    ['[data-highlight-objects]','negro.http.objects',true,'hide-object-highlights'],
    ['[data-highlight-context]','negro.http.context',false,'hide-context-highlights']
  ];
  const current=(key,def)=>{const saved=localStorage.getItem(key); return saved===null?def:saved==='on';};
  const apply=()=>{
    specs.forEach(([sel,key,def,klass])=>{
      const on=current(key,def);
      document.querySelectorAll(sel).forEach(el=>{ if(el.checked!==on) el.checked=on; });
      roots.forEach(root=>root.classList.toggle(klass,!on));
    });
  };
  specs.forEach(([sel,key,def])=>{
    document.querySelectorAll(sel).forEach(el=>{
      el.checked=current(key,def);
      el.addEventListener('change',()=>{
        localStorage.setItem(key,el.checked?'on':'off');
        apply();
      });
    });
  });
  apply();
})();

// v0.110 · live Flow/Scenario execution timeline.
(()=>{
  const root=document.querySelector('[data-scenario-live],[data-flow-live]');
  if(!root) return;
  const url=root.dataset.liveUrl;
  const initialStatus=String(root.dataset.runStatus||'');
  const total=Math.max(0,Number(root.dataset.liveTotal||0));
  const stepsRoot=root.querySelector('[data-live-steps]');
  const count=root.querySelector('[data-live-count]');
  const progress=root.querySelector('[data-live-progress]');
  const badge=root.querySelector('[data-live-status-badge]');
  const title=root.querySelector('[data-live-title]');
  const escLive=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const labels={queued:'Preparando…',running:'Ejecutando…',waiting_input:'Esperando input',waiting_prerequisite:'Esperando requisito',completed:'Completado',failed:'Falló',aborted:'Abortado'};
  let stopped=false;
  const render=(data)=>{
    const run=data.run||{};
    const items=Array.isArray(data.attempts)?data.attempts:(Array.isArray(data.steps)?data.steps:[]);
    const status=String(run.status||'');
    if(count) count.textContent=String(items.length);
    if(progress) progress.style.width=`${total?Math.min(100,(items.length/total)*100):0}%`;
    if(badge){badge.textContent=labels[status]||status;badge.className=`badge run-state state-${escLive(status)}`;}
    if(title){
      if(status==='waiting_input') title.textContent='Esperando tu input';
      else if(status==='completed') title.textContent=root.hasAttribute('data-scenario-live')?'Prueba terminada':'Reproducción terminada';
      else if(status==='failed') title.textContent='Run detenido';
      else title.textContent=root.hasAttribute('data-scenario-live')?'Ejecutando prueba…':'Ejecutando Flow…';
    }
    if(stepsRoot){
      const html=items.map((s,idx)=>{
        const pos=Number(s.position||idx+1);
        const method=escLive(s.method||'');
        const path=escLive(s.path||'');
        const code=s.status_code==null?'…':`HTTP ${escLive(s.status_code)}`;
        const elapsed=s.elapsed_ms==null?'':`${escLive(s.elapsed_ms)} ms`;
        const err=s.error?`<small class="error">${escLive(s.error)}</small>`:'';
        return `<div class="live-run-step ${s.error?'has-error':''}"><span class="live-step-number">${pos}</span><b>${method} <code title="${path}">${path}</code></b><span class="badge">${code}</span><small>${elapsed}</small>${err}</div>`;
      }).join('');
      const next=(status==='running'||status==='queued') && items.length<total?`<div class="live-run-step is-running"><span class="live-step-number">${items.length+1}</span><b>Ejecutando siguiente Step…</b><span class="spinner-dot">●</span></div>`:'';
      stepsRoot.innerHTML=html+next || '<div class="live-run-empty">Preparando ejecución…</div>';
    }
    // A server-rendered refresh is needed to expose the secure input form and,
    // once done, the complete evidence/history. Do it only when the page was
    // loaded in a different state so terminal pages do not reload forever.
    if(status==='waiting_input' && initialStatus!=='waiting_input'){
      stopped=true; window.setTimeout(()=>window.location.reload(),250); return;
    }
    if(['completed','failed','aborted'].includes(status)){
      stopped=true;
      if(initialStatus!==status) window.setTimeout(()=>window.location.reload(),500);
    }
  };
  const poll=async()=>{
    if(stopped||!url) return;
    try{
      const res=await fetch(url,{headers:{Accept:'application/json'},cache:'no-store'});
      if(!res.ok) throw new Error(`HTTP ${res.status}`);
      render(await res.json());
    }catch(err){
      const empty=root.querySelector('[data-live-empty]');
      if(empty) empty.textContent=`No pude actualizar el Run: ${err.message}`;
    }
    if(!stopped) window.setTimeout(poll,650);
  };
  if(!['completed','failed','aborted','waiting_input'].includes(initialStatus)) poll();
})();

// v0.115 · Live Traffic Timeline: exact capture events, unread state, live follow and JWT inspector.
(()=>{
  const root=document.querySelector('[data-workbench]');
  if(!root) return;
  const detailUrl=root.dataset.detailUrl;
  const liveUrl=root.dataset.liveUrl;
  const seenAllUrl=root.dataset.seenAllUrl;
  const createFlowUrl=root.dataset.createFlowUrl;
  const targetKey=root.dataset.targetKey||'';
  const list=root.querySelector('[data-traffic-list]');
  const rows=()=>[...root.querySelectorAll('[data-source-key][data-event-id]')];
  const esc=(v)=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  const methodClass=(m)=>`wb-method method-${String(m||'').toLowerCase()}`;
  let selected={source:'',event:0,exchange:0};
  const active=root.querySelector('.wb-traffic-row.active');
  if(active) selected={source:active.dataset.sourceKey||'',event:Number(active.dataset.eventId||0),exchange:Number(active.dataset.exchangeId||0)};
  const raw={request:root.querySelector('[data-http-view="request"] code')?.textContent||'',response:root.querySelector('[data-http-view="response"] code')?.textContent||''};
  const mode={request:'pretty',response:'pretty'};
  let annotations=[];
  try{annotations=JSON.parse(root.querySelector('[data-workbench-annotations]')?.textContent||'[]')||[];}catch(_){annotations=[];}

  // ---- Calm HTTP rendering -------------------------------------------------
  const prettyHttp=(text)=>{
    const src=String(text||'');
    const sep=src.includes('\r\n\r\n')?'\r\n\r\n':'\n\n';
    const idx=src.indexOf(sep);
    if(idx<0) return src;
    const head=src.slice(0,idx),body=src.slice(idx+sep.length),trimmed=body.trim();
    if(!trimmed) return src;
    try{return `${head}${sep}${JSON.stringify(JSON.parse(trimmed),null,2)}`;}catch(_){return src;}
  };
  const semanticCss=(cls)=>({auth:'http-ann-auth',resolver:'http-ann-resolver',context:'http-ann-context',entity:'http-ann-entity'}[String(cls||'').toLowerCase()]||'');
  const semanticLabel=(a)=>{const cls=String(a.classification||'').toUpperCase(),owner=String(a.identity_name||a.object_type||'').trim();return owner?`${cls} · ${owner}`:cls;};
  const regexEscape=(v)=>String(v||'').replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const looksJwt=(v)=>/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(String(v||'').trim());
  const compactText=(v)=>{const x=String(v||'');return x.length>86?`${x.slice(0,34)}…${x.slice(-18)}`:x;};
  const jwtSummary=(token)=>{
    try{
      const p=String(token).split('.')[1],pad=p.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-p.length%4)%4);
      const obj=JSON.parse(decodeURIComponent(escape(atob(pad))));
      return ['iss','sub','aud','exp'].filter(k=>obj[k]!=null).map(k=>`${k}: ${Array.isArray(obj[k])?obj[k].join(','):obj[k]}`).join(' · ');
    }catch(_){return '';}
  };
  const smartValue=(value,label='value')=>{
    const v=String(value||''),jwt=looksJwt(v),long=v.length>86;
    if(!jwt&&!long) return esc(v);
    const badge=jwt?'JWT':'long';
    const summary=jwt?jwtSummary(v):'';
    const jwtAttr=jwt?` data-jwt-token="${esc(v)}"`:'';
    const title=jwt?'Abrir JWT Inspector':((summary?summary+' · ':'')+'Clic para copiar el valor completo');
    return `<span class="wb-compact-value ${jwt?'is-jwt':''}" data-copy-value="${esc(v)}"${jwtAttr} title="${esc(title)}">${esc(compactText(v))}<em>${badge}</em></span>`;
  };
  const semanticApplies=(a,line,idx,bodyStarted)=>{
    const loc=String(a.location||'').toLowerCase(),key=String(a.key_name||''),value=String(a.value_raw||a.value_preview||'');
    if(!value) return false;
    if(loc.includes('_header:')){const h=loc.split(':',2)[1]||'';return new RegExp(`^${regexEscape(h)}\\s*:`, 'i').test(line) && line.includes(value);}
    if(loc.includes('_cookie:')) return /^(cookie|set-cookie)\s*:/i.test(line) && (!key||line.toLowerCase().includes(key.toLowerCase())) && line.includes(value);
    if(loc.includes('_query:')) return idx===0 && (!key||line.toLowerCase().includes(key.toLowerCase())) && (line.includes(value)||line.includes(encodeURIComponent(value)));
    if(loc.includes('_json:')) return bodyStarted && (!key||line.toLowerCase().includes(`"${key.toLowerCase()}"`)) && line.includes(value);
    if(loc.includes('_form:')) return bodyStarted && (!key||line.toLowerCase().includes(key.toLowerCase())) && line.includes(value);
    return line.includes(value) && (value.length>=8 || (!!key && line.toLowerCase().includes(key.toLowerCase())));
  };
  const decorateSemantic=(html,line,side,idx,bodyStarted)=>{
    let out=html;
    const candidates=(annotations||[]).filter(a=>String(a.side||'')===side&&semanticCss(a.classification)&&semanticApplies(a,line,idx,bodyStarted));
    for(const a of candidates){
      const rawValue=String(a.value_raw||a.value_preview||'');if(!rawValue)continue;
      const needle=esc(rawValue),css=semanticCss(a.classification),label=semanticLabel(a);
      if(!needle||!out.includes(needle))continue;
      const reason=[a.match_reason,a.source_exchange_id?`aprendido en #${a.source_exchange_id}`:''].filter(Boolean).join(' · ');
      out=out.replace(needle,`<span class="http-annotation ${css}" data-label="${esc(label)}" title="${esc(reason||label)}">${smartValue(rawValue,label)}</span>`);
    }
    return out;
  };
  const headerTone=(name)=>{
    const n=String(name||'').toLowerCase();
    if(['authorization','cookie','set-cookie','x-api-key','proxy-authorization'].includes(n)) return 'header-critical';
    if(n.includes('correlation')||n.includes('request-id')||n.includes('trace')||n.includes('session')||n.includes('tenant')||n.includes('user-id')) return 'header-context';
    if(['user-agent','accept','accept-language','accept-encoding','cache-control','connection','sec-fetch-dest','sec-fetch-mode','sec-fetch-site','priority'].includes(n)||n.startsWith('sec-ch-')) return 'header-muted';
    return '';
  };
  const compactKnownValue=(html,rawValue)=>{
    const v=String(rawValue||'').trim();if(!(looksJwt(v)||v.length>110))return html;
    const needle=esc(v);return html.includes(needle)?html.replace(needle,smartValue(v)):html;
  };
  const lineHtml=(line,idx,bodyStarted,side,smart)=>{
    if(!bodyStarted && idx===0){
      const m=line.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/\S+))?/);
      if(m){const h=`<span class="h-method">${esc(m[1])}</span> <span class="h-path">${esc(m[2])}</span>${m[3]?` <span class="h-proto">${esc(m[3])}</span>`:''}`;return `<span class="wb-http-line">${decorateSemantic(h,line,side,idx,bodyStarted)}</span>`;}
      const r=line.match(/^(HTTP\/\S+)\s+(\d+)(.*)$/);
      if(r){const h=`<span class="h-proto">${esc(r[1])}</span> <span class="h-method">${esc(r[2])}</span>${esc(r[3])}`;return `<span class="wb-http-line">${decorateSemantic(h,line,side,idx,bodyStarted)}</span>`;}
    }
    if(!bodyStarted){
      const h=line.match(/^([^:]+):(.*)$/);
      if(h){
        const name=h[1],value=h[2],tone=smart?headerTone(name):'';
        let x=`<span class="h-name">${esc(name)}</span>:<span class="h-value">${esc(value)}</span>`;
        x=decorateSemantic(x,line,side,idx,bodyStarted);
        if(smart)x=compactKnownValue(x,value);
        return `<span class="wb-http-line ${tone}">${x}</span>`;
      }
    }
    let out=esc(line);
    if(bodyStarted){
      out=out.replace(/(&quot;[^&\n]+?&quot;)(\s*:)/g,'<span class="h-json-key">$1</span>$2')
             .replace(/(:\s*)(&quot;.*?&quot;)/g,'$1<span class="h-json-string">$2</span>')
             .replace(/(:\s*)(-?\d+(?:\.\d+)?)/g,'$1<span class="h-json-number">$2</span>')
             .replace(/(:\s*)(true|false|null)/g,'$1<span class="h-json-bool">$2</span>');
      out=decorateSemantic(out,line,side,idx,bodyStarted);
      if(smart){const jm=line.match(/^\s*"[^"]+"\s*:\s*"([^"]*)"\s*,?\s*$/);if(jm)out=compactKnownValue(out,jm[1]);}
    }else out=decorateSemantic(out,line,side,idx,bodyStarted);
    return `<span class="wb-http-line">${out||' '}</span>`;
  };
  const paint=(side)=>{
    const pre=root.querySelector(`[data-http-view="${side}"]`),code=pre?.querySelector('code');if(!pre||!code)return;
    const smart=mode[side]==='pretty',text=smart?prettyHttp(raw[side]):raw[side];pre.classList.toggle('pretty',smart);
    let body=false;
    code.innerHTML=String(text||'').replace(/\r\n/g,'\n').split('\n').map((line,i)=>{const rendered=lineHtml(line,i,body,side,smart);if(line==='')body=true;return rendered;}).join('\n');
    root.querySelectorAll(`[data-view-mode="${side}"]`).forEach(b=>b.classList.toggle('active',b.dataset.mode===mode[side]));
  };
  paint('request');paint('response');

  // ---- Context rendering ---------------------------------------------------
  const renderIdentity=(d)=>{const card=root.querySelector('[data-context-card="identity"]');if(!card)return;const i=d.identity,matches=d.identity_matches||[];const inferred=!i&&matches.length?`<div class="wb-identity-matches">${matches.map(m=>`<div><strong>${esc(m.name)}</strong><span>Reconocida en HTTP · ${(m.classifications||[]).map(x=>esc(String(x).toUpperCase())).join(' + ')}</span></div>`).join('')}</div>`:'';card.innerHTML=`<div class="wb-card-title"><span>◎</span><b>Identity</b></div>${i?`<strong>${esc(i.name)}</strong><div class="wb-kv"><span>role</span><code>${esc(i.role||i.kind||'—')}</code><span>context</span><code>${esc(i.context_label||'—')}</code><span>confidence</span><code>${esc(i.confidence||'—')}</code></div>`:(inferred||'<p class="wb-muted">Sin Identity resuelta.</p>')}`;};
  const renderObjects=(d)=>{const card=root.querySelector('[data-context-card="objects"]');if(!card)return;const os=d.objects||[];card.innerHTML=`<div class="wb-card-title"><span>◇</span><b>Objects</b><em>${os.length}</em></div>${os.length?`<div class="wb-object-list">${os.map(o=>`<div><b>${esc(o.type_name)}</b><code>${esc(o.identifier_raw||o.identifier_preview||'')}</code></div>`).join('')}</div>`:'<p class="wb-muted">Sin Objects correlacionados.</p>'}`;};
  const renderSignals=(d)=>{const card=root.querySelector('[data-context-card="signals"]');if(!card)return;const ss=d.signals||[];card.innerHTML=`<div class="wb-card-title"><span>◉</span><b>Signals</b><em>${ss.length}</em></div>${ss.length?`<div class="wb-signal-list">${ss.map(s=>`<div><span class="signal-dot severity-${esc(s.severity)}"></span><span>${esc(s.title)}</span><em>${esc(s.severity)}</em></div>`).join('')}</div>`:'<p class="wb-muted">Sin Signals pendientes.</p>'}`;};
  const renderFlow=(d)=>{const card=root.querySelector('[data-context-card="flow"]');if(!card)return;const fs=d.flows||[];card.innerHTML=`<div class="wb-card-title"><span>⌁</span><b>Flow</b></div>${fs.length?`<div class="wb-flow-list">${fs.map(f=>`<a href="/t/${encodeURIComponent(d.target_key)}/flows/${Number(f.id)}#flow-step-${Number(f.step_id)}"><span>${Number(f.position||0)}</span><b>${esc(f.name)}</b><small>${esc(f.label||f.state_label||'Step observado')}</small></a>`).join('')}</div>`:'<p class="wb-muted">Esta Request aún no pertenece a un Flow.</p>'}`;};
  const renderRelated=(d)=>{const card=root.querySelector('[data-context-card="related"]');if(!card)return;const rs=d.related||[];card.innerHTML=`<summary class="wb-card-title"><span>↔</span><b>Related Requests</b><em>${rs.length}</em></summary>${rs.length?`<div class="wb-related-list">${rs.map(r=>`<button type="button" data-related-source="${esc(d.target_key)}" data-related-exchange="${Number(r.id)}"><b class="${methodClass(r.method)}">${esc(r.method)}</b><code>${esc(r.path)}</code><span>${esc(r.status_code??'—')}</span></button>`).join('')}</div>`:'<p class="wb-muted">Sin relaciones suficientes todavía.</p>'}`;};
  const renderActions=(d)=>{const card=root.querySelector('.wb-quick-actions');if(!card)return;const e=d.exchange||{};if(d.is_inbox){card.innerHTML='<summary class="wb-card-title"><span>⚡</span><b>Quick Actions</b></summary><p class="wb-inbox-note"><b>Traffic Inbox.</b> Se conservó esta Request sin ampliar scope. Asigna el host a un proyecto autorizado antes de usar acciones activas.</p><a class="wb-assign-project" href="/projects">Administrar proyectos</a>';return;}const t=encodeURIComponent(d.target_key),id=Number(e.id||0),rid=Number(e.resource_id||0);card.innerHTML=`<summary class="wb-card-title"><span>⚡</span><b>Quick Actions</b></summary><div class="wb-action-grid"><a href="/t/${t}/exchange/${id}/inspect">Inspector avanzado</a><a href="/t/${t}/parameters/related/${id}">Follow Value</a><a href="/t/${t}/flows/add?exchange_id=${id}">Add to Flow</a><a href="/t/${t}/replays/new?exchange_id=${id}">Replay / Identity</a></div><form class="wb-repeater-form" method="post" action="/t/${t}/resource/${rid}/send-repeater"><input type="hidden" name="csrf" value="${esc(root.dataset.csrf||window.NEGRO_CSRF||'')}"><input type="hidden" name="method" value="${esc(e.method||'GET')}"><input type="hidden" name="exchange_id" value="${id}"><button type="submit">Enviar a Burp Repeater</button></form>`;};
  const renderSemanticSummary=(d)=>{const el=root.querySelector('[data-semantic-summary]');if(!el)return;const c=d.semantic_counts||{},labels={auth:'AUTH',resolver:'RESOLVER',context:'CONTEXT',entity:'ENTITY'};el.innerHTML=Object.keys(labels).filter(k=>Number(c[k]||0)>0).map(k=>`<em class="wb-semantic-chip semantic-${k}">${labels[k]} ${Number(c[k])}</em>`).join('');};
  const setUnreadCount=(n)=>{const count=Math.max(0,Number(n)||0),badge=root.querySelector('[data-unread-badge]'),el=root.querySelector('[data-unread-count]');if(el)el.textContent=String(count);if(badge)badge.classList.toggle('is-empty',count===0);};
  const renderDetail=(d)=>{const e=d.exchange||{};raw.request=d.request_text||'';raw.response=d.response_text||'';annotations=d.annotations||[];paint('request');paint('response');const sm=root.querySelector('[data-summary-method]');if(sm){sm.textContent=e.method||'';sm.className=methodClass(e.method)}const su=root.querySelector('[data-summary-url]');if(su)su.textContent=e.url||'';const ss=root.querySelector('[data-summary-status]');if(ss){ss.textContent=e.status_code??'—';ss.className=`wb-status status-${Math.floor(Number(e.status_code||0)/100)}xx`;}const st=root.querySelector('[data-summary-target]');if(st)st.textContent=d.target_name||'';const si=root.querySelector('[data-summary-id]');if(si)si.textContent=d.event_id||e.id||'';const ct=root.querySelector('.wb-context-title>div>span');if(ct)ct.textContent=d.target_name||'';renderSemanticSummary(d);renderIdentity(d);renderObjects(d);renderSignals(d);renderFlow(d);renderRelated(d);renderActions(d);};
  const loadEvent=async(eventId,{scroll=true}={})=>{if(!detailUrl||!eventId)return;root.classList.add('is-loading');try{const u=new URL(detailUrl,window.location.origin);u.searchParams.set('event_id',String(eventId));const res=await fetch(u,{headers:{Accept:'application/json'},cache:'no-store'});if(!res.ok)throw new Error(`HTTP ${res.status}`);const d=await res.json();renderDetail(d);selected={source:d.target_key||'',event:Number(eventId),exchange:Number((d.exchange||{}).id||0)};rows().forEach(r=>r.classList.toggle('active',Number(r.dataset.eventId)===Number(eventId)));const activeRow=rows().find(r=>r.classList.contains('active'));const wasUnread=activeRow?.dataset.unread==='1'||activeRow?.classList.contains('is-unread');if(activeRow){activeRow.classList.remove('is-unread');activeRow.dataset.unread='0';const dot=activeRow.querySelector('.wb-unread-dot');if(dot)dot.setAttribute('aria-hidden','true');}if(scroll&&activeRow)activeRow.scrollIntoView({block:'nearest'});const current=new URL(window.location.href);current.searchParams.set('event',String(eventId));current.searchParams.delete('source_key');current.searchParams.delete('exchange');history.replaceState(null,'',current);const shown=Number(root.querySelector('[data-unread-count]')?.textContent||0);if(wasUnread)setUnreadCount(Math.max(0,shown-1));}catch(err){console.error('Negro Workbench',err);}finally{root.classList.remove('is-loading');}};
  const loadExchange=async(source,id)=>{if(!detailUrl||!source||!id)return;root.classList.add('is-loading');try{const u=new URL(detailUrl,window.location.origin);u.searchParams.set('source_key',source);u.searchParams.set('exchange_id',String(id));const res=await fetch(u,{headers:{Accept:'application/json'},cache:'no-store'});if(!res.ok)throw new Error(`HTTP ${res.status}`);const d=await res.json();renderDetail(d);selected={source,event:0,exchange:Number(id)};rows().forEach(r=>r.classList.remove('active'));}catch(err){console.error('Negro Workbench',err);}finally{root.classList.remove('is-loading');}};

  // ---- Marking / mental flow drafting -------------------------------------
  const markKey=`negro:wb:marks:${targetKey}`,splitKey=`negro:wb:split:${targetKey}`,contextKey='negro:wb:context-hidden';
  let marks={};try{marks=JSON.parse(localStorage.getItem(markKey)||'{}')||{};}catch(_){marks={};}
  let activeColor='blue';
  const saveMarks=()=>localStorage.setItem(markKey,JSON.stringify(marks));
  const markId=(r)=>r?.dataset.compoundId||`event:${r?.dataset.eventId||''}`;
  const applyMarks=()=>{rows().forEach(r=>{const m=marks[markId(r)];r.classList.remove('marked','mark-blue','mark-green','mark-purple','mark-orange');if(m?.color){r.classList.add('marked',`mark-${m.color}`);const pin=r.querySelector('[data-mark-toggle]');if(pin)pin.dataset.color=m.color;}});updateMarkToolbar();};
  const updateMarkToolbar=()=>{const items=Object.values(marks).filter(Boolean),count=items.length;const el=root.querySelector('[data-mark-count]');if(el)el.textContent=`${count} marcada${count===1?'':'s'}`;root.querySelector('[data-create-flow-marked]')?.toggleAttribute('disabled',count===0);root.querySelector('[data-clear-marks]')?.toggleAttribute('disabled',count===0);};
  const setMark=(r,color)=>{if(!r)return;const key=markId(r),current=marks[key];if(!color||(current&&current.color===color))delete marks[key];else marks[key]={source:r.dataset.sourceKey||'',eventId:Number(r.dataset.eventId||0),exchangeId:Number(r.dataset.exchangeId||0),color};saveMarks();applyMarks();};
  const clearMarks=()=>{marks={};saveMarks();applyMarks();};
  applyMarks();

  // ---- Flexible reading layout -------------------------------------------
  const stack=root.querySelector('[data-message-stack]'),splitter=root.querySelector('[data-message-splitter]');
  const setSplit=(pct)=>{const p=Math.max(20,Math.min(80,Number(pct)||50));root.style.setProperty('--wb-request-pct',`${p}%`);localStorage.setItem(splitKey,String(p));};
  setSplit(localStorage.getItem(splitKey)||50);
  const setPaneLayout=(layout)=>{root.dataset.paneLayout=layout;root.querySelectorAll('[data-pane-layout]').forEach(b=>b.classList.toggle('active',b.dataset.paneLayout===layout));};
  setPaneLayout('split');
  if(splitter&&stack){let dragging=false;splitter.addEventListener('pointerdown',ev=>{dragging=true;splitter.setPointerCapture(ev.pointerId);document.body.classList.add('wb-resizing');});splitter.addEventListener('pointermove',ev=>{if(!dragging)return;const rect=stack.getBoundingClientRect();setSplit(((ev.clientY-rect.top)/rect.height)*100);});splitter.addEventListener('pointerup',()=>{dragging=false;document.body.classList.remove('wb-resizing');});splitter.addEventListener('dblclick',()=>setSplit(50));}
  const setContextHidden=(hidden)=>{root.classList.toggle('context-hidden',hidden);localStorage.setItem(contextKey,hidden?'1':'0');};
  setContextHidden(localStorage.getItem(contextKey)==='1');
  const setFocus=(on)=>{document.body.classList.toggle('workbench-focus',on);root.classList.toggle('focus-mode',on);root.querySelectorAll('[data-focus-toggle]').forEach(b=>b.classList.toggle('active',on));};

  // ---- Flow creation from marked requests --------------------------------
  const dialog=root.querySelector('[data-flow-dialog]');
  const markItemsForScope=(scope)=>Object.values(marks).filter(x=>x&&(scope==='all'||x.color===scope));
  const refreshFlowDialogCount=()=>{const scope=dialog?.querySelector('[name="mark_scope"]')?.value||'all',count=root.querySelector('[data-flow-selection-count]');if(count)count.textContent=String(markItemsForScope(scope).length);};
  const openFlowDialog=()=>{const sel=dialog?.querySelector('[name="mark_scope"]');if(sel)sel.value=activeColor;refreshFlowDialogCount();const err=root.querySelector('[data-flow-dialog-error]');if(err){err.hidden=true;err.textContent='';}dialog?.showModal();dialog?.querySelector('input[name="flow_name"]')?.focus();};
  const closeFlowDialog=()=>dialog?.close();
  const createFlow=async(name,scope='all')=>{
    const items=markItemsForScope(scope),sources=[...new Set(items.map(x=>x.source))],err=root.querySelector('[data-flow-dialog-error]');
    if(!items.length){if(err){err.hidden=false;err.textContent='No hay Requests marcadas con ese color.';}return;}
    if(sources.length!==1||sources[0]!==targetKey){if(err){err.hidden=false;err.textContent='Para crear un Flow, las Requests marcadas deben pertenecer al proyecto actual y no al Traffic Inbox.';}return;}
    const res=await fetch(createFlowUrl,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({csrf:root.dataset.csrf||'',source_key:sources[0],event_ids:items.map(x=>x.eventId),name})});
    const body=await res.json().catch(()=>({}));if(!res.ok){if(err){err.hidden=false;err.textContent=body.detail||`No se pudo crear el Flow (${res.status})`;}return;}
    clearMarks();window.location.href=body.href;
  };

  // ---- JWT Inspector --------------------------------------------------------
  const jwtDialog=root.querySelector('[data-jwt-dialog]');
  let currentJwt='';
  const b64urlText=(part)=>{const p=String(part||'').replace(/-/g,'+').replace(/_/g,'/'),pad=p+'='.repeat((4-p.length%4)%4);const bin=atob(pad);const bytes=Uint8Array.from(bin,c=>c.charCodeAt(0));return new TextDecoder().decode(bytes);};
  const decodeJwt=(token)=>{const parts=String(token||'').split('.');if(parts.length!==3)throw new Error('JWT inválido');return {header:JSON.parse(b64urlText(parts[0])),claims:JSON.parse(b64urlText(parts[1])),signature:parts[2]};};
  const claimTime=(key,value)=>{if(!['iat','exp','nbf'].includes(String(key))||!Number.isFinite(Number(value)))return '';const ms=Number(value)*1000,date=new Date(ms),delta=ms-Date.now();const mins=Math.round(Math.abs(delta)/60000);let relative='';if(key==='exp')relative=delta>=0?`vigente · vence en ${mins<60?mins+' min':Math.round(mins/60)+' h'}`:`expiró hace ${mins<60?mins+' min':Math.round(mins/60)+' h'}`;else if(key==='nbf')relative=delta>0?`válido en ${mins<60?mins+' min':Math.round(mins/60)+' h'}`:'ya válido';else relative=`emitido ${delta<=0?'hace ':''}${mins<60?mins+' min':Math.round(mins/60)+' h'}`;return `${date.toLocaleString()} · ${relative}`;};
  const claimValue=(v)=>{if(v===null)return 'null';if(Array.isArray(v))return v.join(', ');if(typeof v==='object')return JSON.stringify(v);return String(v);};
  const claimRows=(obj)=>Object.entries(obj||{}).map(([k,v])=>`<div class="wb-jwt-claim"><code>${esc(k)}</code><div><strong>${esc(claimValue(v))}</strong>${claimTime(k,v)?`<small>${esc(claimTime(k,v))}</small>`:''}</div></div>`).join('')||'<p class="wb-muted">Sin datos.</p>';
  const openJwt=(token)=>{try{const d=decodeJwt(token);currentJwt=String(token);const full=jwtDialog?.querySelector('[data-jwt-full]');if(full){full.value=currentJwt;full.classList.remove('expanded');}const len=jwtDialog?.querySelector('[data-jwt-length]');if(len)len.textContent=`${currentJwt.length} caracteres`;const h=jwtDialog?.querySelector('[data-jwt-header]');if(h)h.innerHTML=claimRows(d.header);const c=jwtDialog?.querySelector('[data-jwt-claims]');if(c)c.innerHTML=claimRows(d.claims);const sig=jwtDialog?.querySelector('[data-jwt-signature]');if(sig)sig.textContent=d.signature?'✓ Signature presente':'⚠ Sin signature';jwtDialog?.showModal();}catch(err){console.warn('JWT Inspector',err);}};

  // ---- Live capture timeline ------------------------------------------------
  const unreadBadge=root.querySelector('[data-unread-badge]'),jump=root.querySelector('[data-new-events-jump]');
  let cursorEventId=Math.max(Number(root.dataset.latestEventId||0),...rows().map(r=>Number(r.dataset.eventId||0)),0),pendingNew=0,liveStopped=false;
  const atBottom=()=>!list||((list.scrollHeight-list.scrollTop-list.clientHeight)<72);
  const tagHtml=(t)=>`<em class="wb-tag tag-${esc(t.kind||'neutral')}">${esc(t.label||'')}</em>`;
  const rowHtml=(r)=>{const unread=!!r.is_unread;return `<a class="wb-traffic-row ${unread?'is-unread':''}" href="?event=${Number(r.id)}" data-source-key="${esc(r.target_key||'')}" data-event-id="${Number(r.id)}" data-exchange-id="${Number(r.exchange_id||0)}" data-compound-id="${esc(r.compound_id||('event:'+r.id))}" data-unread="${unread?'1':'0'}"><span class="wb-row-id"><i class="wb-unread-dot" title="Nueva, aún no vista"></i><i class="wb-mark-pin" data-mark-toggle title="Marcar Request"></i>${Number(r.id)}</span><span class="wb-row-main"><span class="wb-row-line"><b class="${methodClass(r.method)}">${esc(r.method||'')}</b><strong>${esc(r.hostname||'')}</strong></span><code>${esc(r.path||'/')}</code><span class="wb-tags">${(r.tags||[]).map(tagHtml).join('')}${r.is_inbox?'<em class="wb-tag tag-inbox">Sin proyecto</em>':''}</span></span><span class="wb-status status-${Math.floor(Number(r.status_code||0)/100)}xx">${esc(r.status_code??'—')}</span><time>${esc(String(r.captured_at||'').slice(11,19))}</time></a>`;};
  const updateJump=()=>{if(!jump)return;jump.hidden=pendingNew<=0;const b=jump.querySelector('b');if(b)b.textContent=String(pendingNew);};
  const appendEvents=(items)=>{if(!list||!items?.length)return;const follow=atBottom();list.querySelector('.wb-empty')?.remove();const html=items.filter(r=>!root.querySelector(`[data-event-id="${Number(r.id)}"]`)).map(rowHtml).join('');if(!html)return;const temp=document.createElement('div');temp.innerHTML=html;const added=[...temp.children];added.forEach(el=>list.appendChild(el));applyMarks();const countEl=root.querySelector('[data-event-count]');if(countEl)countEl.textContent=String(rows().length);if(follow){list.scrollTop=list.scrollHeight;pendingNew=0;}else{pendingNew+=added.length;}updateJump();};
  const liveParams=()=>{const current=new URL(window.location.href),p=new URLSearchParams();['q','target','host','method','status','scope','tool'].forEach(k=>{const v=current.searchParams.get(k);if(v)p.set(k,v);});p.set('hide_static',current.searchParams.get('hide_static')??'1');const since=Number(root.dataset.sinceEventId||0);if(since>0)p.set('since_event_id',String(since));p.set('after_event_id',String(cursorEventId));return p;};
  const pollLive=async()=>{if(liveStopped||!liveUrl)return;try{const u=new URL(liveUrl,window.location.origin);u.search=liveParams().toString();const res=await fetch(u,{headers:{Accept:'application/json'},cache:'no-store'});if(res.ok){const data=await res.json();appendEvents(data.rows||[]);cursorEventId=Math.max(cursorEventId,Number(data.latest_event_id||0));setUnreadCount(Number(data.unread_count||0));}}catch(err){console.debug('Workbench live',err);}finally{if(!liveStopped)window.setTimeout(pollLive,700);}};
  if(list){list.scrollTop=list.scrollHeight;window.setTimeout(pollLive,350);}
  window.addEventListener('beforeunload',()=>{liveStopped=true;});

  // ---- Events --------------------------------------------------------------
  list?.addEventListener('click',ev=>{const pin=ev.target.closest('[data-mark-toggle]');if(pin){ev.preventDefault();ev.stopPropagation();setMark(pin.closest('[data-source-key][data-event-id]'),activeColor);return;}const a=ev.target.closest('[data-source-key][data-event-id]');if(!a)return;ev.preventDefault();loadEvent(Number(a.dataset.eventId));});
  root.addEventListener('click',ev=>{
    const color=ev.target.closest('[data-mark-color]');if(color){activeColor=color.dataset.markColor;root.querySelectorAll('[data-mark-color]').forEach(b=>b.classList.toggle('active',b===color));return;}
    if(ev.target.closest('[data-clear-marks]')){clearMarks();return;}
    if(ev.target.closest('[data-create-flow-marked]')){openFlowDialog();return;}
    if(ev.target.closest('[data-close-flow-dialog]')){closeFlowDialog();return;}
    const layout=ev.target.closest('[data-pane-layout]');if(layout){setPaneLayout(layout.dataset.paneLayout);return;}
    if(ev.target.closest('[data-context-toggle]')){setContextHidden(!root.classList.contains('context-hidden'));return;}
    if(ev.target.closest('[data-focus-toggle]')){setFocus(!document.body.classList.contains('workbench-focus'));return;}
    const jwt=ev.target.closest('[data-jwt-token]');if(jwt){ev.preventDefault();openJwt(jwt.dataset.jwtToken||jwt.dataset.copyValue||'');return;}
    if(ev.target.closest('[data-close-jwt-dialog]')){jwtDialog?.close();return;}
    if(ev.target.closest('[data-copy-jwt]')){navigator.clipboard?.writeText(currentJwt);const b=ev.target.closest('[data-copy-jwt]');if(b){const old=b.textContent;b.textContent='Copiado';setTimeout(()=>b.textContent=old,800);}return;}
    if(ev.target.closest('[data-toggle-jwt-full]')){const area=jwtDialog?.querySelector('[data-jwt-full]');if(area){area.classList.toggle('expanded');ev.target.closest('[data-toggle-jwt-full]').textContent=area.classList.contains('expanded')?'Contraer':'Expandir';}return;}
    if(ev.target.closest('[data-new-events-jump]')){if(list){list.scrollTop=list.scrollHeight;pendingNew=0;updateJump();}return;}
    if(ev.target.closest('[data-unread-badge]')){if(seenAllUrl){fetch(seenAllUrl,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({csrf:root.dataset.csrf||'',through_event_id:cursorEventId})}).then(r=>r.json()).then(d=>{rows().forEach(r=>{r.classList.remove('is-unread');r.dataset.unread='0';});setUnreadCount(Number(d.unread_count||0));}).catch(()=>{});}return;}
    const cv=ev.target.closest('[data-copy-value]');if(cv){navigator.clipboard?.writeText(cv.dataset.copyValue||'');cv.classList.add('copied');setTimeout(()=>cv.classList.remove('copied'),700);return;}
    const rel=ev.target.closest('[data-related-source][data-related-exchange]');if(rel){ev.preventDefault();loadExchange(rel.dataset.relatedSource,Number(rel.dataset.relatedExchange));return;}
    const view=ev.target.closest('[data-view-mode]');if(view){mode[view.dataset.viewMode]=view.dataset.mode;paint(view.dataset.viewMode);return;}
    const copy=ev.target.closest('[data-copy-http]');if(copy){navigator.clipboard?.writeText(raw[copy.dataset.copyHttp]||'');copy.textContent='Copiado';setTimeout(()=>copy.textContent='Copiar',800);}
  });
  dialog?.querySelector('[name="mark_scope"]')?.addEventListener('change',refreshFlowDialogCount);
  dialog?.querySelector('[data-flow-dialog-form]')?.addEventListener('submit',ev=>{ev.preventDefault();const fd=new FormData(ev.currentTarget);createFlow(fd.get('flow_name')||'',fd.get('mark_scope')||'all');});
  document.addEventListener('keydown',ev=>{
    const tag=(document.activeElement?.tagName||'').toLowerCase();if(['input','textarea','select'].includes(tag))return;
    if(ev.key==='/'){const q=root.querySelector('.wb-search input[name="q"]');if(q){ev.preventDefault();q.focus();}return;}
    if(ev.key.toLowerCase()==='f'){ev.preventDefault();setFocus(!document.body.classList.contains('workbench-focus'));return;}
    if(['0','1','2','3','4'].includes(ev.key)){const r=rows().find(x=>Number(x.dataset.eventId)===selected.event);if(r){ev.preventDefault();const colors={1:'blue',2:'green',3:'purple',4:'orange'};if(ev.key==='0'){const k=markId(r);delete marks[k];saveMarks();applyMarks();}else setMark(r,colors[ev.key]);}return;}
    if(!['ArrowDown','ArrowUp','j','k'].includes(ev.key))return;
    const rs=rows();if(!rs.length)return;let idx=rs.findIndex(r=>Number(r.dataset.eventId)===selected.event);if(idx<0)idx=rs.length-1;idx=(ev.key==='ArrowDown'||ev.key==='j')?Math.min(rs.length-1,idx+1):Math.max(0,idx-1);const r=rs[idx];ev.preventDefault();loadEvent(Number(r.dataset.eventId));
  });
})();
