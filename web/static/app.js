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

// v0.115.2 · Live Traffic Timeline: exact capture events, review queue, live follow and JWT inspector.
(()=>{
  const root=document.querySelector('[data-workbench]');
  if(!root) return;
  const detailUrl=root.dataset.detailUrl;
  const liveUrl=root.dataset.liveUrl;
  const seenAllUrl=root.dataset.seenAllUrl;
  const createFlowUrl=root.dataset.createFlowUrl;
  const analysisScopeUrl=root.dataset.analysisScopeUrl;
  const analysisScopeRemoveUrl=root.dataset.analysisScopeRemoveUrl;
  const initialVisibility=(root.dataset.visibility||'focus').toLowerCase();
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
  let inlineValues=[],identityOptions=[],objectTypeOptions=[],fieldSemantics=[];
  const applyInlineContext=(ctx={})=>{
    inlineValues=Array.isArray(ctx.values)?ctx.values:[];
    identityOptions=Array.isArray(ctx.identities)?ctx.identities:[];
    objectTypeOptions=Array.isArray(ctx.object_types)?ctx.object_types:[];
    fieldSemantics=Array.isArray(ctx.field_semantics)?ctx.field_semantics:[];
  };
  try{applyInlineContext(JSON.parse(root.querySelector('[data-workbench-inline-context]')?.textContent||'{}')||{});}catch(_){applyInlineContext({});}
  // Workbench preference keys must exist before the first renderer/layout setup runs.
  // Declaring these here prevents a TDZ ReferenceError that previously stopped every control.
  const markKey=`negro:wb:marks:${targetKey}`,splitKey=`negro:wb:split:${targetKey}`,contextKey='negro:wb:context-hidden',trafficKey='negro:wb:traffic-collapsed',wrapKey='negro:wb:exact-lines';
  const trafficHeightKey=`negro:wb:traffic-height:${targetKey}`;

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
  const jwtTokenFromValue=(v)=>{const raw=String(v||'').trim(),m=raw.match(/^(?:Bearer\s+)?(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/i);return m?m[1]:'';};
  const looksJwt=(v)=>!!jwtTokenFromValue(v);
  const compactText=(v)=>{const x=String(v||'');return x.length>86?`${x.slice(0,34)}…${x.slice(-18)}`:x;};
  const jwtSummary=(token)=>{
    try{
      const normalized=jwtTokenFromValue(token)||String(token||'').trim();
      const p=normalized.split('.')[1],pad=p.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-p.length%4)%4);
      const obj=JSON.parse(decodeURIComponent(escape(atob(pad))));
      return ['iss','sub','aud','exp'].filter(k=>obj[k]!=null).map(k=>`${k}: ${Array.isArray(obj[k])?obj[k].join(','):obj[k]}`).join(' · ');
    }catch(_){return '';}
  };
  const smartValue=(value,label='value')=>{
    const v=String(value||''),jwtToken=jwtTokenFromValue(v),jwt=!!jwtToken,long=v.length>86;
    if(!jwt&&!long) return esc(v);
    const badge=jwt?'JWT':'long';
    const summary=jwt?jwtSummary(jwtToken):'';
    const title=jwt?`Abrir JWT Inspector${summary?' · '+summary:''}`:'Clic para copiar el valor completo';
    if(jwt){
      // Use a real button instead of a passive span. This avoids browser/event-delegation
      // edge cases inside syntax-highlighted code and gives the JWT inspector an explicit action.
      return `<button type="button" class="wb-compact-value is-jwt wb-jwt-trigger" data-jwt-open="1" data-jwt-token="${esc(jwtToken)}" title="${esc(title)}">${esc(compactText(v))}<em>JWT</em></button>`;
    }
    return `<span class="wb-compact-value" data-copy-value="${esc(v)}" title="${esc(title)}">${esc(compactText(v))}<em>${badge}</em></span>`;
  };
  const smartInlineValue=(value)=>{
    const v=String(value||''),jwtToken=jwtTokenFromValue(v),jwt=!!jwtToken,long=v.length>86;
    if(!jwt&&!long)return esc(v);
    const compact=esc(compactText(v));
    if(jwt)return `<span class="wb-inline-compact">${compact}</span><button type="button" class="wb-inline-jwt" data-jwt-open="1" data-jwt-token="${esc(jwtToken)}" title="Abrir JWT Inspector y ver claims">JWT</button>`;
    return `<span class="wb-inline-compact">${compact}</span><em class="wb-inline-long">long</em>`;
  };
  const normalizeFieldKey=(v)=>String(v||'').trim().toLowerCase().replace(/-/g,'_').replace(/[^a-z0-9_]/g,'');
  const fieldRuleFor=(key)=>fieldSemantics.find(r=>String(r.normalized_key||'')===normalizeFieldKey(key))||null;
  const inlineFieldMarkup=(idx,label)=>`<span class="wb-inline-field-key" role="button" tabindex="0" data-inline-field-index="${Number(idx)}" title="Clic para enseñar qué significa este campo">${esc(label)}</span>`;
  const inlineValueMarkup=(idx,display,rawValue)=>`<span class="wb-inline-value" role="button" tabindex="0" data-inline-index="${Number(idx)}" title="Clic para enseñar este valor a Negro">${smartInlineValue(rawValue??display)}</span>`;
  const findInlineCandidate=(side,key,value,locationPrefix='')=>inlineValues.findIndex(v=>
    String(v.side||'')===side && String(v.key||'')===String(key||'') && String(v.value||'')===String(value??'') && (!locationPrefix||String(v.location||'').startsWith(locationPrefix))
  );
  const renderRequestTarget=(target)=>{
    const rawTarget=String(target||'');
    const qpos=rawTarget.indexOf('?');
    const rawPath=qpos>=0?rawTarget.slice(0,qpos):rawTarget;
    const rawQuery=qpos>=0?rawTarget.slice(qpos+1):'';
    let pathHtml=esc(rawPath);
    const pathCandidates=inlineValues.map((v,i)=>({v,i})).filter(({v})=>String(v.side||'')==='request'&&String(v.location||'').startsWith('request_path:'));
    for(const {v,i} of pathCandidates){
      const value=String(v.value||'');if(!value)continue;
      const encoded=encodeURIComponent(value);
      for(const needle of [esc(value),esc(encoded)]){
        if(needle&&pathHtml.includes(needle)){pathHtml=pathHtml.replace(needle,inlineValueMarkup(i,needle,value));break;}
      }
    }
    if(qpos<0)return pathHtml;
    const pairs=rawQuery.split('&').map(part=>{
      const eq=part.indexOf('='),rk=eq>=0?part.slice(0,eq):part,rv=eq>=0?part.slice(eq+1):'';
      let key,value;try{key=decodeURIComponent(rk.replace(/\+/g,' '));}catch(_){key=rk;}try{value=decodeURIComponent(rv.replace(/\+/g,' '));}catch(_){value=rv;}
      const idx=findInlineCandidate('request',key,value,`request_query:${key}`);
      if(idx<0)return esc(part);
      const keyHtml=inlineFieldMarkup(idx,rk);
      const valueHtml=inlineValueMarkup(idx,rv,value);
      return eq>=0?`${keyHtml}=<span class="wb-inline-url-value">${valueHtml}</span>`:keyHtml;
    }).join('&amp;');
    return `${pathHtml}<span class="http-token-punctuation">?</span>${pairs}`;
  };
  const decorateFieldInteractive=(html,line,side,idx,bodyStarted)=>{
    let out=html;
    const found=inlineValues.map((v,i)=>({v,i})).filter(x=>String(x.v.side||'')===side&&candidateApplies(x.v,line,idx,bodyStarted));
    for(const {v,i} of found){
      const key=String(v.key||'');if(!key)continue;
      if(!bodyStarted&&String(v.location||'').includes('_header:')){
        const needle=`>${esc(key)}</span>`;
        if(out.includes(needle)&&!out.includes(`data-inline-field-index="${i}"`))out=out.replace(needle,`>${inlineFieldMarkup(i,key)}</span>`);
      }else if(bodyStarted&&String(v.location||'').includes('_json:')){
        const needle=`<span class="http-token-key">&quot;${esc(key)}&quot;</span>`;
        if(out.includes(needle)&&!out.includes(`data-inline-field-index="${i}"`))out=out.replace(needle,`<span class="http-token-key">&quot;${inlineFieldMarkup(i,key)}&quot;</span>`);
      }else if(bodyStarted&&String(v.location||'').includes('_form:')){
        const needle=esc(key);
        if(out.includes(needle)&&!out.includes(`data-inline-field-index="${i}"`))out=out.replace(needle,inlineFieldMarkup(i,key));
      }
    }
    return out;
  };

  const candidateApplies=(a,line,idx,bodyStarted)=>{
    const loc=String(a.location||'').toLowerCase(),key=String(a.key||''),value=String(a.value||'');
    if(!value)return false;
    if(loc.includes('_header:')){const h=loc.split(':',2)[1]||'';return new RegExp(`^${regexEscape(h)}\\s*:`, 'i').test(line)&&line.includes(value);}
    if(loc.includes('_cookie:'))return /^(cookie|set-cookie)\s*:/i.test(line)&&(!key||line.toLowerCase().includes(key.toLowerCase()))&&line.includes(value);
    if(loc.includes('_query:'))return idx===0&&(!key||line.toLowerCase().includes(key.toLowerCase()))&&(line.includes(value)||line.includes(encodeURIComponent(value)));
    if(loc.includes('_json:'))return bodyStarted&&(!key||line.toLowerCase().includes(`"${key.toLowerCase()}"`))&&line.includes(value);
    if(loc.includes('_form:'))return bodyStarted&&(!key||line.toLowerCase().includes(key.toLowerCase()))&&line.includes(value);
    return line.includes(value)&&(value.length>=4||!!key);
  };
  const candidateIndexFor=(ann)=>inlineValues.findIndex(v=>String(v.side||'')===String(ann.side||'')&&String(v.location||'')===String(ann.location||'')&&String(v.key||'')===String(ann.key_name||'')&&String(v.value||'')===String(ann.value_raw||ann.value_preview||''));
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
      const needle=esc(rawValue),css=semanticCss(a.classification),label=semanticLabel(a),ci=candidateIndexFor(a);
      if(!needle||!out.includes(needle))continue;
      const reason=[a.match_reason,a.source_exchange_id?`aprendido en #${a.source_exchange_id}`:''].filter(Boolean).join(' · ');
      const inlineAttrs=ci>=0?` role="button" tabindex="0" data-inline-index="${ci}"`:'';
      out=out.replace(needle,`<span class="http-annotation ${css}${ci>=0?' wb-inline-value':''}" data-label="${esc(label)}" title="${esc(reason||label)}"${inlineAttrs}>${ci>=0?smartInlineValue(rawValue):smartValue(rawValue,label)}</span>`);
    }
    return out;
  };
  const decorateInteractive=(html,line,side,idx,bodyStarted)=>{
    let out=html;
    const found=inlineValues.map((v,i)=>({v,i})).filter(x=>String(x.v.side||'')===side&&candidateApplies(x.v,line,idx,bodyStarted)).sort((a,b)=>String(b.v.value||'').length-String(a.v.value||'').length);
    for(const {v,i} of found){
      if(out.includes(`data-inline-index="${i}"`))continue;
      const rawValue=String(v.value||'');if(!rawValue)continue;const needle=esc(rawValue);if(!needle||!out.includes(needle))continue;
      out=out.replace(needle,`<span class="wb-inline-value" role="button" tabindex="0" data-inline-index="${i}" title="Clic para enseñar este valor a Negro">${smartInlineValue(rawValue)}</span>`);
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
    const lineNo=idx+1;
    if(!bodyStarted && idx===0){
      const m=line.match(/^([A-Z]+)\s+(\S+)(?:\s+(HTTP\/\S+))?/);
      if(m){const targetHtml=side==='request'?renderRequestTarget(m[2]):esc(m[2]);const h=`<span class="http-token-method">${esc(m[1])}</span> <span class="http-token-target">${targetHtml}</span>${m[3]?` <span class="http-token-protocol">${esc(m[3])}</span>`:''}`;{let z=decorateSemantic(h,line,side,idx,bodyStarted);z=decorateInteractive(z,line,side,idx,bodyStarted);z=decorateFieldInteractive(z,line,side,idx,bodyStarted);return `<span class="wb-http-line" data-line="${lineNo}">${z}</span>`;}}
      const r=line.match(/^(HTTP\/\S+)\s+(\d+)(.*)$/);
      if(r){const status=Number(r[2]),statusClass=status<300?'http-token-status-ok':status<400?'http-token-status-redirect':'http-token-status-error';const h=`<span class="http-token-protocol">${esc(r[1])}</span> <span class="${statusClass}">${esc(r[2])}</span><span class="http-token-status-text">${esc(r[3])}</span>`;{let z=decorateSemantic(h,line,side,idx,bodyStarted);z=decorateInteractive(z,line,side,idx,bodyStarted);return `<span class="wb-http-line" data-line="${lineNo}">${z}</span>`;}}
    }
    if(!bodyStarted){
      const h=line.match(/^([^:]+):(.*)$/);
      if(h){
        const name=h[1],value=h[2],tone=smart?headerTone(name):'',sensitive=/^(authorization|cookie|set-cookie|x-api-key|api-key|proxy-authorization)$/i.test(name.trim());
        let x=`<span class="http-token-header-name${sensitive?' http-token-sensitive':''}">${esc(name)}</span><span class="http-token-punctuation">:</span><span class="http-token-header-value${sensitive?' http-token-sensitive-value':''}">${esc(value)}</span>`;
        x=decorateSemantic(x,line,side,idx,bodyStarted);
        x=decorateInteractive(x,line,side,idx,bodyStarted);
        x=decorateFieldInteractive(x,line,side,idx,bodyStarted);
        if(smart&&!x.includes('data-inline-index='))x=compactKnownValue(x,value);
        return `<span class="wb-http-line ${tone}" data-line="${lineNo}">${x}</span>`;
      }
    }
    let out=esc(line);
    if(bodyStarted){
      out=out.replace(/(&quot;[^&\n]+?&quot;)(\s*:)/g,'<span class="http-token-key">$1</span><span class="http-token-punctuation">$2</span>')
             .replace(/(:\s*)(&quot;.*?&quot;)/g,'$1<span class="http-token-string">$2</span>')
             .replace(/(:\s*)(-?\d+(?:\.\d+)?)/g,'$1<span class="http-token-number">$2</span>')
             .replace(/(:\s*)(true|false|null)/g,'$1<span class="http-token-literal">$2</span>');
      out=decorateSemantic(out,line,side,idx,bodyStarted);
      out=decorateInteractive(out,line,side,idx,bodyStarted);
      out=decorateFieldInteractive(out,line,side,idx,bodyStarted);
      if(smart&&!out.includes('data-inline-index=')){const jm=line.match(/^\s*"[^"]+"\s*:\s*"([^"]*)"\s*,?\s*$/);if(jm)out=compactKnownValue(out,jm[1]);}
    }else{out=decorateSemantic(out,line,side,idx,bodyStarted);out=decorateInteractive(out,line,side,idx,bodyStarted);}
    return `<span class="wb-http-line${line===''?' wb-http-separator':''}" data-line="${lineNo}">${out||' '}</span>`;
  };
  const paint=(side)=>{
    const pre=root.querySelector(`[data-http-view="${side}"]`),code=pre?.querySelector('code');if(!pre||!code)return;
    const smart=mode[side]==='pretty',text=smart?prettyHttp(raw[side]):raw[side];pre.classList.toggle('pretty',smart);
    let body=false;
    code.innerHTML=String(text||'').replace(/\r\n/g,'\n').split('\n').map((line,i)=>{const rendered=lineHtml(line,i,body,side,smart);if(line==='')body=true;return rendered;}).join('\n');
    root.querySelectorAll(`[data-view-mode="${side}"]`).forEach(b=>b.classList.toggle('active',b.dataset.mode===mode[side]));
  };
  paint('request');paint('response');

  const exactLinesDefault=localStorage.getItem(wrapKey)==='1';
  const setExactLines=(side,on)=>{const pre=root.querySelector(`[data-http-view="${side}"]`);if(!pre)return;pre.classList.toggle('exact-lines',!!on);root.querySelectorAll(`[data-wb-wrap="${side}"]`).forEach(b=>b.textContent=on?'Ajustar líneas':'Líneas exactas');};
  setExactLines('request',exactLinesDefault);setExactLines('response',exactLinesDefault);
  let fullscreenContextBefore=null;
  const toggleFullscreen=async()=>{const workspace=root.querySelector('.wb-grid');if(!workspace)return;try{if(document.fullscreenElement===workspace){await document.exitFullscreen();}else if(workspace.requestFullscreen){fullscreenContextBefore=root.classList.contains('context-hidden');setContextHidden(true,{persist:false});await workspace.requestFullscreen();}else{workspace.classList.toggle('fullscreen-pane');root.classList.toggle('immersive-fullscreen',workspace.classList.contains('fullscreen-pane'));}}catch(_){workspace.classList.toggle('fullscreen-pane');root.classList.toggle('immersive-fullscreen',workspace.classList.contains('fullscreen-pane'));}};
  document.addEventListener('fullscreenchange',()=>{const workspace=root.querySelector('.wb-grid'),on=document.fullscreenElement===workspace;root.classList.toggle('immersive-fullscreen',on);root.querySelectorAll('[data-http-fullscreen]').forEach(b=>b.textContent=on?'Salir de pantalla completa':'Pantalla completa');if(!on&&fullscreenContextBefore!==null){setContextHidden(fullscreenContextBefore,{persist:false});fullscreenContextBefore=null;}});

  // ---- Context rendering ---------------------------------------------------
  const renderIdentity=(d)=>{const card=root.querySelector('[data-context-card="identity"]');if(!card)return;const i=d.identity,matches=d.identity_matches||[];const inferred=!i&&matches.length?`<div class="wb-identity-matches">${matches.map(m=>`<div><strong>${esc(m.name)}</strong><span>Reconocida en HTTP · ${(m.classifications||[]).map(x=>esc(String(x).toUpperCase())).join(' + ')}</span></div>`).join('')}</div>`:'';card.innerHTML=`<div class="wb-card-title"><span>◎</span><b>Identity</b></div>${i?`<strong>${esc(i.name)}</strong><div class="wb-kv"><span>role</span><code>${esc(i.role||i.kind||'—')}</code><span>context</span><code>${esc(i.context_label||'—')}</code><span>confidence</span><code>${esc(i.confidence||'—')}</code></div>`:(inferred||'<p class="wb-muted">Sin Identity resuelta.</p>')}`;};
  const renderObjects=(d)=>{const card=root.querySelector('[data-context-card="objects"]');if(!card)return;const os=d.objects||[];card.innerHTML=`<div class="wb-card-title"><span>◇</span><b>Objects</b><em>${os.length}</em></div>${os.length?`<div class="wb-object-list">${os.map(o=>`<div><b>${esc(o.type_name)}</b><code>${esc(o.identifier_raw||o.identifier_preview||'')}</code></div>`).join('')}</div>`:'<p class="wb-muted">Sin Objects correlacionados.</p>'}`;};
  const renderSignals=(d)=>{const card=root.querySelector('[data-context-card="signals"]');if(!card)return;const ss=d.signals||[];card.innerHTML=`<div class="wb-card-title"><span>◉</span><b>Signals</b><em>${ss.length}</em></div>${ss.length?`<div class="wb-signal-list">${ss.map(s=>`<div><span class="signal-dot severity-${esc(s.severity)}"></span><span>${esc(s.title)}</span><em>${esc(s.severity)}</em></div>`).join('')}</div>`:'<p class="wb-muted">Sin Signals pendientes.</p>'}`;};
  const renderFlow=(d)=>{const card=root.querySelector('[data-context-card="flow"]');if(!card)return;const fs=d.flows||[];card.innerHTML=`<div class="wb-card-title"><span>⌁</span><b>Flow</b></div>${fs.length?`<div class="wb-flow-list">${fs.map(f=>`<a href="/t/${encodeURIComponent(d.target_key)}/flows/${Number(f.id)}#flow-step-${Number(f.step_id)}"><span>${Number(f.position||0)}</span><b>${esc(f.name)}</b><small>${esc(f.label||f.state_label||'Step observado')}</small></a>`).join('')}</div>`:'<p class="wb-muted">Esta Request aún no pertenece a un Flow.</p>'}`;};
  const renderRelated=(d)=>{const card=root.querySelector('[data-context-card="related"]');if(!card)return;const rs=d.related||[];card.innerHTML=`<summary class="wb-card-title"><span>↔</span><b>Related Requests</b><em>${rs.length}</em></summary>${rs.length?`<div class="wb-related-list">${rs.map(r=>`<button type="button" data-related-source="${esc(d.target_key)}" data-related-exchange="${Number(r.id)}"><b class="${methodClass(r.method)}">${esc(r.method)}</b><code>${esc(r.path)}</code><span>${esc(r.status_code??'—')}</span></button>`).join('')}</div>`:'<p class="wb-muted">Sin relaciones suficientes todavía.</p>'}`;};
  const renderActions=(d)=>{const card=root.querySelector('.wb-quick-actions');if(!card)return;const e=d.exchange||{};if(d.is_inbox){card.innerHTML=`<summary class="wb-card-title"><span>⚡</span><b>Actions</b></summary><p class="wb-inbox-note"><b>Traffic Inbox.</b> Puedes incluir este tráfico en el proyecto para analizarlo sin ampliar el scope autorizado de Recon.</p><button type="button" class="wb-assign-project" data-analysis-scope-open data-host="${esc(e.hostname||'')}" data-method="${esc(e.method||'GET')}" data-path="${esc(e.path||'/')}" data-event-id="${Number(d.event_id||selected.event||0)}">Incluir en este proyecto…</button>`;return;}const t=encodeURIComponent(d.target_key),id=Number(e.id||0),rid=Number(e.resource_id||0),activeAllowed=!!d.active_scope_authorized,rules=Array.isArray(d.analysis_rules)?d.analysis_rules:[];const membership=rules.length?`<div class="wb-analysis-membership"><small>TARGET DE ANÁLISIS</small>${rules.map(r=>`<div><span><b>${r.rule_type==='host'?'Host completo':'Endpoint'}</b><code>${esc(r.rule_type==='host'?(r.hostname||''):`${r.method||''} ${r.path||''}`)}</code></span><button type="button" data-analysis-scope-remove data-rule-id="${Number(r.id||0)}" data-rule-label="${esc(r.rule_type==='host'?(r.hostname||''):`${r.method||''} ${r.path||''}`)}">Retirar</button></div>`).join('')}</div>`:'';card.innerHTML=`<summary class="wb-card-title"><span>⚡</span><b>Actions</b></summary>${membership}<div class="wb-action-grid wb-action-grid-compact"><a href="/t/${t}/parameters/related/${id}">Follow Value</a>${activeAllowed?`<a href="/t/${t}/replays/new?exchange_id=${id}">Replay</a>`:''}</div>${activeAllowed?`<form class="wb-repeater-form" method="post" action="/t/${t}/resource/${rid}/send-repeater"><input type="hidden" name="csrf" value="${esc(root.dataset.csrf||window.NEGRO_CSRF||'')}"><input type="hidden" name="method" value="${esc(e.method||'GET')}"><input type="hidden" name="exchange_id" value="${id}"><button type="submit">Enviar a Burp Repeater</button></form>`:'<p class="wb-analysis-only"><b>Analysis-only.</b> Correlación y Flows sí; Replay/Repeater siguen bloqueados hasta que el host esté dentro del scope autorizado de Recon.</p>'}`;};
  const renderSemanticSummary=(d)=>{const el=root.querySelector('[data-semantic-summary]');if(!el)return;const c=d.semantic_counts||{},labels={auth:'AUTH',resolver:'RESOLVER',context:'CONTEXT',entity:'ENTITY'};el.innerHTML=Object.keys(labels).filter(k=>Number(c[k]||0)>0).map(k=>`<em class="wb-semantic-chip semantic-${k}">${labels[k]} ${Number(c[k])}</em>`).join('');};
  const setUnreadCount=(n)=>{const count=Math.max(0,Number(n)||0),badge=root.querySelector('[data-unread-badge]'),el=root.querySelector('[data-unread-count]'),compact=root.querySelector('[data-compact-new]'),compactCount=root.querySelector('[data-compact-unread]');if(el)el.textContent=String(count);if(badge)badge.classList.toggle('is-empty',count===0);if(compactCount)compactCount.textContent=String(count);if(compact)compact.classList.toggle('is-empty',count===0);};
  const updateTrafficCompact=(d)=>{const c=root.querySelector('[data-traffic-compact]');if(!c)return;const e=d.exchange||{};let host=e.hostname||'',path=e.path||'';if((!host||!path)&&e.url){try{const u=new URL(e.url);host=host||u.host;path=path||(u.pathname+u.search);}catch(_){path=path||e.url;}}const unread=Math.max(0,Number(root.querySelector('[data-unread-count]')?.textContent||0));c.innerHTML=`<button type="button" class="wb-traffic-expand" data-traffic-toggle title="Desplegar Traffic Inbox (T)">⌄</button><b class="${methodClass(e.method)}">${esc(e.method||'—')}</b><strong title="${esc(host)}">${esc(host||d.target_name||'')}</strong><code title="${esc(path||e.url||'')}">${esc(path||e.url||'—')}</code><span class="wb-compact-status status-${Math.floor(Number(e.status_code||0)/100)}xx">${esc(e.status_code??'—')}</span><span class="wb-compact-event">Event #<b>${Number(d.event_id||e.id||0)}</b></span><span class="wb-compact-new ${unread?'':'is-empty'}" data-compact-new>● <b data-compact-unread>${unread}</b> nuevas</span>`;};
  const renderDetail=(d)=>{const e=d.exchange||{};root.querySelector('[data-summary]')?.classList.remove('wb-detail-empty');root.querySelector('[data-message-stack]')?.classList.remove('wb-detail-empty');raw.request=d.request_text||'';raw.response=d.response_text||'';annotations=d.annotations||[];applyInlineContext({values:d.values||[],identities:d.identity_options||[],object_types:d.object_type_options||[],field_semantics:d.field_semantics||[]});paint('request');paint('response');const sm=root.querySelector('[data-summary-method]');if(sm){sm.textContent=e.method||'';sm.className=methodClass(e.method)}const su=root.querySelector('[data-summary-url]');if(su)su.textContent=e.url||'';const ss=root.querySelector('[data-summary-status]');if(ss){ss.textContent=e.status_code??'—';ss.className=`wb-status status-${Math.floor(Number(e.status_code||0)/100)}xx`;}const st=root.querySelector('[data-summary-target]');if(st)st.textContent=d.target_name||'';const si=root.querySelector('[data-summary-id]');if(si)si.textContent=d.event_id||e.id||'';const sx=root.querySelector('[data-summary-exchange]');if(sx)sx.textContent=e.id||'—';const sz=root.querySelector('[data-summary-size]');if(sz)sz.textContent=Number(e.response_size||0);const ct=root.querySelector('.wb-context-title>div>span');if(ct)ct.textContent=d.target_name||'';updateTrafficCompact(d);renderSemanticSummary(d);renderIdentity(d);renderObjects(d);renderSignals(d);renderFlow(d);renderRelated(d);renderActions(d);};
  // v0.116.7 · Fast LIVE detail loading. A click must never queue almost a second
  // of retries or allow an older request to overwrite a newer selection.
  let detailAbort=null,detailLoadSeq=0;
  const sleep=(ms,signal)=>new Promise((resolve,reject)=>{const id=window.setTimeout(resolve,ms);if(signal)signal.addEventListener('abort',()=>{window.clearTimeout(id);reject(new DOMException('Aborted','AbortError'));},{once:true});});
  const fetchEventDetail=async(eventId,signal)=>{const u=new URL(detailUrl,window.location.origin);u.searchParams.set('event_id',String(eventId));const request=()=>fetch(u,{headers:{Accept:'application/json'},cache:'no-store',signal});let res=await request();if(res.status===404){await sleep(85,signal);res=await request();}if(!res.ok)throw new Error(`HTTP ${res.status}`);return await res.json();};
  const loadEvent=async(eventId,{scroll=true}={})=>{if(!detailUrl||!eventId)return;detailAbort?.abort();const controller=new AbortController();detailAbort=controller;const seq=++detailLoadSeq;root.classList.add('is-loading');try{const d=await fetchEventDetail(eventId,controller.signal);if(seq!==detailLoadSeq||controller.signal.aborted)return;renderDetail(d);selected={source:d.target_key||'',event:Number(eventId),exchange:Number((d.exchange||{}).id||0)};rows().forEach(r=>r.classList.toggle('active',Number(r.dataset.eventId)===Number(eventId)));const activeRow=rows().find(r=>r.classList.contains('active'));const wasUnread=activeRow?.dataset.unread==='1'||activeRow?.classList.contains('is-unread');if(activeRow){activeRow.classList.remove('is-unread');activeRow.dataset.unread='0';const dot=activeRow.querySelector('.wb-unread-dot');if(dot)dot.setAttribute('aria-hidden','true');}markPendingReviewed(eventId);if(scroll&&activeRow&&!root.classList.contains('traffic-collapsed'))activeRow.scrollIntoView({block:'nearest'});const current=new URL(window.location.href);current.searchParams.set('event',String(eventId));current.searchParams.delete('source_key');current.searchParams.delete('exchange');history.replaceState(null,'',current);const shown=Number(root.querySelector('[data-unread-count]')?.textContent||0);if(wasUnread)setUnreadCount(Math.max(0,shown-1));}catch(err){if(err?.name!=='AbortError')console.error('Negro Workbench',err);}finally{if(seq===detailLoadSeq)root.classList.remove('is-loading');}};
  const loadExchange=async(source,id)=>{if(!detailUrl||!source||!id)return;root.classList.add('is-loading');try{const u=new URL(detailUrl,window.location.origin);u.searchParams.set('source_key',source);u.searchParams.set('exchange_id',String(id));const res=await fetch(u,{headers:{Accept:'application/json'},cache:'no-store'});if(!res.ok)throw new Error(`HTTP ${res.status}`);const d=await res.json();renderDetail(d);selected={source,event:0,exchange:Number(id)};rows().forEach(r=>r.classList.remove('active'));}catch(err){console.error('Negro Workbench',err);}finally{root.classList.remove('is-loading');}};

  // ---- Inline semantics: teach Negro where you are reading -----------------
  const inlinePopover=root.querySelector('[data-inline-popover]');
  let currentInlineIndex=-1,currentInlineClass='',currentInlineKind='value';
  const closeInline=()=>{if(inlinePopover){inlinePopover.hidden=true;inlinePopover.classList.remove('open');}currentInlineIndex=-1;currentInlineKind='value';};
  const fillInlineCatalogs=()=>{
    const identitySelect=inlinePopover?.querySelector('[data-inline-identity]');
    if(identitySelect){const current=identitySelect.value;identitySelect.innerHTML='<option value="">Selecciona…</option>'+identityOptions.map(i=>`<option value="${Number(i.id)}">${esc(i.name||('Identity #'+i.id))}</option>`).join('');if(current)identitySelect.value=current;}
    const dl=inlinePopover?.querySelector('[data-inline-object-types]');if(dl)dl.innerHTML=objectTypeOptions.map(o=>`<option value="${esc(o.name||'')}"></option>`).join('');
  };
  const setInlineClass=(cls)=>{
    currentInlineClass=String(cls||'').toLowerCase();
    inlinePopover?.querySelectorAll('[data-inline-class]').forEach(b=>b.classList.toggle('active',b.dataset.inlineClass===currentInlineClass));
    const identityWrap=inlinePopover?.querySelector('[data-inline-identity-wrap]'),objectWrap=inlinePopover?.querySelector('[data-inline-object-wrap]');
    // A field rule describes the role of the key; it never binds every future
    // value to one concrete Identity. Identity selection therefore only exists
    // when teaching a specific value.
    if(identityWrap)identityWrap.hidden=currentInlineKind==='field'||!['auth','resolver','context'].includes(currentInlineClass);
    if(objectWrap)objectWrap.hidden=currentInlineClass!=='entity';
  };
  const placeInline=(anchor)=>{if(!inlinePopover||!anchor)return;const r=anchor.getBoundingClientRect(),w=Math.min(360,window.innerWidth-24);inlinePopover.style.width=`${w}px`;inlinePopover.hidden=false;inlinePopover.classList.add('open');const h=inlinePopover.offsetHeight||310;let left=Math.max(12,Math.min(window.innerWidth-w-12,r.left));let top=r.bottom+8;if(top+h>window.innerHeight-12)top=Math.max(12,r.top-h-8);inlinePopover.style.left=`${left}px`;inlinePopover.style.top=`${top}px`;};
  const setInlineModeUi=(kind)=>{
    currentInlineKind=kind==='field'?'field':'value';
    const kindEl=inlinePopover?.querySelector('[data-inline-kind]'),hint=inlinePopover?.querySelector('[data-inline-field-hint]'),follow=inlinePopover?.querySelector('[data-inline-follow]');
    if(kindEl)kindEl.textContent=currentInlineKind==='field'?'ENSEÑAR CAMPO A NEGRO':'ENSEÑAR VALOR A NEGRO';
    if(hint)hint.hidden=currentInlineKind!=='field';
    if(follow)follow.textContent=currentInlineKind==='field'?'Buscar campo':'Follow Value';
  };
  const openInline=(idx,anchor)=>{
    const v=inlineValues[Number(idx)];if(!v||!inlinePopover)return;currentInlineIndex=Number(idx);setInlineModeUi('value');fillInlineCatalogs();
    const learned=(annotations||[]).find(a=>String(a.side||'')===String(v.side||'')&&String(a.location||'')===String(v.location||'')&&String(a.key_name||'')===String(v.key||'')&&String(a.value_raw||a.value_preview||'')===String(v.value||''));
    const ann=learned||v.annotation||{},suggested=String(ann.classification||v.default_classification||'').toLowerCase();
    inlinePopover.querySelector('[data-inline-key]').textContent=v.key||'valor';inlinePopover.querySelector('[data-inline-preview]').textContent=v.preview||compactText(v.value||'');
    inlinePopover.querySelector('[data-inline-side]').textContent=String(v.side||'').toUpperCase();inlinePopover.querySelector('[data-inline-location]').textContent=v.location||'';
    const identitySelect=inlinePopover.querySelector('[data-inline-identity]');if(identitySelect)identitySelect.value=String(ann.identity_id||'');
    const objectInput=inlinePopover.querySelector('[data-inline-object-type]');if(objectInput)objectInput.value=String(ann.object_type||'');
    const feedback=inlinePopover.querySelector('[data-inline-feedback]');if(feedback){feedback.hidden=true;feedback.textContent='';}
    const follow=inlinePopover.querySelector('[data-inline-follow]');if(follow)follow.href=`/t/${encodeURIComponent(selected.source||targetKey)}/search?q=${encodeURIComponent(v.value||'')}`;
    setInlineClass(['auth','resolver','context','entity'].includes(suggested)?suggested:'');placeInline(anchor);
  };
  const openInlineField=(idx,anchor)=>{
    const v=inlineValues[Number(idx)];if(!v||!inlinePopover)return;currentInlineIndex=Number(idx);setInlineModeUi('field');fillInlineCatalogs();
    const rule=fieldRuleFor(v.key)||{},suggested=String(rule.classification||v.default_classification||'').toLowerCase();
    inlinePopover.querySelector('[data-inline-key]').textContent=v.key||'campo';inlinePopover.querySelector('[data-inline-preview]').textContent='Regla para futuros valores de este campo';
    inlinePopover.querySelector('[data-inline-side]').textContent='FIELD';inlinePopover.querySelector('[data-inline-location]').textContent=v.location||'';
    const identitySelect=inlinePopover.querySelector('[data-inline-identity]');if(identitySelect)identitySelect.value='';
    const objectInput=inlinePopover.querySelector('[data-inline-object-type]');if(objectInput)objectInput.value=String(rule.object_type||'');
    const feedback=inlinePopover.querySelector('[data-inline-feedback]');if(feedback){feedback.hidden=true;feedback.textContent='';}
    const follow=inlinePopover.querySelector('[data-inline-follow]');if(follow)follow.href=`/t/${encodeURIComponent(selected.source||targetKey)}/search?q=${encodeURIComponent(v.key||'')}`;
    setInlineClass(['auth','resolver','context','entity'].includes(suggested)?suggested:'');placeInline(anchor);
  };
  const reloadSelected=()=>selected.event?loadEvent(selected.event,{scroll:false}):loadExchange(selected.source,selected.exchange);
  const saveInline=async(classification)=>{
    const v=inlineValues[currentInlineIndex],feedback=inlinePopover?.querySelector('[data-inline-feedback]');if(!v||!selected.source||!selected.exchange)return;
    if(selected.source==='__inbox__'){if(feedback){feedback.hidden=false;feedback.textContent='Asigna este host a un proyecto antes de enseñar semántica.';}return;}
    const cls=String(classification||currentInlineClass||'').toLowerCase();
    const identityId=Number(inlinePopover?.querySelector('[data-inline-identity]')?.value||0),objectType=String(inlinePopover?.querySelector('[data-inline-object-type]')?.value||'').trim();
    if(currentInlineKind==='field'){
      if(cls==='entity'&&!objectType){if(feedback){feedback.hidden=false;feedback.textContent='Indica el tipo de Object.';}return;}
      const fd=new FormData();fd.set('csrf',root.dataset.csrf||'');fd.set('key',v.key||'');fd.set('classification',cls||'ignore');fd.set('object_type',objectType);fd.set('note','');
      try{
        const url=`/t/${encodeURIComponent(selected.source)}/exchange/${Number(selected.exchange)}/field-semantics`,res=await fetch(url,{method:'POST',body:fd,headers:{Accept:'application/json'}}),body=await res.json().catch(()=>({}));
        if(!res.ok||body.ok===false)throw new Error(body.error||`HTTP ${res.status}`);closeInline();await reloadSelected();
      }catch(err){if(feedback){feedback.hidden=false;feedback.textContent=`No pude guardar: ${err.message}`;}}
      return;
    }
    if(['auth','resolver','context'].includes(cls)&&!identityId){if(feedback){feedback.hidden=false;feedback.textContent='Selecciona una Identity.';}return;}
    if(cls==='entity'&&!objectType){if(feedback){feedback.hidden=false;feedback.textContent='Indica el tipo de Object.';}return;}
    const fd=new FormData();fd.set('csrf',root.dataset.csrf||'');fd.set('annotations_json',JSON.stringify([{side:v.side,location:v.location,key:v.key,value:v.value,classification:cls||'ignore',identity_id:identityId||null,object_type:objectType,note:''}]));
    try{
      const url=`/t/${encodeURIComponent(selected.source)}/exchange/${Number(selected.exchange)}/annotations/batch`,res=await fetch(url,{method:'POST',body:fd,headers:{Accept:'application/json'}}),body=await res.json().catch(()=>({}));
      if(!res.ok||body.ok===false)throw new Error(body.error||`HTTP ${res.status}`);closeInline();await reloadSelected();
    }catch(err){if(feedback){feedback.hidden=false;feedback.textContent=`No pude guardar: ${err.message}`;}}
  };

  // ---- Marking / mental flow drafting -------------------------------------
  // Preference keys are declared near Workbench initialization so every control can use them safely.
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
  if(splitter&&stack){let dragging=false;splitter.addEventListener('pointerdown',ev=>{dragging=true;splitter.setPointerCapture(ev.pointerId);document.body.classList.add('wb-resizing');});splitter.addEventListener('pointermove',ev=>{if(!dragging)return;const rect=stack.getBoundingClientRect();setSplit(((ev.clientX-rect.left)/rect.width)*100);});splitter.addEventListener('pointerup',()=>{dragging=false;document.body.classList.remove('wb-resizing');});splitter.addEventListener('pointercancel',()=>{dragging=false;document.body.classList.remove('wb-resizing');});splitter.addEventListener('dblclick',()=>setSplit(50));}

  // Traffic height is independently resizable, just like the Request/Response width.
  const trafficSplitter=root.querySelector('[data-traffic-splitter]'),grid=root.querySelector('.wb-grid');
  const setTrafficHeight=(px,{persist=true}={})=>{if(!grid)return;const rect=grid.getBoundingClientRect(),max=Math.max(180,rect.height*0.68),h=Math.max(120,Math.min(max,Number(px)||rect.height*.27));root.style.setProperty('--wb-traffic-height',`${Math.round(h)}px`);if(persist)localStorage.setItem(trafficHeightKey,String(Math.round(h)));};
  const restoreTrafficHeight=()=>{const saved=Number(localStorage.getItem(trafficHeightKey)||0);if(saved>0)setTrafficHeight(saved,{persist:false});else root.style.removeProperty('--wb-traffic-height');};
  restoreTrafficHeight();
  if(trafficSplitter&&grid){let dragging=false;trafficSplitter.addEventListener('pointerdown',ev=>{dragging=true;trafficSplitter.setPointerCapture(ev.pointerId);document.body.classList.add('wb-traffic-resizing');ev.preventDefault();});trafficSplitter.addEventListener('pointermove',ev=>{if(!dragging)return;const rect=grid.getBoundingClientRect();setTrafficHeight(ev.clientY-rect.top);});const stop=()=>{dragging=false;document.body.classList.remove('wb-traffic-resizing');};trafficSplitter.addEventListener('pointerup',stop);trafficSplitter.addEventListener('pointercancel',stop);trafficSplitter.addEventListener('dblclick',()=>{localStorage.removeItem(trafficHeightKey);root.style.removeProperty('--wb-traffic-height');});}

  const setContextHidden=(hidden,{persist=true}={})=>{root.classList.toggle('context-hidden',hidden);if(persist)localStorage.setItem(contextKey,hidden?'1':'0');root.querySelectorAll('[data-context-toggle]').forEach(b=>{b.classList.toggle('active',!hidden);b.setAttribute('aria-expanded',hidden?'false':'true');});};
  const setTrafficCollapsed=(collapsed)=>{root.classList.remove('traffic-hidden');root.classList.toggle('traffic-collapsed',collapsed);localStorage.setItem(trafficKey,collapsed?'1':'0');root.querySelectorAll('[data-traffic-toggle]').forEach(b=>{b.classList.toggle('active',!collapsed);b.setAttribute('aria-expanded',collapsed?'false':'true');});if(!collapsed){restoreTrafficHeight();const r=rows().find(x=>Number(x.dataset.eventId)===selected.event);window.setTimeout(()=>r?.scrollIntoView({block:'nearest'}),0);}};
  setContextHidden(localStorage.getItem(contextKey)==='1');
  setTrafficCollapsed(localStorage.getItem(trafficKey)==='1');
  const setFocus=(on)=>{document.body.classList.toggle('workbench-focus',on);root.classList.toggle('focus-mode',on);root.querySelectorAll('[data-focus-toggle]').forEach(b=>b.classList.toggle('active',on));};
  const setTrafficVisibility=(mode)=>{const next=['all','focus','target'].includes(String(mode))?String(mode):'focus';const u=new URL(window.location.href);u.searchParams.set('visibility',next);u.searchParams.set('target',next==='target'?targetKey:'all');u.searchParams.delete('event');window.location.href=u.toString();};
  root.querySelectorAll('[data-visibility-mode]').forEach(b=>b.addEventListener('click',()=>setTrafficVisibility(b.dataset.visibilityMode)));

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
  const decodeJwt=(token)=>{const parts=String(token||'').split('.');if(parts.length!==3)return {header:{},claims:{},signature:'',errors:['El token no tiene las 3 partes esperadas de un JWT.']};const errors=[];let header={},claims={};try{header=JSON.parse(b64urlText(parts[0]));}catch(err){errors.push(`Header: ${err?.message||'no se pudo decodificar'}`);}try{claims=JSON.parse(b64urlText(parts[1]));}catch(err){errors.push(`Payload: ${err?.message||'no se pudo decodificar'}`);}return {header,claims,signature:parts[2],errors};};
  const claimTime=(key,value)=>{if(!['iat','exp','nbf'].includes(String(key))||!Number.isFinite(Number(value)))return '';const ms=Number(value)*1000,date=new Date(ms),delta=ms-Date.now();const mins=Math.round(Math.abs(delta)/60000);let relative='';if(key==='exp')relative=delta>=0?`vigente · vence en ${mins<60?mins+' min':Math.round(mins/60)+' h'}`:`expiró hace ${mins<60?mins+' min':Math.round(mins/60)+' h'}`;else if(key==='nbf')relative=delta>0?`válido en ${mins<60?mins+' min':Math.round(mins/60)+' h'}`:'ya válido';else relative=`emitido ${delta<=0?'hace ':''}${mins<60?mins+' min':Math.round(mins/60)+' h'}`;return `${date.toLocaleString()} · ${relative}`;};
  const claimValue=(v)=>{if(v===null)return 'null';if(Array.isArray(v))return v.join(', ');if(typeof v==='object')return JSON.stringify(v);return String(v);};
  const jwtParentIndex=(token)=>{const needle=jwtTokenFromValue(token)||String(token||'').trim();return inlineValues.findIndex(v=>(jwtTokenFromValue(v.value)||String(v.value||'').trim())===needle&&String(v.detected_type||'').toUpperCase()==='JWT');};
  const ensureJwtClaimCandidate=(parentIndex,key,value)=>{
    const parent=inlineValues[Number(parentIndex)];if(!parent)return -1;const meta=(parent.jwt_claims||[]).find(c=>String(c.key||'')===String(key||''))||{};
    const claimKey=`jwt.${String(key||'')}`,claimValue=String(value??''),location=String(meta.location||`${parent.location}#jwt:${key}`);
    let idx=inlineValues.findIndex(v=>String(v.side||'')===String(parent.side||'')&&String(v.location||'')===location&&String(v.key||'')===claimKey&&String(v.value||'')===claimValue);
    if(idx<0){inlineValues.push({side:parent.side,location,key:claimKey,value:claimValue,preview:claimValue,detected_type:'jwt_claim',default_classification:(meta.field_semantic||{}).classification||meta.default_classification||'ignore',annotation:meta.annotation||null,field_semantic:meta.field_semantic||null,jwt_claim_name:String(key||'')});idx=inlineValues.length-1;}
    return idx;
  };
  const claimRows=(obj,{interactive=false,parentIndex=-1}={})=>Object.entries(obj||{}).map(([k,v])=>{const raw=claimValue(v),idx=interactive?ensureJwtClaimCandidate(parentIndex,k,raw):-1,meta=idx>=0?(inlineValues[idx]||{}):{},ann=meta.annotation||{},cls=String(ann.classification||meta.default_classification||'ignore').toLowerCase(),badge=['auth','resolver','context','entity'].includes(cls)?`<em class="wb-jwt-semantic semantic-${esc(cls)}">${esc(cls.toUpperCase())}</em>`:'';return `<div class="wb-jwt-claim ${idx>=0?'is-interactive':''}"><code ${idx>=0?`role="button" tabindex="0" data-jwt-claim-field-index="${idx}" title="Enseñar el claim jwt.${esc(k)}"`:''}>${esc(k)}</code><div><strong ${idx>=0?`role="button" tabindex="0" data-jwt-claim-value-index="${idx}" title="Enseñar este valor a Negro"`:''}>${esc(raw)}</strong>${badge}${claimTime(k,v)?`<small>${esc(claimTime(k,v))}</small>`:''}</div></div>`;}).join('')||'<p class="wb-muted">Sin datos.</p>';
  const openJwt=(token)=>{if(!jwtDialog)return;currentJwt=jwtTokenFromValue(token)||String(token||'').trim();const full=jwtDialog.querySelector('[data-jwt-full]');if(full){full.value=currentJwt;full.classList.remove('expanded');}const len=jwtDialog.querySelector('[data-jwt-length]');if(len)len.textContent=`${currentJwt.length} caracteres`;const errBox=jwtDialog.querySelector('[data-jwt-error]');let d={header:{},claims:{},signature:'',errors:[]};try{d=decodeJwt(currentJwt);}catch(err){d.errors=[String(err?.message||err||'No se pudo decodificar el JWT')];}const parentIndex=jwtParentIndex(currentJwt);const h=jwtDialog.querySelector('[data-jwt-header]');if(h)h.innerHTML=claimRows(d.header);const c=jwtDialog.querySelector('[data-jwt-claims]');if(c)c.innerHTML=claimRows(d.claims,{interactive:parentIndex>=0,parentIndex});const sig=jwtDialog.querySelector('[data-jwt-signature]');if(sig)sig.textContent=d.signature?'✓ Signature presente':'⚠ Sin signature';if(errBox){const errors=d.errors||[];errBox.hidden=!errors.length;errBox.textContent=errors.length?`No se pudo decodificar completamente: ${errors.join(' · ')}`:'';}try{if(!jwtDialog.open)jwtDialog.showModal();}catch(err){jwtDialog.setAttribute('open','');console.warn('JWT Inspector modal fallback',err);}};
  const openJwtClaimSemantic=(idx,anchor,kind='value')=>{const rect=anchor.getBoundingClientRect();try{jwtDialog?.close();}catch(_){}const virtualAnchor={getBoundingClientRect:()=>rect};window.setTimeout(()=>kind==='field'?openInlineField(Number(idx),virtualAnchor):openInline(Number(idx),virtualAnchor),0);};
  // Capture-phase fallback: JWT is a first-class action in the Workbench.
  // Keeping this independent from the generic code/copy delegation makes the
  // inspector reliable even when the token is nested inside syntax-highlight spans.
  document.addEventListener('click',ev=>{
    const trigger=ev.target?.closest?.('[data-jwt-open]');
    if(!trigger||!root.contains(trigger))return;
    ev.preventDefault();
    ev.stopPropagation();
    openJwt(trigger.dataset.jwtToken||'');
  },true);

  // ---- Live capture timeline ------------------------------------------------
  const unreadBadge=root.querySelector('[data-unread-badge]'),jump=root.querySelector('[data-new-events-jump]'),liveFollowBtn=root.querySelector('[data-live-follow-toggle]');
  let cursorEventId=Math.max(Number(root.dataset.latestEventId||0),...rows().map(r=>Number(r.dataset.eventId||0)),0),liveStopped=false,liveFollow=root.dataset.liveFollowDefault==='1';
  // Session-local queue: events that arrived while this page was open and have not
  // been reviewed yet. Unlike the global unread badge, this powers the bottom
  // “N nuevas” control and must shrink as the analyst opens those requests.
  const pendingReviewIds=new Set();
  const atBottom=()=>!list||((list.scrollHeight-list.scrollTop-list.clientHeight)<40);
  const setLiveFollow=(on,{jumpToEnd=false}={})=>{liveFollow=!!on;liveFollowBtn?.classList.toggle('active',liveFollow);const label=liveFollowBtn?.querySelector('b');if(label)label.textContent=liveFollow?'Siguiendo LIVE':'Seguir LIVE';if(liveFollow&&jumpToEnd&&list)list.scrollTop=list.scrollHeight;};
  setLiveFollow(liveFollow);
  const tagHtml=(t)=>`<em class="wb-tag tag-${esc(t.kind||'neutral')}">${esc(t.label||'')}</em>`;
  const paramHtml=(items)=>{const ps=(items||[]).slice(0,4);if(!ps.length)return '';return `<span class="wb-param-preview">${ps.map(p=>`<em title="${esc((p.location||'')+' · '+(p.name||'')+'='+(p.value||''))}"><b>${esc(p.name||'')}</b>${String(p.value??'')!==''?`=<span>${esc(p.value)}</span>`:''}</em>`).join('')}</span>`;};
  const rowHtml=(r)=>{const unread=!!r.is_unread,isTarget=String(r.target_key||'')===String(targetKey);return `<a class="wb-traffic-row ${isTarget?'is-target-row':'is-outside-target'} ${unread?'is-unread':''}" href="?event=${Number(r.id)}" data-source-key="${esc(r.target_key||'')}" data-event-id="${Number(r.id)}" data-exchange-id="${Number(r.exchange_id||0)}" data-compound-id="${esc(r.compound_id||('event:'+r.id))}" data-unread="${unread?'1':'0'}"><span class="wb-row-id"><i class="wb-unread-dot" title="Nueva, aún no vista"></i><i class="wb-mark-pin" data-mark-toggle title="Marcar Request"></i>${Number(r.id)}</span><b class="${methodClass(r.method)}">${esc(r.method||'')}</b><strong class="wb-row-host" title="${esc(r.hostname||'')}">${esc(r.hostname||'')}</strong><span class="wb-row-endpoint" title="${esc(r.path||'/')}"><code>${esc(r.path||'/')}</code>${paramHtml(r.request_params)}</span><span class="wb-status status-${Math.floor(Number(r.status_code||0)/100)}xx">${esc(r.status_code??'—')}</span><span class="wb-tags">${r.interaction_kind==='EXPERIMENT'?`<em class="wb-tag tag-experiment" title="${esc(r.provenance_source||'EXPERIMENT')}">EXPERIMENT</em>`:''}${(r.tags||[]).map(tagHtml).join('')}${r.is_inbox?'<em class="wb-tag tag-inbox">Sin proyecto</em>':''}</span><time>${esc(String(r.captured_at||'').slice(11,19))}</time></a>`;};
  const updateJump=()=>{if(!jump)return;const count=pendingReviewIds.size;jump.hidden=count<=0;const b=jump.querySelector('b');if(b)b.textContent=String(count);};
  const markPendingReviewed=(eventId)=>{const id=Number(eventId||0);if(id>0&&pendingReviewIds.delete(id))updateJump();};
  const MAX_LIVE_DOM_ROWS=650;
  const pruneLiveDom=()=>{if(!list)return;let current=rows();if(current.length<=MAX_LIVE_DOM_ROWS)return;let removeCount=current.length-MAX_LIVE_DOM_ROWS;for(const row of current){if(removeCount<=0)break;if(row.classList.contains('active')||row.classList.contains('marked'))continue;row.remove();removeCount--;}};
  const appendEvents=(items)=>{if(!list||!items?.length)return;list.querySelector('.wb-empty')?.remove();const fresh=items.filter(r=>!root.querySelector(`[data-event-id="${Number(r.id)}"]`));const html=fresh.map(rowHtml).join('');if(!html)return;const temp=document.createElement('div');temp.innerHTML=html;const added=[...temp.children];added.forEach(el=>list.appendChild(el));applyMarks();const countEl=root.querySelector('[data-event-count]');if(countEl){const currentTotal=Number(countEl.textContent||0);countEl.textContent=String(currentTotal+fresh.length);}const shownUnread=Number(root.querySelector('[data-unread-count]')?.textContent||0),addedUnread=fresh.filter(r=>r.is_unread).length;setUnreadCount(shownUnread+addedUnread);fresh.forEach(r=>{if(r.is_unread)pendingReviewIds.add(Number(r.id));});pruneLiveDom();if(liveFollow)list.scrollTop=list.scrollHeight;updateJump();};
  const liveParams=()=>{const current=new URL(window.location.href),p=new URLSearchParams();['q','target','visibility','host','method','status','scope','tool'].forEach(k=>{const v=current.searchParams.get(k);if(v)p.set(k,v);});p.set('hide_static',current.searchParams.get('hide_static')??'1');const since=Number(root.dataset.sinceEventId||0);if(since>0)p.set('since_event_id',String(since));p.set('after_event_id',String(cursorEventId));return p;};
  let livePollInFlight=false;
  const pollLive=async()=>{if(liveStopped||!liveUrl||livePollInFlight)return;livePollInFlight=true;try{const u=new URL(liveUrl,window.location.origin);u.search=liveParams().toString();const res=await fetch(u,{headers:{Accept:'application/json'},cache:'no-store'});if(res.ok){const data=await res.json();appendEvents(data.rows||[]);cursorEventId=Math.max(cursorEventId,Number(data.latest_event_id||0));}}catch(err){console.debug('Workbench live',err);}finally{livePollInFlight=false;if(!liveStopped)window.setTimeout(pollLive,document.hidden?1800:850);}};
  if(list){if(liveFollow)list.scrollTop=list.scrollHeight;else active?.scrollIntoView({block:'nearest'});list.addEventListener('scroll',()=>{if(liveFollow&&!atBottom())setLiveFollow(false);},{passive:true});window.setTimeout(pollLive,350);}
  window.addEventListener('beforeunload',()=>{liveStopped=true;});

  // ---- Passive project analysis scope --------------------------------------
  const analysisDialog=root.querySelector('[data-analysis-scope-dialog]');
  const openAnalysisScope=(button)=>{if(!analysisDialog)return;const host=button?.dataset.host||'',method=button?.dataset.method||'GET',path=button?.dataset.path||'/',eventId=Number(button?.dataset.eventId||selected.event||0);analysisDialog.dataset.eventId=String(eventId);analysisDialog.dataset.host=host;analysisDialog.dataset.method=method;analysisDialog.dataset.path=path;const h=analysisDialog.querySelector('[data-analysis-host]'),e=analysisDialog.querySelector('[data-analysis-endpoint]'),f=analysisDialog.querySelector('[data-analysis-scope-feedback]');if(h)h.textContent=host||'—';if(e)e.textContent=`${method} ${path}`;if(f){f.hidden=true;f.textContent='';}try{analysisDialog.showModal();}catch(_){analysisDialog.setAttribute('open','');}};
  const closeAnalysisScope=()=>{try{analysisDialog?.close();}catch(_){analysisDialog?.removeAttribute('open');}};
  analysisDialog?.querySelector('[data-analysis-scope-form]')?.addEventListener('submit',async ev=>{ev.preventDefault();const feedback=analysisDialog.querySelector('[data-analysis-scope-feedback]'),ruleType=analysisDialog.querySelector('input[name="analysis_rule_type"]:checked')?.value||'host',eventId=Number(analysisDialog.dataset.eventId||0);if(!eventId||!analysisScopeUrl)return;feedback.hidden=false;feedback.textContent='Incluyendo tráfico…';try{const res=await fetch(analysisScopeUrl,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({csrf:root.dataset.csrf||'',event_id:eventId,rule_type:ruleType})}),body=await res.json().catch(()=>({}));if(!res.ok)throw new Error(body.detail||`HTTP ${res.status}`);feedback.textContent=`Listo · ${Number(body.moved_events||0)} evento(s) incluidos. Recon activo no cambió.`;window.setTimeout(()=>{const u=new URL(window.location.href);u.searchParams.set('target',targetKey);u.searchParams.set('event',String(eventId));window.location.href=u.toString();},450);}catch(err){feedback.textContent=`No pude incluirlo: ${err.message}`;}});

  const removeAnalysisRule=async(button)=>{const ruleId=Number(button?.dataset.ruleId||0);if(!ruleId||!analysisScopeRemoveUrl)return;const label=button?.dataset.ruleLabel||'esta regla';if(!window.confirm(`¿Retirar ${label} del target de análisis?\n\nEl tráfico histórico volverá a Traffic Inbox. Los Flows y evidencia ya creados no se borran. El scope autorizado de Recon no cambia.`))return;button.disabled=true;const original=button.textContent;button.textContent='Retirando…';try{const res=await fetch(analysisScopeRemoveUrl,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({csrf:root.dataset.csrf||'',rule_id:ruleId,move_history:true})}),body=await res.json().catch(()=>({}));if(!res.ok)throw new Error(body.detail||`HTTP ${res.status}`);const u=new URL(window.location.href);u.searchParams.set('visibility','focus');u.searchParams.set('target','all');if(selected.event)u.searchParams.set('event',String(selected.event));window.location.href=u.toString();}catch(err){window.alert(`No pude retirarlo: ${err.message}`);button.disabled=false;button.textContent=original;}};

  // ---- Events --------------------------------------------------------------
  list?.addEventListener('click',ev=>{const pin=ev.target.closest('[data-mark-toggle]');if(pin){ev.preventDefault();ev.stopPropagation();setMark(pin.closest('[data-source-key][data-event-id]'),activeColor);return;}const a=ev.target.closest('[data-source-key][data-event-id]');if(!a)return;ev.preventDefault();setLiveFollow(false);const eventId=Number(a.dataset.eventId);rows().forEach(r=>r.classList.toggle('active',r===a));loadEvent(eventId);});
  root.addEventListener('click',ev=>{
    const color=ev.target.closest('[data-mark-color]');if(color){activeColor=color.dataset.markColor;root.querySelectorAll('[data-mark-color]').forEach(b=>b.classList.toggle('active',b===color));return;}
    if(ev.target.closest('[data-clear-marks]')){clearMarks();return;}
    if(ev.target.closest('[data-create-flow-marked]')){openFlowDialog();return;}
    if(ev.target.closest('[data-close-flow-dialog]')){closeFlowDialog();return;}
    const layout=ev.target.closest('button[data-pane-layout]');if(layout){setPaneLayout(layout.dataset.paneLayout);return;}
    if(ev.target.closest('[data-context-toggle]')){setContextHidden(!root.classList.contains('context-hidden'),{persist:!document.fullscreenElement});return;}
    if(ev.target.closest('[data-traffic-toggle]')){setTrafficCollapsed(!root.classList.contains('traffic-collapsed'));return;}
    if(ev.target.closest('[data-http-fullscreen]')){toggleFullscreen();return;}
    const wrapBtn=ev.target.closest('[data-wb-wrap]');if(wrapBtn){const side=wrapBtn.dataset.wbWrap,pre=root.querySelector(`[data-http-view="${side}"]`),next=!pre?.classList.contains('exact-lines');setExactLines(side,next);localStorage.setItem(wrapKey,next?'1':'0');return;}
    if(ev.target.closest('[data-focus-toggle]')){setFocus(!document.body.classList.contains('workbench-focus'));return;}
    const jwt=ev.target.closest('[data-jwt-open],[data-jwt-token]');if(jwt){ev.preventDefault();ev.stopPropagation();openJwt(jwt.dataset.jwtToken||jwt.dataset.copyValue||'');return;}
    const jwtClaimValue=ev.target.closest('[data-jwt-claim-value-index]');if(jwtClaimValue){ev.preventDefault();ev.stopPropagation();openJwtClaimSemantic(Number(jwtClaimValue.dataset.jwtClaimValueIndex),jwtClaimValue,'value');return;}
    const jwtClaimField=ev.target.closest('[data-jwt-claim-field-index]');if(jwtClaimField){ev.preventDefault();ev.stopPropagation();openJwtClaimSemantic(Number(jwtClaimField.dataset.jwtClaimFieldIndex),jwtClaimField,'field');return;}
    const analysisOpen=ev.target.closest('[data-analysis-scope-open]');if(analysisOpen){ev.preventDefault();openAnalysisScope(analysisOpen);return;}
    if(ev.target.closest('[data-analysis-scope-close]')){ev.preventDefault();closeAnalysisScope();return;}
    const analysisRemove=ev.target.closest('[data-analysis-scope-remove]');if(analysisRemove){ev.preventDefault();removeAnalysisRule(analysisRemove);return;}
    const inline=ev.target.closest('[data-inline-index]');if(inline){ev.preventDefault();openInline(Number(inline.dataset.inlineIndex),inline);return;}
    const inlineField=ev.target.closest('[data-inline-field-index]');if(inlineField){ev.preventDefault();openInlineField(Number(inlineField.dataset.inlineFieldIndex),inlineField);return;}
    if(ev.target.closest('[data-inline-close]')){closeInline();return;}
    const inlineClass=ev.target.closest('[data-inline-class]');if(inlineClass){setInlineClass(inlineClass.dataset.inlineClass);return;}
    if(ev.target.closest('[data-inline-save]')){saveInline(currentInlineClass);return;}
    if(ev.target.closest('[data-inline-ignore]')){saveInline('ignore');return;}
    if(ev.target.closest('[data-close-jwt-dialog]')){jwtDialog?.close();return;}
    if(ev.target.closest('[data-copy-jwt]')){navigator.clipboard?.writeText(currentJwt);const b=ev.target.closest('[data-copy-jwt]');if(b){const old=b.textContent;b.textContent='Copiado';setTimeout(()=>b.textContent=old,800);}return;}
    if(ev.target.closest('[data-toggle-jwt-full]')){const area=jwtDialog?.querySelector('[data-jwt-full]');if(area){area.classList.toggle('expanded');ev.target.closest('[data-toggle-jwt-full]').textContent=area.classList.contains('expanded')?'Contraer':'Expandir';}return;}
    if(ev.target.closest('[data-new-events-jump]')){const next=[...pendingReviewIds].sort((a,b)=>a-b)[0];if(next){setLiveFollow(false);loadEvent(next,{scroll:true});}else setLiveFollow(true,{jumpToEnd:true});return;}
    if(ev.target.closest('[data-live-follow-toggle]')){setLiveFollow(!liveFollow,{jumpToEnd:!liveFollow});return;}
    if(ev.target.closest('[data-unread-badge]')){if(seenAllUrl){fetch(seenAllUrl,{method:'POST',headers:{'Content-Type':'application/json','Accept':'application/json'},body:JSON.stringify({csrf:root.dataset.csrf||'',through_event_id:cursorEventId})}).then(r=>r.json()).then(d=>{rows().forEach(r=>{r.classList.remove('is-unread');r.dataset.unread='0';});setUnreadCount(Number(d.unread_count||0));}).catch(()=>{});}return;}
    const cv=ev.target.closest('[data-copy-value]');if(cv){navigator.clipboard?.writeText(cv.dataset.copyValue||'');cv.classList.add('copied');setTimeout(()=>cv.classList.remove('copied'),700);return;}
    const rel=ev.target.closest('[data-related-source][data-related-exchange]');if(rel){ev.preventDefault();loadExchange(rel.dataset.relatedSource,Number(rel.dataset.relatedExchange));return;}
    const view=ev.target.closest('[data-view-mode]');if(view){mode[view.dataset.viewMode]=view.dataset.mode;paint(view.dataset.viewMode);return;}
    const copy=ev.target.closest('[data-copy-http]');if(copy){navigator.clipboard?.writeText(raw[copy.dataset.copyHttp]||'');copy.textContent='Copiado';setTimeout(()=>copy.textContent='Copiar',800);}
  });
  dialog?.querySelector('[name="mark_scope"]')?.addEventListener('change',refreshFlowDialogCount);
  dialog?.querySelector('[data-flow-dialog-form]')?.addEventListener('submit',ev=>{ev.preventDefault();const fd=new FormData(ev.currentTarget);createFlow(fd.get('flow_name')||'',fd.get('mark_scope')||'all');});
  document.addEventListener('pointerdown',ev=>{if(inlinePopover&&!inlinePopover.hidden&&!ev.target.closest('[data-inline-popover]')&&!ev.target.closest('[data-inline-index]')&&!ev.target.closest('[data-inline-field-index]')&&!ev.target.closest('[data-jwt-open]'))closeInline();});
  document.addEventListener('keydown',ev=>{
    const jwtFocus=ev.target?.closest?.('[data-jwt-open],[data-jwt-token]');if(jwtFocus&&(ev.key==='Enter'||ev.key===' ')){ev.preventDefault();openJwt(jwtFocus.dataset.jwtToken||jwtFocus.dataset.copyValue||'');return;}
    const jwtClaimValueFocus=ev.target?.closest?.('[data-jwt-claim-value-index]');if(jwtClaimValueFocus&&(ev.key==='Enter'||ev.key===' ')){ev.preventDefault();openJwtClaimSemantic(Number(jwtClaimValueFocus.dataset.jwtClaimValueIndex),jwtClaimValueFocus,'value');return;}
    const jwtClaimFieldFocus=ev.target?.closest?.('[data-jwt-claim-field-index]');if(jwtClaimFieldFocus&&(ev.key==='Enter'||ev.key===' ')){ev.preventDefault();openJwtClaimSemantic(Number(jwtClaimFieldFocus.dataset.jwtClaimFieldIndex),jwtClaimFieldFocus,'field');return;}
    const inlineFocus=ev.target?.closest?.('[data-inline-index]');if(inlineFocus&&(ev.key==='Enter'||ev.key===' ')){ev.preventDefault();openInline(Number(inlineFocus.dataset.inlineIndex),inlineFocus);return;}
    const inlineFieldFocus=ev.target?.closest?.('[data-inline-field-index]');if(inlineFieldFocus&&(ev.key==='Enter'||ev.key===' ')){ev.preventDefault();openInlineField(Number(inlineFieldFocus.dataset.inlineFieldIndex),inlineFieldFocus);return;}
    if(ev.key==='Escape'&&!inlinePopover?.hidden){closeInline();return;}
    const tag=(document.activeElement?.tagName||'').toLowerCase();if(['input','textarea','select'].includes(tag))return;
    if(ev.key==='/'){const q=root.querySelector('.wb-search input[name="q"]');if(q){ev.preventDefault();q.focus();}return;}
    if(ev.key.toLowerCase()==='f'){ev.preventDefault();setFocus(!document.body.classList.contains('workbench-focus'));return;}
    if(ev.key.toLowerCase()==='t'){ev.preventDefault();setTrafficCollapsed(!root.classList.contains('traffic-collapsed'));return;}
    if(ev.key.toLowerCase()==='c'){ev.preventDefault();setContextHidden(!root.classList.contains('context-hidden'),{persist:!document.fullscreenElement});return;}
    if(['0','1','2','3','4'].includes(ev.key)){const r=rows().find(x=>Number(x.dataset.eventId)===selected.event);if(r){ev.preventDefault();const colors={1:'blue',2:'green',3:'purple',4:'orange'};if(ev.key==='0'){const k=markId(r);delete marks[k];saveMarks();applyMarks();}else setMark(r,colors[ev.key]);}return;}
    if(!['ArrowDown','ArrowUp','j','k'].includes(ev.key))return;
    const rs=rows();if(!rs.length)return;let idx=rs.findIndex(r=>Number(r.dataset.eventId)===selected.event);if(idx<0)idx=rs.length-1;idx=(ev.key==='ArrowDown'||ev.key==='j')?Math.min(rs.length-1,idx+1):Math.max(0,idx-1);const r=rs[idx];ev.preventDefault();loadEvent(Number(r.dataset.eventId));
  });
})();
