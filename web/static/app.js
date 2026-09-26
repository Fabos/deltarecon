(() => {
  const root = document.querySelector('[data-jobs]');
  if (!root) return;
  const esc = (v) => String(v ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
  async function refresh() {
    try {
      const res = await fetch('/api/jobs', {headers:{'Accept':'application/json'}});
      if (!res.ok) return;
      const data = await res.json();
      const jobs = data.jobs || [];
      if (!jobs.length) return;
      root.innerHTML = jobs.map(j => `<div class="job"><span class="status-dot ${esc(j.status)}"></span><div><strong>${esc(j.label)}</strong><small>${esc(j.status)} · ${esc(j.started_at)}</small>${j.error ? `<small class="error">${esc(j.error)}</small>` : ''}</div></div>`).join('');
    } catch (_) {}
  }
  refresh();
  setInterval(refresh, 3000);
})();
