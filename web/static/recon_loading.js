(()=>{
  function ensureOverlay(){
    let el=document.querySelector('[data-recon-loading-overlay]');
    if(el)return el;
    el=document.createElement('div');
    el.className='recon-loading-overlay';
    el.setAttribute('data-recon-loading-overlay','');
    el.hidden=true;
    el.innerHTML=`<div class="recon-loading-card" role="status" aria-live="polite">
      <div class="recon-loading-spinner" aria-hidden="true"></div>
      <div><span class="eyebrow">RECON EN EJECUCIÓN</span><h2 data-recon-loading-title>Ejecutando tarea…</h2><p data-recon-loading-tools></p><small>No cierres esta vista. Negro guardará comando, stdout, stderr y evidencia de cada herramienta.</small></div>
    </div>`;
    document.body.appendChild(el);
    return el;
  }
  function bind(){
    document.querySelectorAll('form[data-recon-run]').forEach(form=>{
      if(form.dataset.reconLoadingBound==='1')return;
      form.dataset.reconLoadingBound='1';
      form.addEventListener('submit',(event)=>{
        event.preventDefault();
        const overlay=ensureOverlay();
        const title=overlay.querySelector('[data-recon-loading-title]');
        const tools=overlay.querySelector('[data-recon-loading-tools]');
        if(title)title.textContent=form.dataset.loadingLabel||'Ejecutando recon…';
        if(tools){
          const raw=(form.dataset.loadingTools||'').trim();
          tools.textContent=raw?`Herramientas previstas: ${raw}`:'Procesando y normalizando evidencia…';
        }
        const button=form.querySelector('button[type="submit"]');
        if(button){button.disabled=true;button.dataset.originalText=button.textContent;button.textContent='Ejecutando…';}
        overlay.hidden=false;
        document.body.classList.add('recon-is-loading');
        requestAnimationFrame(()=>requestAnimationFrame(()=>form.submit()));
      },{once:true});
    });
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bind);else bind();
})();
