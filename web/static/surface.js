(() => {
  const root = document.querySelector('[data-surface-root]');
  if (!root) return;
  const api = root.dataset.api;
  const rootDomain = root.dataset.rootDomain || '';
  const svg = root.querySelector('[data-surface-svg]');
  const stage = root.querySelector('[data-map-stage]');
  const detail = root.querySelector('[data-surface-detail]');
  const grid = root.querySelector('[data-host-grid]');
  const runList = root.querySelector('[data-run-list]');
  const empty = root.querySelector('[data-map-empty]');
  const visibleCount = root.querySelector('[data-visible-count]');
  const search = root.querySelector('[data-filter-search]');
  const filterEls = [...root.querySelectorAll('[data-filter]')];
  const layerEls = [...root.querySelectorAll('[data-layer]')];
  const collapseFamilies = root.querySelector('[data-collapse-families]');
  const viewBtns = [...root.querySelectorAll('[data-surface-view]')];
  const viewPanels = [...root.querySelectorAll('[data-view-panel]')];
  const importPanel = root.querySelector('[data-import-panel]');
  const NS = 'http://www.w3.org/2000/svg';
  let data = {hosts:[], filters:{}, summary:{}, tool_runs:[]};
  let selectedHost = '';
  let view = {x: 18, y: 18, k: 1};
  let pan = null;
  let sceneExtent = {width:1460,height:760};

  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const short = (s, n=34) => String(s || '').length > n ? `${String(s).slice(0,n-1)}…` : String(s || '');
  const codeClass = code => {
    const n = Number(code || 0);
    if (!n) return 'unknown';
    if (n >= 500) return 'error';
    if (n >= 400) return 'warn';
    if (n >= 300) return 'redirect';
    if (n >= 200) return 'ok';
    return 'unknown';
  };
  const envClass = env => String(env || 'UNKNOWN').toLowerCase();

  function fillSelect(name, values){
    const el = root.querySelector(`[data-filter="${name}"]`);
    if (!el) return;
    values.forEach(v => { const o=document.createElement('option'); o.value=String(v); o.textContent=String(v); el.appendChild(o); });
  }
  function filterEl(name){ return root.querySelector(`[data-filter="${name}"]`); }
  function selectedLayers(){ return new Set(layerEls.filter(x=>x.checked).map(x=>x.dataset.layer)); }
  function filters(){
    const f = {q:(search?.value||'').trim().toLowerCase()};
    filterEls.forEach(el => f[el.dataset.filter] = el.value || '');
    return f;
  }
  function haystack(h){
    return [h.hostname,h.title,h.url,h.webserver,h.location,h.family,h.environment,h.status_code,
      ...(h.technologies||[]),...(h.providers||[]),...(h.servers||[]),...(h.ips||[]),...(h.cnames||[]),...(h.sources||[])].join(' ').toLowerCase();
  }
  function visibleHosts(){
    const f=filters();
    return data.hosts.filter(h => {
      if(f.q && !haystack(h).includes(f.q)) return false;
      if(f.technology){
        const wanted=f.technology.toLowerCase();
        const ok=(h.technologies||[]).some(t=>{const got=String(t).toLowerCase();return got===wanted || (!wanted.includes(':') && got.startsWith(wanted+':'));});
        if(!ok)return false;
      }
      if(f.server && !(h.servers||[]).includes(f.server)) return false;
      if(f.provider && !(h.providers||[]).includes(f.provider)) return false;
      if(f.environment && h.environment !== f.environment) return false;
      if(f.status && String(h.status_code) !== f.status) return false;
      if(f.family && h.family !== f.family) return false;
      if(f.source && !(h.sources||[]).includes(f.source)) return false;
      return true;
    });
  }

  function node(type,id,label,meta={}){ return {type,id:`${type}:${id}`,key:id,label,meta}; }
  function edge(source,target,relation,kind='observed'){ return {source,target,relation,kind}; }

  function buildScene(hosts){
    const layers=selectedLayers();
    const collapsed=!!collapseFamilies?.checked;
    const nodes=[]; const edges=[]; const seen=new Set();
    const add=n=>{ if(!seen.has(n.id)){seen.add(n.id);nodes.push(n);} return n.id; };
    const rootId=add(node('root',rootDomain,rootDomain,{count:hosts.length}));
    const families = new Map();
    hosts.forEach(h=>{
      const family=h.family||'other';
      if(!families.has(family)) families.set(family,[]);
      families.get(family).push(h);
    });
    [...families.entries()].sort((a,b)=>a[0].localeCompare(b[0])).forEach(([family,items])=>{
      const fid=add(node('family',family,family,{count:items.length,heuristic:true,hosts:items.map(x=>x.hostname)}));
      edges.push(edge(rootId,fid,'POSSIBLE_FAMILY','heuristic'));
      if (collapsed) return;
      items.sort((a,b)=>a.hostname.localeCompare(b.hostname)).forEach(h=>{
        const hid=add(node('host',h.hostname,h.hostname,h));
        edges.push(edge(fid,hid,'GROUPS','heuristic'));
        if(layers.has('provider')) (h.providers||[]).forEach(p=>{const id=add(node('provider',p,p));edges.push(edge(hid,id,'PROXIED_BY','observed'));});
        if(layers.has('technology')) (h.technologies||[]).forEach(t=>{const id=add(node('technology',t,t));edges.push(edge(hid,id,'USES','fingerprint'));});
        if(layers.has('server')) (h.servers||[]).forEach(s=>{const id=add(node('server',s,s));edges.push(edge(hid,id,'SERVED_BY','fingerprint'));});
        if(layers.has('ip')) (h.ips||[]).slice(0,4).forEach(ip=>{const id=add(node('ip',ip,ip));edges.push(edge(hid,id,'OBSERVED_IP','observed'));});
      });
    });
    if(!collapsed){
      const visibleSet=new Set(hosts.map(h=>h.hostname));
      hosts.forEach(h=>(h.redirects||[]).forEach(dst=>{if(visibleSet.has(dst))edges.push(edge(`host:${h.hostname}`,`host:${dst}`,'REDIRECTS_TO','observed'));}));
    }
    return {nodes,edges,collapsed};
  }

  function layout(scene){
    const byType = type => scene.nodes.filter(n=>n.type===type);
    const roots=byType('root'), families=byType('family'), hosts=byType('host');
    const right=scene.nodes.filter(n=>['provider','technology','server','ip'].includes(n.type));
    const familyHosts=new Map();
    scene.edges.filter(e=>e.relation==='GROUPS').forEach(e=>{if(!familyHosts.has(e.source))familyHosts.set(e.source,[]);familyHosts.get(e.source).push(e.target);});
    let y=50; const pos=new Map();
    roots.forEach(n=>pos.set(n.id,{x:90,y:Math.max(120, Math.min(420, (scene.collapsed?families.length:hosts.length)*20))}));
    families.forEach(f=>{
      const ids=familyHosts.get(f.id)||[];
      const height=scene.collapsed?58:Math.max(76,ids.length*44);
      pos.set(f.id,{x:scene.collapsed?480:330,y:y+height/2});
      ids.forEach((id,i)=>pos.set(id,{x:620,y:y+36+i*44}));
      y+=height+22;
    });
    right.forEach((n,i)=>{
      const links=scene.edges.filter(e=>e.target===n.id).map(e=>pos.get(e.source)).filter(Boolean);
      const avg=links.length?links.reduce((s,p)=>s+p.y,0)/links.length:80+i*46;
      pos.set(n.id,{x:n.type==='ip'?1240:1010,y:avg + ((i%3)-1)*10});
    });
    return {pos,width:1460,height:Math.max(620,y+80)};
  }

  function svgEl(tag,attrs={}){const el=document.createElementNS(NS,tag);Object.entries(attrs).forEach(([k,v])=>el.setAttribute(k,String(v)));return el;}
  function renderGraph(){
    const hosts=visibleHosts();
    visibleCount.textContent=String(hosts.length);
    const scene=buildScene(hosts);
    empty.hidden=scene.nodes.length>1;
    svg.innerHTML='';
    const {pos,width,height}=layout(scene); sceneExtent={width,height};
    svg.setAttribute('viewBox','0 0 1460 760');
    const world=svgEl('g',{transform:`translate(${view.x} ${view.y}) scale(${view.k})`}); svg.appendChild(world);
    scene.edges.forEach(e=>{
      const a=pos.get(e.source), b=pos.get(e.target); if(!a||!b)return;
      const path=svgEl('path',{d:`M ${a.x+70} ${a.y} C ${a.x+150} ${a.y}, ${b.x-150} ${b.y}, ${b.x-70} ${b.y}`,class:`surface-edge ${e.kind}`});
      const title=svgEl('title'); title.textContent=e.relation; path.appendChild(title); world.appendChild(path);
    });
    scene.nodes.forEach(n=>{
      const p=pos.get(n.id); if(!p)return;
      const g=svgEl('g',{class:`surface-node ${n.type}${n.type==='host'&&selectedHost===n.key?' selected':''}`,transform:`translate(${p.x} ${p.y})`,tabindex:'0'});
      const w=n.type==='host'?230:n.type==='family'?210:n.type==='root'?190:190;
      const h=n.type==='family'&&scene.collapsed?42:n.type==='host'?34:30;
      const rect=svgEl('rect',{x:-w/2,y:-h/2,width:w,height:h,rx:n.type==='host'?9:14}); g.appendChild(rect);
      const text=svgEl('text',{x:0,y:scene.collapsed&&n.type==='family'?0:4,'text-anchor':'middle'}); text.textContent=short(n.label,n.type==='host'?31:28); g.appendChild(text);
      if(n.type==='family'&&scene.collapsed){const count=svgEl('text',{x:0,y:13,'text-anchor':'middle',class:'surface-node-sub'});count.textContent=`${n.meta.count} hosts`;g.appendChild(count);}
      if(n.type==='host'){const dot=svgEl('circle',{cx:-w/2+10,cy:0,r:4,class:`status-dot ${codeClass(n.meta.status_code)}`});g.appendChild(dot);}
      const title=svgEl('title'); title.textContent=n.label; g.appendChild(title);
      g.addEventListener('click',ev=>{ev.stopPropagation(); if(n.type==='host'){selectedHost=n.key;renderDetail(n.meta);renderGraph();} else if(n.type==='family'){renderNodeDetail(n,true);} else renderNodeDetail(n,false);});
      g.addEventListener('keydown',ev=>{if(ev.key==='Enter')g.dispatchEvent(new Event('click'));}); world.appendChild(g);
    });
  }

  function tags(items,cls=''){return (items||[]).map(x=>`<span class="surface-chip ${cls}">${esc(x)}</span>`).join('');}
  function renderDetail(h){
    if(!h){detail.innerHTML='<div class="surface-detail-empty"><span class="surface-detail-icon">◎</span><b>Selecciona una rama</b><p>Abre una familia o hostname para reducir ruido y revisar evidencia.</p></div>';return;}
    const sharedEdge=(h.providers||[]).some(x=>/cloudflare|fastly|cloudfront/i.test(x));
    detail.innerHTML=`
      <div class="surface-detail-head"><div><span class="eyebrow">HOSTNAME</span><h2>${esc(h.hostname)}</h2></div>${h.status_code?`<span class="surface-status ${codeClass(h.status_code)}">${esc(h.status_code)}</span>`:'<span class="surface-status unknown">HTTP ?</span>'}</div>
      ${h.title?`<p class="surface-title">${esc(h.title)}</p>`:''}
      <div class="surface-detail-grid"><div><span>Ambiente</span><b class="env-${envClass(h.environment)}">${esc(h.environment||'UNKNOWN')}</b></div><div><span>Familia</span><b>${esc(h.family||'—')}</b><small>heurística</small></div><div><span>DNS</span><b>${esc(h.dns_state||'UNKNOWN')}</b></div><div><span>HTTP</span><b>${esc(h.http_state||'UNKNOWN')}</b></div></div>
      <section><h3>Tecnologías</h3><div class="surface-chips">${tags(h.technologies,'technology')||'<span class="muted">Sin fingerprint</span>'}</div></section>
      <section><h3>Entrega / proveedor</h3><div class="surface-chips">${tags(h.providers,'provider')||'<span class="muted">No identificado</span>'}</div></section>
      <section><h3>Servidor observado</h3><div class="surface-chips">${tags(h.servers,'server')||'<span class="muted">No identificado</span>'}</div></section>
      <section><h3>DNS / red</h3><dl class="surface-kv"><dt>IP observada</dt><dd>${(h.ips||[]).map(esc).join('<br>')||'—'}</dd><dt>CNAME</dt><dd>${(h.cnames||[]).map(esc).join('<br>')||'—'}</dd><dt>Origin</dt><dd><b>UNKNOWN</b> <small>no se infiere desde edge/CDN</small></dd></dl></section>
      ${h.location?`<section><h3>Redirect</h3><code class="surface-code">${esc(h.location)}</code></section>`:''}
      <section><h3>Siguiente lectura</h3><div class="surface-action-note ${sharedEdge?'caution':''}">${sharedEdge?'Nmap no se recomienda sobre la IP observada: parece edge/CDN compartido. Profundiza por hostname, TLS, HTTP o busca origin con evidencia.':'Este host no está marcado como edge compartido. Antes de Nmap, valida propiedad/scope y si la IP es realmente infraestructura directa.'}</div></section>
      <section><h3>Evidencia</h3><div class="surface-chips">${tags(h.sources,'source')}</div><small class="muted">Última observación: ${esc(h.last_seen_at||'—')}</small></section>
      ${h.url?`<a class="button ghost full" target="_blank" rel="noopener noreferrer" href="${esc(h.url)}">Abrir host ↗</a>`:''}`;
  }
  function enterFamily(name){
    const sel=filterEl('family'); if(sel) sel.value=name;
    if(collapseFamilies) collapseFamilies.checked=false;
    selectedHost=''; renderDetail(null); refresh(); fit();
  }
  function renderNodeDetail(n, family=false){
    detail.innerHTML=`<div class="surface-detail-head"><div><span class="eyebrow">${esc(n.type.toUpperCase())}</span><h2>${esc(n.label)}</h2></div></div><p class="muted">${family?'Agrupación heurística: sirve para reducir el mapa, no afirma que todos los hosts compartan backend.':'Nodo contextual. Selecciona un hostname para revisar evidencia completa.'}</p>${n.meta?.count?`<div class="surface-big-number">${esc(n.meta.count)} <small>hosts relacionados</small></div>`:''}${family?'<button class="button full" type="button" data-enter-family>Investigar esta rama</button>':''}`;
    detail.querySelector('[data-enter-family]')?.addEventListener('click',()=>enterFamily(n.key));
  }

  function renderInventory(){
    const hosts=visibleHosts(); visibleCount.textContent=String(hosts.length);
    grid.innerHTML = hosts.length ? hosts.map(h=>`<article class="surface-host-card" data-host-card="${esc(h.hostname)}"><div class="surface-host-card-head"><div><span class="surface-host-dot ${codeClass(h.status_code)}"></span><b>${esc(h.hostname)}</b><small>${esc(h.title||'')}</small></div>${h.status_code?`<span class="surface-status ${codeClass(h.status_code)}">${esc(h.status_code)}</span>`:'<span class="surface-status unknown">?</span>'}</div><div class="surface-card-meta"><span class="env-pill env-${envClass(h.environment)}">${esc(h.environment||'UNKNOWN')}</span><span>${esc(h.family||'—')}</span>${h.webserver?`<span>${esc(h.webserver)}</span>`:''}</div><div class="surface-chips compact">${tags(h.technologies,'technology')}</div><div class="surface-card-rel"><span>${(h.providers||[]).map(esc).join(' · ')||'Proveedor no identificado'}</span><span>${(h.sources||[]).map(esc).join(' + ')}</span></div></article>`).join('') : '<div class="panel empty-state"><strong>No hay hosts con estos filtros.</strong><span>Quita algún filtro o ejecuta una fase adicional.</span></div>';
    grid.querySelectorAll('[data-host-card]').forEach(card=>card.addEventListener('click',()=>{selectedHost=card.dataset.hostCard;const h=data.hosts.find(x=>x.hostname===selectedHost);renderDetail(h);switchView('map');if(collapseFamilies)collapseFamilies.checked=false;renderGraph();}));
  }

  function renderRuns(){
    if(!runList)return;
    const runs=data.tool_runs||[];
    runList.innerHTML=runs.length?runs.map(r=>{
      let cmd=[];try{cmd=JSON.parse(r.command_json||'[]')}catch(_){cmd=[]}
      return `<article class="surface-run-card"><div class="surface-run-card-top"><div><span class="eyebrow">${esc((r.phase||'').toUpperCase())} · ${esc(r.tool)}</span><b>${esc(r.status)}</b></div><span>${esc(r.record_count||0)} líneas</span></div><code>${esc(cmd.join(' '))}</code><div class="surface-run-meta"><span>${esc(r.started_at||'')}</span>${r.return_code!==null&&r.return_code!==undefined?`<span>rc=${esc(r.return_code)}</span>`:''}${r.error?`<span class="error">${esc(r.error)}</span>`:''}</div></article>`;
    }).join(''):'<div class="panel empty-state"><strong>Aún no hay ejecuciones desde Superficie.</strong><span>Ejecuta una fase y Negro guardará el comando y su resultado.</span></div>';
  }

  function refresh(){ renderGraph(); renderInventory(); renderRuns(); }
  function switchView(name){viewBtns.forEach(b=>b.classList.toggle('active',b.dataset.surfaceView===name));viewPanels.forEach(p=>p.hidden=p.dataset.viewPanel!==name);if(name==='map')renderGraph();else if(name==='inventory')renderInventory();else renderRuns();}
  function fit(){const scale=Math.max(.16,Math.min(1,700/Math.max(700,sceneExtent.height)));view={x:18,y:18,k:scale};renderGraph();}
  function resetDrill(){
    const fam=filterEl('family'); if(fam)fam.value='';
    if(search)search.value='';
    if(collapseFamilies)collapseFamilies.checked=true;
    selectedHost='';renderDetail(null);refresh();fit();
  }
  function bind(){
    search?.addEventListener('input',refresh);
    filterEls.forEach(el=>el.addEventListener('change',()=>{if(el.dataset.filter==='family'&&el.value&&collapseFamilies)collapseFamilies.checked=false;refresh();}));
    layerEls.forEach(el=>el.addEventListener('change',renderGraph)); collapseFamilies?.addEventListener('change',renderGraph);
    root.querySelector('[data-filter-clear]')?.addEventListener('click',()=>{if(search)search.value='';filterEls.forEach(el=>el.value='');refresh();});
    root.querySelector('[data-drill-reset]')?.addEventListener('click',resetDrill);
    root.querySelector('[data-surface-fit]')?.addEventListener('click',fit);
    root.querySelector('[data-import-toggle]')?.addEventListener('click',()=>{importPanel.hidden=!importPanel.hidden;});
    viewBtns.forEach(b=>b.addEventListener('click',()=>switchView(b.dataset.surfaceView)));
    root.querySelector('[data-copy-visible]')?.addEventListener('click',async()=>{const text=visibleHosts().map(h=>h.hostname).join('\n');try{await navigator.clipboard.writeText(text);}catch(_){}});
    svg.addEventListener('click',()=>{selectedHost='';renderDetail(null);renderGraph();});
    svg.addEventListener('wheel',e=>{e.preventDefault();view.k=Math.max(.45,Math.min(2.1,view.k*(e.deltaY<0?1.08:.92)));renderGraph();},{passive:false});
    svg.addEventListener('pointerdown',e=>{if(e.target.closest('.surface-node'))return;pan={x:e.clientX,y:e.clientY,vx:view.x,vy:view.y};svg.setPointerCapture?.(e.pointerId);});
    svg.addEventListener('pointermove',e=>{if(!pan)return;view.x=pan.vx+(e.clientX-pan.x);view.y=pan.vy+(e.clientY-pan.y);renderGraph();});
    svg.addEventListener('pointerup',()=>{pan=null;});
  }

  fetch(api).then(r=>r.json()).then(payload=>{
    data=payload||data;
    fillSelect('technology',data.filters?.technologies||[]); fillSelect('server',data.filters?.servers||[]); fillSelect('provider',data.filters?.providers||[]);
    fillSelect('environment',data.filters?.environments||[]); fillSelect('status',data.filters?.statuses||[]); fillSelect('family',data.filters?.families||[]); fillSelect('source',data.filters?.sources||[]);
    bind(); refresh(); fit();
  }).catch(err=>{stage.innerHTML=`<div class="callout warning">No pude cargar la superficie: ${esc(err.message||err)}</div>`;});
})();
