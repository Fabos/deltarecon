(() => {
  const root = document.querySelector('[data-graph-root]');
  if (!root) return;
  const svg = root.querySelector('[data-graph-canvas]');
  const detail = root.querySelector('[data-graph-detail]');
  const search = root.querySelector('[data-graph-search]');
  const typeWrap = root.querySelector('[data-graph-types]');
  const empty = root.querySelector('[data-graph-empty]');
  const api = root.dataset.api;
  const base = root.dataset.base;
  const NS = 'http://www.w3.org/2000/svg';
  const typeOrder = ['target','host','resource','operation','request','javascript','observation','lead','finding','source','external'];
  const typeLabel = {target:'Target',host:'Hosts',resource:'Resources',operation:'Métodos',request:'Requests',javascript:'JavaScript',observation:'Observaciones',lead:'Leads',finding:'Findings',source:'Sources',external:'Relacionados'};
  let graph = {nodes:[],edges:[]};
  let visibleNodes = [], visibleEdges = [], selected = null, preset = 'all';
  let activeTypes = new Set();
  let view = {x:0,y:0,k:1};
  let drag = null;

  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const slugState = s => ['finding','interesting','tested','untested'].includes(s) ? s : 'normal';
  const nodeRadius = t => t === 'target' ? 18 : t === 'host' ? 14 : t === 'finding' ? 13 : t === 'resource' ? 11 : 8;

  function load() {
    fetch(api, {headers:{'Accept':'application/json'}}).then(r => { if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); }).then(data => {
      graph = data; buildTypeFilters(); layout(); applyFilters(); fit();
    }).catch(err => { detail.innerHTML = `<div class="graph-detail-empty"><h3>No se pudo cargar el mapa</h3><p>${esc(err.message)}</p></div>`; });
  }

  function buildTypeFilters(){
    const present = new Set(graph.nodes.map(n=>n.type));
    activeTypes = new Set(present);
    typeWrap.innerHTML = '';
    typeOrder.filter(t=>present.has(t)).forEach(t=>{
      const b=document.createElement('button'); b.type='button'; b.className='graph-type active'; b.dataset.type=t; b.textContent=`${typeLabel[t]||t} · ${graph.nodes.filter(n=>n.type===t).length}`;
      b.addEventListener('click',()=>{ activeTypes.has(t)?activeTypes.delete(t):activeTypes.add(t); b.classList.toggle('active',activeTypes.has(t)); applyFilters(); });
      typeWrap.appendChild(b);
    });
  }

  function layout(){
    const width = Math.max(1000, svg.clientWidth || 1200), height = Math.max(680, svg.clientHeight || 760);
    const lanes = {}; typeOrder.forEach((t,i)=>lanes[t]=i);
    const byType = {}; graph.nodes.forEach(n=>(byType[n.type] ||= []).push(n));
    graph.nodes.forEach(n=>{ n.x=width/2; n.y=height/2; n.vx=0; n.vy=0; });
    Object.entries(byType).forEach(([t,nodes])=>{
      const lane = lanes[t] ?? typeOrder.length;
      const angleBase = (lane/typeOrder.length)*Math.PI*2;
      const ring = t==='target'?0:150 + lane*32;
      nodes.forEach((n,i)=>{
        const a=angleBase + (i-Math.floor(nodes.length/2))*0.16;
        n.x=width/2 + Math.cos(a)*ring + (i%3)*24;
        n.y=height/2 + Math.sin(a)*ring + (i%5)*18;
      });
    });
    // Deterministic, bounded force relaxation. Good enough for hundreds of nodes without another framework.
    const map = new Map(graph.nodes.map(n=>[n.id,n]));
    for(let iter=0;iter<70;iter++){
      graph.edges.forEach(e=>{ const a=map.get(e.source),b=map.get(e.target); if(!a||!b)return; const dx=b.x-a.x,dy=b.y-a.y,d=Math.max(24,Math.hypot(dx,dy)),desired=110; const f=(d-desired)*0.008; a.vx+=dx/d*f;a.vy+=dy/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f; });
      for(let i=0;i<graph.nodes.length;i++) for(let j=i+1;j<graph.nodes.length;j++){ const a=graph.nodes[i],b=graph.nodes[j]; const dx=b.x-a.x,dy=b.y-a.y,d2=dx*dx+dy*dy; if(d2>0&&d2<130*130){ const d=Math.sqrt(d2),f=(130-d)*0.002; a.vx-=dx/d*f;a.vy-=dy/d*f;b.vx+=dx/d*f;b.vy+=dy/d*f; }}
      graph.nodes.forEach(n=>{ if(n.type==='target'){n.x=width/2;n.y=height/2;n.vx=n.vy=0;return;} n.vx*=.75;n.vy*=.75;n.x+=n.vx;n.y+=n.vy; });
    }
  }

  function presetMatch(n){
    if(preset==='untested') return n.state==='untested';
    if(preset==='interesting') return n.state==='interesting'||n.state==='finding'||n.type==='lead'||n.type==='finding';
    if(preset==='burp') return n.type==='source' && n.id.includes('burp') || (n.meta && String(n.meta.source||'').includes('burp')) || n.type==='request';
    if(preset==='resources') return ['host','resource','operation','javascript'].includes(n.type);
    return true;
  }

  function applyFilters(){
    const q=(search.value||'').trim().toLowerCase();
    const base = graph.nodes.filter(n=>activeTypes.has(n.type)&&presetMatch(n)&&(!q||n.label.toLowerCase().includes(q)||JSON.stringify(n.meta||{}).toLowerCase().includes(q)));
    const ids=new Set(base.map(n=>n.id));
    // Perspective presets keep one-hop context so the map remains explanatory, not a set of isolated dots.
    if(['burp','interesting'].includes(preset)){
      const seed=new Set(ids);
      graph.edges.forEach(e=>{ if(seed.has(e.source)) ids.add(e.target); if(seed.has(e.target)) ids.add(e.source); });
    }
    visibleNodes=graph.nodes.filter(n=>ids.has(n.id)&&activeTypes.has(n.type));
    visibleEdges=graph.edges.filter(e=>ids.has(e.source)&&ids.has(e.target));
    empty.hidden=visibleNodes.length>0;
    render();
  }

  function render(){
    svg.innerHTML='';
    const g=document.createElementNS(NS,'g'); g.setAttribute('class','graph-scene'); g.setAttribute('transform',`translate(${view.x} ${view.y}) scale(${view.k})`); svg.appendChild(g);
    const nodeMap=new Map(visibleNodes.map(n=>[n.id,n]));
    visibleEdges.forEach(e=>{ const a=nodeMap.get(e.source),b=nodeMap.get(e.target); if(!a||!b)return; const path=document.createElementNS(NS,'path'); const mx=(a.x+b.x)/2, bend=((a.y+b.y)%2?1:-1)*18; path.setAttribute('d',`M ${a.x} ${a.y} Q ${mx+bend} ${(a.y+b.y)/2-bend} ${b.x} ${b.y}`); path.setAttribute('class','graph-edge'); path.dataset.id=e.id; path.addEventListener('click',ev=>{ev.stopPropagation();showEdge(e)}); g.appendChild(path); });
    visibleNodes.forEach(n=>{ const ng=document.createElementNS(NS,'g'); ng.setAttribute('class',`graph-node type-${n.type} state-${slugState(n.state)}${selected===n.id?' selected':''}`); ng.setAttribute('transform',`translate(${n.x} ${n.y})`); ng.dataset.id=n.id;
      const circle=document.createElementNS(NS,'circle'); circle.setAttribute('r',nodeRadius(n.type)); ng.appendChild(circle);
      const label=document.createElementNS(NS,'text'); label.setAttribute('x',nodeRadius(n.type)+7); label.setAttribute('y','4'); label.textContent=n.label.length>42?n.label.slice(0,39)+'…':n.label; ng.appendChild(label);
      ng.addEventListener('click',ev=>{ev.stopPropagation();selected=n.id;showNode(n);render();});
      ng.addEventListener('dblclick',ev=>{ev.stopPropagation();focusNeighborhood(n.id,1)});
      g.appendChild(ng);
    });
    svg.onclick=()=>{selected=null;detail.innerHTML='<div class="graph-detail-empty"><div class="graph-detail-icon">⌁</div><h3>Selecciona un nodo</h3><p>Verás procedencia, estado, relaciones y accesos directos a la evidencia real.</p></div>';render();};
  }

  function relationsFor(id){ return graph.edges.filter(e=>e.source===id||e.target===id); }
  function showNode(n){
    const rels=relationsFor(n.id); const meta=n.meta||{};
    const metaRows=Object.entries(meta).filter(([,v])=>v!==null&&v!==''&&typeof v!=='object').slice(0,12).map(([k,v])=>`<div><span>${esc(k.replaceAll('_',' '))}</span><b>${esc(v)}</b></div>`).join('');
    const relationRows=rels.slice(0,18).map(e=>{ const other=graph.nodes.find(x=>x.id===(e.source===n.id?e.target:e.source)); return `<button type="button" class="graph-relation" data-focus="${esc(other?.id||'')}"><span>${esc(e.relation)}</span><b>${esc(other?.label||'')}</b></button>`; }).join('');
    detail.innerHTML=`<div class="graph-detail-head"><span class="graph-node-kind">${esc(typeLabel[n.type]||n.type)}</span><h2>${esc(n.label)}</h2><span class="state-chip state-${slugState(n.state)}">${esc(n.state)}</span></div><div class="graph-detail-meta">${metaRows||'<small>Sin metadata adicional.</small>'}</div>${n.href?`<a class="btn" href="${base}/${esc(n.href)}">Abrir detalle →</a>`:''}<div class="graph-detail-section"><h3>Relaciones · ${rels.length}</h3>${relationRows||'<small>Sin relaciones visibles.</small>'}</div>`;
    detail.querySelectorAll('[data-focus]').forEach(b=>b.addEventListener('click',()=>{ const x=graph.nodes.find(n=>n.id===b.dataset.focus); if(x){selected=x.id;showNode(x);render();} }));
  }
  function showEdge(e){ const a=graph.nodes.find(n=>n.id===e.source),b=graph.nodes.find(n=>n.id===e.target),m=e.meta||{}; detail.innerHTML=`<div class="graph-detail-head"><span class="graph-node-kind">RELATIONSHIP</span><h2>${esc(e.relation)}</h2></div><div class="graph-edge-explain"><b>${esc(a?.label||e.source)}</b><span>— ${esc(e.relation)} →</span><b>${esc(b?.label||e.target)}</b></div><div class="graph-detail-meta"><div><span>source</span><b>${esc(m.source||'—')}</b></div></div>${m.evidence?`<div class="graph-detail-section"><h3>Evidence</h3><pre>${esc(JSON.stringify(m.evidence,null,2))}</pre></div>`:''}`; }

  function focusNeighborhood(id,hops=1){ const ids=new Set([id]); for(let h=0;h<hops;h++){ const frontier=new Set(ids); graph.edges.forEach(e=>{if(frontier.has(e.source))ids.add(e.target);if(frontier.has(e.target))ids.add(e.source);}); } visibleNodes=graph.nodes.filter(n=>ids.has(n.id)); visibleEdges=graph.edges.filter(e=>ids.has(e.source)&&ids.has(e.target)); render(); fit(); }
  function fit(){ if(!visibleNodes.length)return; const box=svg.getBoundingClientRect(); const minX=Math.min(...visibleNodes.map(n=>n.x))-80,maxX=Math.max(...visibleNodes.map(n=>n.x))+180,minY=Math.min(...visibleNodes.map(n=>n.y))-80,maxY=Math.max(...visibleNodes.map(n=>n.y))+80; const w=maxX-minX,h=maxY-minY; const k=Math.max(.22,Math.min(1.2,Math.min(box.width/w,box.height/h))); view.k=k;view.x=box.width/2-(minX+w/2)*k;view.y=box.height/2-(minY+h/2)*k;render(); }

  svg.addEventListener('wheel',e=>{e.preventDefault(); const rect=svg.getBoundingClientRect(),mx=e.clientX-rect.left,my=e.clientY-rect.top,old=view.k,next=Math.max(.18,Math.min(2.4,old*(e.deltaY<0?1.1:.9))); view.x=mx-(mx-view.x)*(next/old);view.y=my-(my-view.y)*(next/old);view.k=next;render();},{passive:false});
  svg.addEventListener('pointerdown',e=>{drag={x:e.clientX,y:e.clientY,vx:view.x,vy:view.y};svg.setPointerCapture(e.pointerId)}); svg.addEventListener('pointermove',e=>{if(!drag)return;view.x=drag.vx+e.clientX-drag.x;view.y=drag.vy+e.clientY-drag.y;render()}); svg.addEventListener('pointerup',()=>drag=null); svg.addEventListener('pointercancel',()=>drag=null);
  search.addEventListener('input',applyFilters);
  root.querySelectorAll('[data-graph-preset]').forEach(b=>b.addEventListener('click',()=>{root.querySelectorAll('[data-graph-preset]').forEach(x=>x.classList.remove('active'));b.classList.add('active');preset=b.dataset.graphPreset;applyFilters();fit();}));
  root.querySelector('[data-graph-fit]').addEventListener('click',fit);
  root.querySelector('[data-graph-all]').addEventListener('click',()=>{preset='all';search.value='';activeTypes=new Set(graph.nodes.map(n=>n.type));buildTypeFilters();applyFilters();fit();});
  root.querySelector('[data-graph-neighborhood]').addEventListener('click',()=>selected&&focusNeighborhood(selected,1));
  load();
})();
