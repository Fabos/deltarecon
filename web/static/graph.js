(() => {
  const root = document.querySelector('[data-graph-root]');
  if (!root) return;

  const svg = root.querySelector('[data-graph-canvas]');
  const detail = root.querySelector('[data-graph-detail]');
  const search = root.querySelector('[data-graph-search]');
  const typeWrap = root.querySelector('[data-graph-types]');
  const empty = root.querySelector('[data-graph-empty]');
  const statusEl = root.querySelector('[data-graph-layout-status]');
  const api = root.dataset.api;
  const base = root.dataset.base;
  const targetKey = root.dataset.target || 'target';
  const csrf = root.dataset.csrf || '';
  const aiEstimateUrl = root.dataset.aiEstimate || '';
  const aiRunUrl = root.dataset.aiRun || '';
  const NS = 'http://www.w3.org/2000/svg';

  const typeOrder = ['source','target','host','javascript','resource','operation','cluster','request','observation','lead','finding','external'];
  const typeLabel = {
    source:'Fuentes', target:'Target', host:'Hosts', javascript:'JavaScript', resource:'Recursos',
    operation:'Métodos', cluster:'Grupos', request:'Solicitudes', observation:'Observaciones',
    lead:'Hipótesis', finding:'Hallazgos', external:'Relacionados'
  };
  const stateLabel = {normal:'Normal',untested:'Pendiente',testing:'En prueba',interesting:'Interesante',finding:'Hallazgo',tested:'Revisado'};
  const coverageLabel = {untested:'Pendiente',testing:'En prueba',tested:'Revisado'};
  const signalLabel = {normal:'Normal',interesting:'Interesante',finding:'Hallazgo'};
  const metaKeyLabel = {id:'ID',type:'Tipo',status:'Estado',confidence:'Confianza',priority:'Prioridad',source:'Fuente',why:'Por qué',next_test:'Siguiente prueba',method:'Método',url:'URL',path:'Ruta',host:'Host',hostname:'Host',seen_count:'Veces visto',authenticated:'Con sesión',authenticated_observed:'Sesión observada',content_type:'Content-Type',request_content_type:'Content-Type solicitud',response_content_type:'Content-Type respuesta',first_seen:'Primera vez',first_seen_at:'Primera vez',last_seen:'Última vez',last_seen_at:'Última vez',finding_count:'Hallazgos',coverage:'Cobertura',signal:'Señal',count:'Cantidad'};
  const relationLabel = {contains:'contiene',supports:'soporta',observed_in:'observado en',discovered:'descubrió',discovered_by:'descubierto por',tested_by:'probado con',produced_lead:'produjo hipótesis',supports_hypothesis:'soporta hipótesis',contradicts_hypothesis:'contradice hipótesis',evidence_for:'evidencia de',affected_by:'afectado por',related_to:'relacionado con',source:'fuente',calls:'llama',accepts:'acepta',produced:'produjo',returned_by:'devuelto por',authenticated_as:'autenticado como',belongs_to:'pertenece a'};
  const valueLabel = v => ({candidate:'Candidata',testing:'En prueba',interesting:'Interesante',negative:'Negativa',postponed:'Para después',confirmed:'Confirmada',discarded:'Descartada',pending:'Pendiente',in_progress:'En revisión',reviewed:'Revisado',unknown:'Sin clasificar',lead:'Interesante',finding:'Hallazgo',high:'Alta',medium:'Media',low:'Baja',none:'Sin prioridad'}[String(v)] || v);

  let graph = {nodes:[],edges:[]};
  let sceneNodes = [], sceneEdges = [], visibleNodes = [], visibleEdges = [];
  let selected = null;
  let preset = 'surface';
  let activeTypes = new Set();
  let expandedClusters = new Set();
  let view = {x:0,y:0,k:1};
  let panDrag = null;
  let nodeDrag = null;
  let suppressClick = false;

  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const slugState = s => ['finding','interesting','tested','testing','untested'].includes(s) ? s : 'normal';
  const nodeRadius = t => t === 'target' ? 13 : t === 'host' ? 12 : t === 'resource' ? 11 : t === 'finding' ? 11 : t === 'cluster' ? 10 : 7;
  const labelLimit = t => ['resource','operation'].includes(t) ? 48 : 34;
  const edgeId = (a,b,r) => `virtual:${a}:${r}:${b}`;
  const byId = () => new Map(graph.nodes.map(n => [n.id,n]));
  const sceneById = () => new Map(sceneNodes.map(n => [n.id,n]));
  const edgesOf = id => graph.edges.filter(e => e.source === id || e.target === id);
  const opposite = (e,id) => e.source === id ? e.target : e.source;

  function layoutStorageKey(){ return `negro.graph.layout.v2:${targetKey}:${preset}`; }
  function readSavedLayout(){
    try { return JSON.parse(localStorage.getItem(layoutStorageKey()) || '{}') || {}; }
    catch (_) { return {}; }
  }
  function writeSavedLayout(){
    const payload = {};
    sceneNodes.forEach(n => {
      if (n.manual) payload[n.id] = {x:Math.round(n.x), y:Math.round(n.y)};
    });
    try { localStorage.setItem(layoutStorageKey(), JSON.stringify(payload)); }
    catch (_) {}
    setLayoutStatus(Object.keys(payload).length ? 'Disposición personalizada guardada' : 'Layout automático');
  }
  function clearSavedLayout(){
    try { localStorage.removeItem(layoutStorageKey()); } catch (_) {}
    sceneNodes.forEach(n => { n.manual = false; });
    setLayoutStatus('Layout automático');
  }
  function setLayoutStatus(text){ if (statusEl) statusEl.textContent = text; }

  function load(){
    return fetch(api, {headers:{'Accept':'application/json'}})
      .then(r => { if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(data => {
        graph = data;
        buildScene();
        buildTypeFilters();
        applyFilters({fitAfter:true});
      })
      .catch(err => {
        detail.innerHTML = `<div class="graph-detail-empty"><h3>No se pudo cargar el mapa</h3><p>${esc(err.message)}</p></div>`;
      });
  }

  function cloneNode(n){ return {...n, meta:{...(n.meta||{})}, x:0, y:0, manual:false}; }

  function findParent(id, preferredTypes=[]){
    const map = byId();
    const rels = edgesOf(id);
    for (const t of preferredTypes) {
      const hit = rels.map(e => map.get(opposite(e,id))).find(n => n && n.type === t);
      if (hit) return hit;
    }
    return rels.map(e => map.get(opposite(e,id))).find(Boolean) || null;
  }

  function makeCluster(parentId, kind, children, relation='contains'){
    const parent = graph.nodes.find(n => n.id === parentId);
    const id = `cluster:${preset}:${kind}:${parentId}`;
    const labelMap = {requests:'Solicitudes Burp', observations:'Observaciones', javascript:'JavaScript'};
    const interesting = children.filter(n => ['interesting','finding'].includes(slugState(n.state))).length;
    const node = {
      id, type:'cluster', label:`${labelMap[kind] || kind} · ${children.length}`, state: interesting ? 'interesting' : 'normal',
      virtual:true, clusterKind:kind, childIds:children.map(n=>n.id), parentId,
      meta:{count:children.length, interesting, parent:parent?.label || parentId}
    };
    const edge = {id:edgeId(parentId,id,relation), source:parentId, target:id, relation, meta:{source:'presentation_cluster'}};
    return {node,edge};
  }

  function buildScene(){
    const rawMap = byId();
    const nodes = [];
    const edges = [];
    const include = new Set();

    const addNode = n => { if (n && !include.has(n.id)) { include.add(n.id); nodes.push(cloneNode(n)); } };
    const addEdge = e => { if (e && !edges.some(x=>x.id===e.id)) edges.push({...e}); };
    const addWithAncestors = (id, depth=4) => {
      const start = rawMap.get(id); if(!start) return;
      addNode(start);
      let frontier = new Set([id]);
      const seen = new Set(frontier);
      for(let hop=0; hop<depth; hop++){
        const next = new Set();
        graph.edges.forEach(e => {
          if(frontier.has(e.target)){
            const n = rawMap.get(e.source);
            if(n && ['target','host','resource','operation','source','javascript'].includes(n.type)){
              addNode(n); addEdge(e); if(!seen.has(n.id)){seen.add(n.id);next.add(n.id);}
            }
          }
          if(frontier.has(e.source) && ['contains','supports','discovered','observed'].includes(e.relation)){
            const n = rawMap.get(e.target);
            if(n && ['host','resource','operation'].includes(n.type)){
              addNode(n); addEdge(e); if(!seen.has(n.id)){seen.add(n.id);next.add(n.id);}
            }
          }
        });
        frontier = next;
      }
    };

    if (preset === 'surface' || preset === 'resources') {
      graph.nodes.filter(n => ['target','host','resource','operation'].includes(n.type)).forEach(addNode);
      graph.edges.filter(e => include.has(e.source) && include.has(e.target) && ['contains','supports'].includes(e.relation)).forEach(addEdge);

      // JavaScript matters, but it should not flood the initial map. Group it per host.
      graph.nodes.filter(n => n.type === 'host').forEach(host => {
        const js = graph.edges
          .filter(e => e.source === host.id)
          .map(e => rawMap.get(e.target))
          .filter(n => n?.type === 'javascript');
        if (!js.length) return;
        addNode(host);
        if (js.length === 1) {
          addNode(js[0]);
          const e = graph.edges.find(x => x.source===host.id && x.target===js[0].id); if(e) addEdge(e);
        } else {
          const c = makeCluster(host.id,'javascript',js,'contains'); nodes.push(c.node); include.add(c.node.id); edges.push(c.edge);
          if(expandedClusters.has(c.node.id)) js.forEach(child => { addNode(child); edges.push({id:edgeId(c.node.id,child.id,'contains'),source:c.node.id,target:child.id,relation:'contains',meta:{source:'expanded_cluster'}}); });
        }
      });
    } else if (preset === 'burp') {
      const burpRequests = graph.nodes.filter(n => n.type==='request' && /burp/i.test(String(n.meta?.source||'')));
      const opIds = new Set();
      burpRequests.forEach(r => edgesOf(r.id).forEach(e => { const n=rawMap.get(opposite(e,r.id)); if(n?.type==='operation') opIds.add(n.id); }));
      opIds.forEach(id => addWithAncestors(id,3));
      graph.nodes.filter(n=>n.type==='source' && /burp/i.test(n.label)).forEach(addNode);
      graph.edges.filter(e=>include.has(e.source)&&include.has(e.target)).forEach(addEdge);
      opIds.forEach(opId => {
        const requests = burpRequests.filter(r => edgesOf(r.id).some(e => opposite(e,r.id)===opId));
        if(!requests.length) return;
        const c=makeCluster(opId,'requests',requests,'observed_in'); nodes.push(c.node); include.add(c.node.id); edges.push(c.edge);
        if(expandedClusters.has(c.node.id)) requests.forEach(child=>{addNode(child);edges.push({id:edgeId(c.node.id,child.id,'observed_in'),source:c.node.id,target:child.id,relation:'observed_in',meta:{source:'expanded_cluster'}});});
      });
    } else if (preset === 'untested') {
      graph.nodes.filter(n => n.state === 'untested' && ['resource','operation','javascript'].includes(n.type)).forEach(n => addWithAncestors(n.id,4));
      graph.edges.filter(e => include.has(e.source)&&include.has(e.target)).forEach(addEdge);
    } else if (preset === 'interesting' || preset === 'attack') {
      const seeds = graph.nodes.filter(n => n.type!=='observation' && (n.type==='finding' || (n.type==='lead' && !['negative','discarded','postponed'].includes(String(n.meta?.status||''))) || n.state==='finding' || n.state==='interesting'));
      seeds.forEach(n => addWithAncestors(n.id,5));
      // An interesting observation seeds the path through its parent without forcing every raw observation onto the canvas.
      graph.nodes.filter(n=>n.type==='observation' && ['interesting','finding'].includes(slugState(n.state))).forEach(obs=>{
        const parentEdge=graph.edges.find(e=>e.target===obs.id);
        if(parentEdge) addWithAncestors(parentEdge.source,5);
      });
      // Include test observations connected to already-visible entities; group noisy repetitions.
      const obsByParent = new Map();
      graph.nodes.filter(n=>n.type==='observation').forEach(obs=>{
        const rel = graph.edges.find(e=>e.target===obs.id && include.has(e.source));
        if(!rel) return;
        const key=rel.source; const arr=obsByParent.get(key)||[];arr.push(obs);obsByParent.set(key,arr);
      });
      obsByParent.forEach((obs,parentId)=>{
        const strong=obs.filter(o=>['interesting','finding'].includes(slugState(o.state)));
        const chosen = preset==='attack' && strong.length ? strong : obs;
        if(chosen.length===1){ addNode(chosen[0]); const e=graph.edges.find(x=>x.target===chosen[0].id&&x.source===parentId); if(e)addEdge(e); }
        else if(chosen.length>1){ const c=makeCluster(parentId,'observations',chosen,'tested_by');nodes.push(c.node);include.add(c.node.id);edges.push(c.edge);if(expandedClusters.has(c.node.id))chosen.forEach(child=>{addNode(child);edges.push({id:edgeId(c.node.id,child.id,'tested_by'),source:c.node.id,target:child.id,relation:'tested_by',meta:{source:'expanded_cluster'}});}); }
      });
      graph.edges.filter(e => include.has(e.source)&&include.has(e.target)).forEach(addEdge);
    } else { // all
      graph.nodes.filter(n => !['request','observation','javascript'].includes(n.type)).forEach(addNode);
      graph.edges.filter(e => include.has(e.source)&&include.has(e.target)).forEach(addEdge);
      // JavaScript stays available without turning the default overview into a wall of bundles.
      graph.nodes.filter(n=>n.type==='host').forEach(host=>{
        const js=graph.edges.filter(e=>e.source===host.id).map(e=>rawMap.get(e.target)).filter(n=>n?.type==='javascript');
        if(!js.length)return;
        const c=makeCluster(host.id,'javascript',js,'contains');nodes.push(c.node);include.add(c.node.id);edges.push(c.edge);
        if(expandedClusters.has(c.node.id))js.forEach(child=>{addNode(child);edges.push({id:edgeId(c.node.id,child.id,'contains'),source:c.node.id,target:child.id,relation:'contains',meta:{source:'expanded_cluster'}});});
      });
      // Requests and observations are grouped until the investigator explicitly expands them.
      graph.nodes.filter(n=>n.type==='operation').forEach(op=>{
        const reqs=graph.nodes.filter(r=>r.type==='request'&&edgesOf(r.id).some(e=>opposite(e,r.id)===op.id));
        if(reqs.length){const c=makeCluster(op.id,'requests',reqs,'observed_in');nodes.push(c.node);include.add(c.node.id);edges.push(c.edge);if(expandedClusters.has(c.node.id))reqs.forEach(child=>{addNode(child);edges.push({id:edgeId(c.node.id,child.id,'observed_in'),source:c.node.id,target:child.id,relation:'observed_in',meta:{source:'expanded_cluster'}});});}
      });
      const parentObs=new Map();
      graph.nodes.filter(n=>n.type==='observation').forEach(obs=>{const e=graph.edges.find(x=>x.target===obs.id);if(!e)return;const arr=parentObs.get(e.source)||[];arr.push(obs);parentObs.set(e.source,arr);});
      parentObs.forEach((obs,p)=>{if(!include.has(p))return;const c=makeCluster(p,'observations',obs,'tested_by');nodes.push(c.node);include.add(c.node.id);edges.push(c.edge);if(expandedClusters.has(c.node.id))obs.forEach(child=>{addNode(child);edges.push({id:edgeId(c.node.id,child.id,'tested_by'),source:c.node.id,target:child.id,relation:'tested_by',meta:{source:'expanded_cluster'}});});});
    }

    sceneNodes = nodes;
    sceneEdges = edges.filter(e => include.has(e.source) && include.has(e.target));
    autoLayout();
  }

  function laneFor(n){
    if (preset === 'surface' || preset === 'resources') {
      return {target:0,host:1,javascript:2,resource:2,operation:3,cluster:4}[n.type] ?? 4;
    }
    if (preset === 'burp') return {source:0,target:0,host:1,resource:2,operation:3,cluster:4,request:5}[n.type] ?? 5;
    if (preset === 'interesting' || preset === 'attack') return {source:0,target:0,host:1,javascript:2,resource:2,operation:3,cluster:4,observation:4,lead:5,finding:5,external:5}[n.type] ?? 5;
    return {source:0,target:0,host:1,javascript:2,resource:2,operation:3,cluster:4,request:5,observation:5,lead:6,finding:6,external:6}[n.type] ?? 6;
  }

  function autoLayout(){
    const width=Math.max(980,svg.clientWidth||1100), height=Math.max(620,svg.clientHeight||680);
    const lanes = new Map();
    sceneNodes.forEach(n=>{const lane=laneFor(n);const arr=lanes.get(lane)||[];arr.push(n);lanes.set(lane,arr);});
    const maxLane = Math.max(1,...lanes.keys());
    const left=78,right=Math.max(760,width-110), laneGap=(right-left)/Math.max(1,maxLane);
    const sceneMap = sceneById();

    const parentKey = n => {
      const rels=sceneEdges.filter(e=>e.target===n.id||e.source===n.id);
      const parents=rels.map(e=>sceneMap.get(e.target===n.id?e.source:e.target)).filter(Boolean).filter(x=>laneFor(x)<laneFor(n));
      return parents.map(x=>x.label).sort().join('|')+'|'+n.label;
    };

    lanes.forEach((arr,lane)=>{
      arr.sort((a,b)=>parentKey(a).localeCompare(parentKey(b)));
      const gap=Math.max(54,Math.min(88,(height-100)/Math.max(1,arr.length)));
      const total=(arr.length-1)*gap;
      const start=Math.max(55,(height-total)/2);
      arr.forEach((n,i)=>{n.x=left+lane*laneGap;n.y=start+i*gap;n.manual=false;});
    });

    // Barycentric passes reduce edge crossings while keeping semantic lanes intact.
    for(let pass=0; pass<4; pass++){
      [...lanes.entries()].sort((a,b)=>a[0]-b[0]).forEach(([lane,arr])=>{
        if(lane===0)return;
        arr.forEach(n=>{
          const prev=sceneEdges.filter(e=>e.target===n.id||e.source===n.id)
            .map(e=>sceneMap.get(e.target===n.id?e.source:e.target)).filter(x=>x&&laneFor(x)<lane);
          if(prev.length)n.y=n.y*.45+(prev.reduce((s,x)=>s+x.y,0)/prev.length)*.55;
        });
        arr.sort((a,b)=>a.y-b.y);
        let y=45; arr.forEach(n=>{n.y=Math.max(n.y,y);y=n.y+58;});
      });
    }

    const saved=readSavedLayout();
    sceneNodes.forEach(n=>{ if(saved[n.id] && Number.isFinite(saved[n.id].x) && Number.isFinite(saved[n.id].y)){ n.x=saved[n.id].x;n.y=saved[n.id].y;n.manual=true; } });
    setLayoutStatus(Object.keys(saved).length ? 'Disposición personalizada guardada' : 'Layout automático');
  }

  function buildTypeFilters(){
    const present=new Set(sceneNodes.map(n=>n.type).filter(t=>t!=='cluster'));
    activeTypes=new Set(present);
    typeWrap.innerHTML='';
    typeOrder.filter(t=>present.has(t)).forEach(t=>{
      const b=document.createElement('button');b.type='button';b.className='graph-type active';b.dataset.type=t;
      b.textContent=`${typeLabel[t]||t} · ${sceneNodes.filter(n=>n.type===t).length}`;
      b.addEventListener('click',()=>{activeTypes.has(t)?activeTypes.delete(t):activeTypes.add(t);b.classList.toggle('active',activeTypes.has(t));applyFilters();});
      typeWrap.appendChild(b);
    });
  }

  function applyFilters({fitAfter=false}={}){
    const q=(search.value||'').trim().toLowerCase();
    const baseNodes=sceneNodes.filter(n => (n.type==='cluster'||activeTypes.has(n.type)) && (!q || n.label.toLowerCase().includes(q) || JSON.stringify(n.meta||{}).toLowerCase().includes(q)));
    const ids=new Set(baseNodes.map(n=>n.id));
    if(q){
      const seed=new Set(ids);
      sceneEdges.forEach(e=>{if(seed.has(e.source))ids.add(e.target);if(seed.has(e.target))ids.add(e.source);});
    }
    visibleNodes=sceneNodes.filter(n=>ids.has(n.id) && (n.type==='cluster'||activeTypes.has(n.type)));
    const visIds=new Set(visibleNodes.map(n=>n.id));
    visibleEdges=sceneEdges.filter(e=>visIds.has(e.source)&&visIds.has(e.target));
    empty.hidden=visibleNodes.length>0;
    render();
    if(fitAfter) fit();
  }

  function relationIsHighlight(e){
    if(preset!=='attack' && preset!=='interesting')return false;
    const m=sceneById(),a=m.get(e.source),b=m.get(e.target);
    return [a,b].some(n=>n && (n.state==='interesting'||n.state==='finding'||n.type==='lead'||n.type==='finding'||n.type==='observation'));
  }

  function labelVisible(n){
    if(selected===n.id)return true;
    if(['target','host','resource','operation','finding','lead','cluster'].includes(n.type))return true;
    return view.k>=1.15;
  }

  function render(){
    svg.innerHTML='';
    const g=document.createElementNS(NS,'g');g.setAttribute('class','graph-scene');g.setAttribute('transform',`translate(${view.x} ${view.y}) scale(${view.k})`);svg.appendChild(g);
    const nodeMap=new Map(visibleNodes.map(n=>[n.id,n]));

    visibleEdges.forEach(e=>{
      const a=nodeMap.get(e.source),b=nodeMap.get(e.target);if(!a||!b)return;
      const path=document.createElementNS(NS,'path');
      const dx=Math.max(45,Math.abs(b.x-a.x)*.48), c1x=a.x+Math.sign(b.x-a.x||1)*dx, c2x=b.x-Math.sign(b.x-a.x||1)*dx;
      path.setAttribute('d',`M ${a.x} ${a.y} C ${c1x} ${a.y}, ${c2x} ${b.y}, ${b.x} ${b.y}`);
      path.setAttribute('class',`graph-edge${relationIsHighlight(e)?' graph-edge-highlight':''}`);path.dataset.id=e.id;
      path.addEventListener('click',ev=>{ev.stopPropagation();showEdge(e)});g.appendChild(path);
    });

    visibleNodes.forEach(n=>{
      const ng=document.createElementNS(NS,'g');
      ng.setAttribute('class',`graph-node type-${n.type} state-${slugState(n.state)}${selected===n.id?' selected':''}${n.manual?' manual':''}`);
      ng.setAttribute('transform',`translate(${n.x} ${n.y})`);ng.dataset.id=n.id;
      const circle=document.createElementNS(NS,'circle');circle.setAttribute('r',nodeRadius(n.type));ng.appendChild(circle);
      if (n.meta?.coverage && ['host','resource'].includes(n.type)) {
        const dot=document.createElementNS(NS,'circle');
        dot.setAttribute('r','3.2'); dot.setAttribute('cx',String(-nodeRadius(n.type)+1)); dot.setAttribute('cy',String(-nodeRadius(n.type)+1));
        dot.setAttribute('class',`graph-coverage-dot coverage-${esc(n.meta.coverage)}`); ng.appendChild(dot);
      }
      if(n.type==='cluster'){
        const inner=document.createElementNS(NS,'circle');inner.setAttribute('r',Math.max(3,nodeRadius(n.type)-4));inner.setAttribute('class','graph-cluster-inner');ng.appendChild(inner);
      }
      if(labelVisible(n)){
        const label=document.createElementNS(NS,'text');label.setAttribute('x',nodeRadius(n.type)+7);label.setAttribute('y','4');label.setAttribute('class','graph-node-label');
        const limit=labelLimit(n.type);label.textContent=n.label.length>limit?n.label.slice(0,limit-1)+'…':n.label;ng.appendChild(label);
      }
      ng.setAttribute('tabindex','0'); ng.setAttribute('role','button'); ng.setAttribute('aria-label',n.label);
      ng.addEventListener('pointerdown',ev=>startNodeDrag(ev,n));
      ng.addEventListener('click',ev=>{ev.stopPropagation();if(suppressClick){suppressClick=false;return;}selected=n.id;showNode(n);render();});
      ng.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();selected=n.id;showNode(n);render();}});
      ng.addEventListener('dblclick',ev=>{ev.stopPropagation();if(n.type==='cluster')toggleCluster(n);else focusNeighborhood(n.id,1);});
      g.appendChild(ng);
    });

    svg.onclick=()=>{if(suppressClick){suppressClick=false;return;}selected=null;detail.innerHTML=emptyDetail();render();};
  }

  function emptyDetail(){return '<div class="graph-detail-empty"><div class="graph-detail-icon">⌁</div><h3>Selecciona un nodo</h3><p>Abre un endpoint, revisa su cobertura o aísla su vecindario para entender el camino.</p></div>';}

  function summarizeNode(n){
    const rawMap=byId();
    const summary={methods:0,requests:0,tests:0,interesting:0,sources:new Set()};
    const ids=new Set([n.id]);
    if(n.type==='resource'){
      graph.edges.filter(e=>e.source===n.id).forEach(e=>{const x=rawMap.get(e.target);if(x?.type==='operation')ids.add(x.id);});
    }
    ids.forEach(id=>{
      graph.edges.forEach(e=>{
        if(e.source!==id&&e.target!==id)return;
        const x=rawMap.get(opposite(e,id));if(!x)return;
        if(x.type==='operation')summary.methods++;
        if(x.type==='request')summary.requests+=Number(x.meta?.seen_count||1);
        if(x.type==='observation'){summary.tests++;if(['interesting','finding'].includes(slugState(x.state)))summary.interesting++;}
        if(x.type==='source')summary.sources.add(x.label);
      });
    });
    return summary;
  }

  function showNode(n){
    const rels=(n.virtual?sceneEdges:graph.edges).filter(e=>e.source===n.id||e.target===n.id);
    const meta=n.meta||{};
    const metaRows=Object.entries(meta).filter(([k,v])=>!['count','interesting'].includes(k)&&v!==null&&v!==''&&typeof v!=='object').slice(0,10).map(([k,v])=>`<div><span>${esc(metaKeyLabel[k]||k.replaceAll('_',' '))}</span><b>${esc(valueLabel(v))}</b></div>`).join('');
    const sourceGraph=n.virtual?sceneNodes:graph.nodes;
    const relationRows=rels.slice(0,16).map(e=>{const other=sourceGraph.find(x=>x.id===(e.source===n.id?e.target:e.source))||graph.nodes.find(x=>x.id===(e.source===n.id?e.target:e.source));return `<button type="button" class="graph-relation" data-focus="${esc(other?.id||'')}"><span>${esc(relationLabel[e.relation]||e.relation)}</span><b>${esc(other?.label||'')}</b></button>`;}).join('');
    const summary=summarizeNode(n);
    const testSummary=meta.test_summary||{};
    const trackedTests=Object.values(testSummary).reduce((a,b)=>a+Number(b||0),0);
    const pendingTests=Number(testSummary.pending||0)+Number(testSummary.testing||0);
    const summaryHtml=['resource','operation'].includes(n.type)?`<div class="graph-coverage"><div><b>${summary.methods||((n.type==='operation')?1:0)}</b><span>Métodos</span></div><div><b>${summary.requests}</b><span>Solicitudes</span></div><div><b>${n.type==='operation'&&trackedTests?trackedTests:summary.tests}</b><span>Pruebas</span></div><div class="${summary.interesting||Number(testSummary.interesting||0)||Number(testSummary.confirmed||0)?'is-interesting':''}"><b>${n.type==='operation'&&trackedTests?pendingTests:summary.interesting}</b><span>${n.type==='operation'&&trackedTests?'Pendientes':'Señales'}</span></div></div>`:'';
    const clusterHtml=n.type==='cluster'?`<div class="graph-detail-section"><h3>${esc(n.label)}</h3><p>${n.meta?.interesting?`Incluye ${n.meta.interesting} señal(es) interesante(s).`: 'Agrupado para mantener el mapa legible.'}</p><button type="button" class="btn-secondary" data-expand-cluster>${expandedClusters.has(n.id)?'Contraer':'Expandir'} elementos</button></div>`:'';
    const statusHtml=(meta.coverage||meta.signal)
      ? `<div class="graph-dual-state">${meta.coverage?`<span class="state-chip coverage-chip coverage-${esc(meta.coverage)}">Cobertura · ${esc(coverageLabel[meta.coverage]||meta.coverage)}</span>`:''}${meta.signal?`<span class="state-chip signal-chip signal-${esc(meta.signal)}">Señal · ${esc(signalLabel[meta.signal]||meta.signal)}</span>`:''}${Number(meta.finding_count||0)>0?`<span class="state-chip signal-chip signal-finding">${esc(meta.finding_count)} hallazgo${Number(meta.finding_count)===1?'':'s'}</span>`:''}</div>`
      : `<span class="state-chip state-${slugState(n.state)}">${esc(stateLabel[slugState(n.state)]||n.state)}</span>`;
    detail.innerHTML=`<div class="graph-detail-head"><span class="graph-node-kind">${esc(typeLabel[n.type]||n.type)}</span><h2>${esc(n.label)}</h2>${statusHtml}</div>${summaryHtml}<div class="graph-detail-actions"><button type="button" class="btn-secondary" data-focus-one>Enfocar 1 salto</button><button type="button" class="btn-secondary" data-focus-two>2 saltos</button>${n.href?`<a class="btn" href="${base}/${esc(n.href)}">Abrir detalle →</a>`:''}<button type="button" class="btn-secondary" data-ai-selected>🧠 Explorar relaciones</button></div><div class="graph-detail-meta">${metaRows||'<small>Sin datos adicionales.</small>'}</div>${clusterHtml}<div class="graph-detail-section"><h3>Relaciones · ${rels.length}</h3>${relationRows||'<small>Sin relaciones visibles.</small>'}</div>`;
    detail.querySelector('[data-focus-one]')?.addEventListener('click',()=>focusNeighborhood(n.id,1));
    detail.querySelector('[data-focus-two]')?.addEventListener('click',()=>focusNeighborhood(n.id,2));
    detail.querySelector('[data-expand-cluster]')?.addEventListener('click',()=>toggleCluster(n));
    detail.querySelector('[data-ai-selected]')?.addEventListener('click',()=>openAiPanel(n.type==='cluster'?(n.parentId||''):n.id,n.type==='cluster'?(n.meta?.parent||n.label):n.label));
    detail.querySelectorAll('[data-focus]').forEach(b=>b.addEventListener('click',()=>{const x=sceneNodes.find(n=>n.id===b.dataset.focus)||graph.nodes.find(n=>n.id===b.dataset.focus);if(x){selected=x.id;showNode(x);render();}}));
  }

  function showEdge(e){
    const map=sceneById(),a=map.get(e.source)||graph.nodes.find(n=>n.id===e.source),b=map.get(e.target)||graph.nodes.find(n=>n.id===e.target),m=e.meta||{};
    const rel=relationLabel[e.relation]||e.relation;
    detail.innerHTML=`<div class="graph-detail-head"><span class="graph-node-kind">RELACIÓN</span><h2>${esc(rel)}</h2></div><div class="graph-edge-explain"><b>${esc(a?.label||e.source)}</b><span>— ${esc(rel)} →</span><b>${esc(b?.label||e.target)}</b></div><div class="graph-detail-meta"><div><span>Fuente</span><b>${esc(m.source||'—')}</b></div></div>${m.evidence?`<div class="graph-detail-section"><h3>Por qué existe</h3><pre>${esc(JSON.stringify(m.evidence,null,2))}</pre></div>`:''}`;
  }

  function toggleCluster(n){
    if(!n || n.type!=='cluster')return;
    expandedClusters.has(n.id)?expandedClusters.delete(n.id):expandedClusters.add(n.id);
    const keepSelected=n.id;buildScene();buildTypeFilters();applyFilters();selected=keepSelected;const x=sceneNodes.find(a=>a.id===keepSelected);if(x)showNode(x);fit();
  }

  function focusNeighborhood(id,hops=1){
    const ids=new Set([id]);let frontier=new Set([id]);
    for(let h=0;h<hops;h++){
      const next=new Set();sceneEdges.forEach(e=>{if(frontier.has(e.source)&&!ids.has(e.target)){ids.add(e.target);next.add(e.target);}if(frontier.has(e.target)&&!ids.has(e.source)){ids.add(e.source);next.add(e.source);}});frontier=next;
    }
    visibleNodes=sceneNodes.filter(n=>ids.has(n.id));visibleEdges=sceneEdges.filter(e=>ids.has(e.source)&&ids.has(e.target));render();fit();
  }

  function fit(){
    if(!visibleNodes.length)return;
    const box=svg.getBoundingClientRect();
    const minX=Math.min(...visibleNodes.map(n=>n.x))-70,maxX=Math.max(...visibleNodes.map(n=>n.x))+200,minY=Math.min(...visibleNodes.map(n=>n.y))-65,maxY=Math.max(...visibleNodes.map(n=>n.y))+65;
    const w=Math.max(220,maxX-minX),h=Math.max(180,maxY-minY);const k=Math.max(.26,Math.min(1.25,Math.min(box.width/w,box.height/h)));
    view.k=k;view.x=box.width/2-(minX+w/2)*k;view.y=box.height/2-(minY+h/2)*k;render();
  }

  function clientToGraph(clientX,clientY){const rect=svg.getBoundingClientRect();return {x:(clientX-rect.left-view.x)/view.k,y:(clientY-rect.top-view.y)/view.k};}
  function startNodeDrag(e,n){
    e.stopPropagation();e.preventDefault();const p=clientToGraph(e.clientX,e.clientY);nodeDrag={id:n.id,pointerId:e.pointerId,dx:n.x-p.x,dy:n.y-p.y,startX:e.clientX,startY:e.clientY,moved:false};svg.setPointerCapture?.(e.pointerId);
  }

  svg.addEventListener('pointermove',e=>{
    if(nodeDrag){const n=sceneNodes.find(x=>x.id===nodeDrag.id);if(!n)return;const p=clientToGraph(e.clientX,e.clientY);if(Math.hypot(e.clientX-nodeDrag.startX,e.clientY-nodeDrag.startY)>4)nodeDrag.moved=true;n.x=p.x+nodeDrag.dx;n.y=p.y+nodeDrag.dy;n.manual=true;render();return;}
    if(!panDrag)return;view.x=panDrag.vx+e.clientX-panDrag.x;view.y=panDrag.vy+e.clientY-panDrag.y;render();
  });
  svg.addEventListener('pointerup',e=>{
    if(nodeDrag){
      const drag=nodeDrag; const n=sceneNodes.find(x=>x.id===drag.id);
      suppressClick=true; window.setTimeout(()=>{suppressClick=false;},120);
      if(drag.moved){writeSavedLayout();}
      else if(n){selected=n.id;showNode(n);render();}
      nodeDrag=null; return;
    }
    panDrag=null;
  });
  svg.addEventListener('pointercancel',()=>{nodeDrag=null;panDrag=null;});
  svg.addEventListener('pointerdown',e=>{if(e.target.closest?.('.graph-node'))return;panDrag={x:e.clientX,y:e.clientY,vx:view.x,vy:view.y};svg.setPointerCapture?.(e.pointerId);});
  svg.addEventListener('wheel',e=>{e.preventDefault();const rect=svg.getBoundingClientRect(),mx=e.clientX-rect.left,my=e.clientY-rect.top,old=view.k,next=Math.max(.2,Math.min(2.6,old*(e.deltaY<0?1.1:.9)));view.x=mx-(mx-view.x)*(next/old);view.y=my-(my-view.y)*(next/old);view.k=next;render();},{passive:false});

  function setPreset(next,button){
    preset=next;selected=null;expandedClusters=new Set();
    root.querySelectorAll('[data-graph-preset]').forEach(x=>x.classList.toggle('active',x===button));
    detail.innerHTML=emptyDetail();buildScene();buildTypeFilters();search.value='';applyFilters({fitAfter:true});
  }

  search.addEventListener('input',()=>applyFilters());
  root.querySelectorAll('[data-graph-preset]').forEach(b=>b.addEventListener('click',()=>setPreset(b.dataset.graphPreset,b)));
  root.querySelector('[data-graph-fit]')?.addEventListener('click',fit);
  root.querySelector('[data-graph-reset-layout]')?.addEventListener('click',()=>{clearSavedLayout();autoLayout();applyFilters({fitAfter:true});});
  root.querySelector('[data-graph-neighborhood]')?.addEventListener('click',()=>selected&&focusNeighborhood(selected,1));
  root.querySelector('[data-graph-two-hop]')?.addEventListener('click',()=>selected&&focusNeighborhood(selected,2));
  root.querySelector('[data-graph-all]')?.addEventListener('click',()=>{search.value='';activeTypes=new Set(sceneNodes.map(n=>n.type).filter(t=>t!=='cluster'));buildTypeFilters();applyFilters({fitAfter:true});});



  // Perspective order is personal UX state, independent of target evidence.
  const presetWrap=root.querySelector('[data-graph-presets]');
  const presetOrderKey=`negro.graph.presetOrder:${targetKey}`;
  const defaultPresetOrder=['surface','untested','interesting','burp','attack','all'];
  function restorePresetOrder(){
    if(!presetWrap)return;
    let order=defaultPresetOrder;
    try{const x=JSON.parse(localStorage.getItem(presetOrderKey)||'[]');if(Array.isArray(x)&&x.length)order=[...x,...defaultPresetOrder.filter(v=>!x.includes(v))];}catch(_){ }
    order.forEach(id=>{const b=presetWrap.querySelector(`[data-graph-preset="${id}"]`);if(b)presetWrap.appendChild(b);});
  }
  function savePresetOrder(){
    if(!presetWrap)return;
    const order=[...presetWrap.querySelectorAll('[data-graph-preset]')].map(b=>b.dataset.graphPreset);
    try{localStorage.setItem(presetOrderKey,JSON.stringify(order));}catch(_){ }
  }
  if(presetWrap){
    restorePresetOrder(); let dragged=null;
    presetWrap.querySelectorAll('[data-graph-preset]').forEach(b=>{
      b.addEventListener('dragstart',e=>{dragged=b;b.classList.add('dragging');e.dataTransfer?.setData('text/plain',b.dataset.graphPreset);});
      b.addEventListener('dragend',()=>{b.classList.remove('dragging');dragged=null;savePresetOrder();});
      b.addEventListener('dragover',e=>{e.preventDefault();if(!dragged||dragged===b)return;const r=b.getBoundingClientRect();presetWrap.insertBefore(dragged,e.clientY<r.top+r.height/2?b:b.nextSibling);});
    });
  }
  root.querySelector('[data-graph-preset-order-reset]')?.addEventListener('click',()=>{try{localStorage.removeItem(presetOrderKey);}catch(_){ }restorePresetOrder();});

  // Graph-aware AI hypotheses.
  const aiPanel=root.querySelector('[data-graph-ai-panel]');
  const aiScope=root.querySelector('[data-graph-ai-scope]');
  const aiModel=root.querySelector('[data-graph-ai-model]');
  const aiEstimateBtn=root.querySelector('[data-graph-ai-estimate-btn]');
  const aiRunBtn=root.querySelector('[data-graph-ai-run-btn]');
  const aiStatus=root.querySelector('[data-graph-ai-status]');
  const aiResults=root.querySelector('[data-graph-ai-results]');
  let aiSelectedNodeId='';
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));
  function fmtCop(v){return `COP $${Number(v||0).toLocaleString('es-CO',{maximumFractionDigits:2})}`;}
  function openAiPanel(nodeId='',label=''){
    aiSelectedNodeId=nodeId||''; if(aiPanel)aiPanel.hidden=false;
    if(aiScope)aiScope.textContent=nodeId?`Explorar relaciones alrededor de “${label||nodeId}” (2 saltos + contexto global).`:'Analizar todo el target y buscar áreas relevantes aún no exploradas.';
    aiRunBtn?.setAttribute('hidden','');
    if(aiStatus)aiStatus.textContent='Primero estima el costo. Negro enviará contexto estructurado; no cuerpos HTTP completos.';
    aiPanel?.scrollIntoView({behavior:'smooth',block:'nearest'});
  }
  root.querySelector('[data-graph-ai-open]')?.addEventListener('click',()=>openAiPanel());
  root.querySelector('[data-graph-ai-close]')?.addEventListener('click',()=>{if(aiPanel)aiPanel.hidden=true;});

  aiEstimateBtn?.addEventListener('click',async()=>{
    aiEstimateBtn.disabled=true; if(aiStatus)aiStatus.textContent='Construyendo contexto y estimando…';
    try{
      const u=new URL(aiEstimateUrl,window.location.origin);u.searchParams.set('model',aiModel?.value||'');if(aiSelectedNodeId)u.searchParams.set('selected_node_id',aiSelectedNodeId);
      const r=await fetch(u,{headers:{Accept:'application/json'}});const d=await r.json();if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);
      if(aiStatus)aiStatus.innerHTML=`<b>${d.cached?'Cache disponible':'Costo máximo estimado'}</b> · ${d.cached?'COP $0':fmtCop(d.max_total_cop_est)} · entrada ≈ ${Number(d.input_tokens_est||0).toLocaleString('es-CO')} tokens · salida máx. ${Number(d.output_tokens_budget||0).toLocaleString('es-CO')}<br><small>Hash de evidencia ${(d.evidence_hash||'').slice(0,12)}… · no se envían cuerpos HTTP completos.</small>`;
      aiRunBtn?.removeAttribute('hidden');
    }catch(err){if(aiStatus)aiStatus.textContent=`No pude estimar: ${err.message}`;}
    finally{aiEstimateBtn.disabled=false;}
  });

  function ideaCard(h){
    const status=h.status||'candidate'; const statusUi={candidate:'Candidata',testing:'En prueba',interesting:'Interesante',negative:'Negativa',postponed:'Para después',confirmed:'Confirmada',discarded:'Descartada'}[status]||status;
    const priority=(h.investigation_priority||'medium').toLowerCase();
    const priorityLabel=priority==='high'?'ALTA PRIORIDAD':priority==='quick'?'CHEQUEO RÁPIDO':'PRIORIDAD MEDIA';
    const reasons=(h.priority_reasons||[]).slice(0,4).map(x=>`<span class="badge reason-chip">${esc(x)}</span>`).join('');
    const steps=(h.steps||[]).slice(0,6).map(x=>`<li><b>${esc(x.action||'')}</b>${x.what_to_watch?`<small>Qué mirar: ${esc(x.what_to_watch)}</small>`:''}</li>`).join('');
    const refs=(h.evidence_refs||[]).slice(0,5).map(r=>`<a class="evidence-ref" href="${base}/resource/${Number(r.resource_id||0)}#http"><span>${r.method?`<b>${esc(r.method)}</b> `:''}<code>${esc((r.path||'')+(r.query?'?'+r.query:''))}</code></span><small>${r.exchange_id?`Solicitud Burp #${Number(r.exchange_id)} · `:''}${r.status!=null?`HTTP ${esc(r.status)}`:''}${r.source?` · ${esc(r.source)}`:''}</small></a>`).join('');
    const resourceId=Number(h.resource_id||0), method=String(h.primary_method||'');
    return `<article class="graph-ai-card priority-view-${esc(priority)}" data-idea="${Number(h.lead_id||0)}"><div class="graph-ai-card-top"><div class="badges"><span class="badge hypothesis-priority priority-${esc(priority)}">${priorityLabel}</span><span class="graph-ai-kind">${esc(h.type||'hypothesis')}</span>${reasons}</div><span class="state-chip">${esc(statusUi)}</span></div><h3>${esc(h.title||'Hipótesis')}</h3>${steps?`<div class="test-plan test-plan-now"><div class="test-plan-title"><span>▶</span><h3>Prueba esto ahora</h3></div><ol class="ai-steps">${steps}</ol></div>`:''}${h.plain_language?`<div class="hypothesis-plain"><b>En simple:</b> ${esc(h.plain_language)}</div>`:''}<p><b>Por qué merece tiempo:</b> ${esc(h.why_interesting||'')}</p><p><b>Objetivo ofensivo:</b> ${esc(h.suggested_investigation||'')}</p>${refs?`<div class="hypothesis-evidence"><h3>Evidencia real</h3><div class="evidence-ref-list">${refs}</div></div>`:''}<p><b>Se vuelve interesante si:</b> ${esc(h.confirm_if||'')}</p><p><b>Descartar si:</b> ${esc(h.discard_if||'')}</p><div class="graph-ai-card-actions">${resourceId?`<a class="btn-secondary" href="${base}/resource/${resourceId}#http">Abrir evidencia HTTP</a>`:''}${resourceId&&method?`<button type="button" class="btn-secondary" data-send-repeater data-resource="${resourceId}" data-method="${esc(method)}">Enviar a Repeater →</button>`:''}<button type="button" class="btn-secondary" data-view-idea>Ver en mapa</button><button type="button" class="btn-secondary" data-idea-status="testing">Empezar prueba</button><button type="button" class="btn-secondary" data-idea-status="negative">Negativa</button><button type="button" class="btn-secondary" data-idea-status="interesting">Interesante</button><button type="button" class="btn-secondary" data-idea-status="postponed">Para después</button><button type="button" class="btn-secondary" data-idea-status="confirmed">Confirmada</button><a class="btn-secondary" href="${base}/hypotheses">Abrir hipótesis</a></div></article>`;
  }
  async function refreshGraphData(){
    const r=await fetch(api,{headers:{Accept:'application/json'}});if(!r.ok)throw new Error(`HTTP ${r.status}`);graph=await r.json();buildScene();buildTypeFilters();applyFilters({fitAfter:false});
  }
  function bindIdeaCards(){
    aiResults?.querySelectorAll('[data-idea]').forEach(card=>{
      const leadId=Number(card.dataset.idea||0);
      card.querySelector('[data-view-idea]')?.addEventListener('click',async()=>{
        const btn=root.querySelector('[data-graph-preset="interesting"]');if(btn)setPreset('interesting',btn);
        const id=`lead:${leadId}`;const n=sceneNodes.find(x=>x.id===id)||graph.nodes.find(x=>x.id===id);if(n){selected=id;showNode(n);focusNeighborhood(id,1);}
      });
      card.querySelector('[data-send-repeater]')?.addEventListener('click',async(ev)=>{
        const b=ev.currentTarget; const rid=Number(b.dataset.resource||0); if(!rid)return;
        const fd=new FormData();fd.set('csrf',csrf);fd.set('method',b.dataset.method||'GET');b.disabled=true;
        try{const r=await fetch(`${base}/resource/${rid}/send-repeater`,{method:'POST',body:fd,headers:{'X-Requested-With':'NegroFetch'}});if(!r.ok)throw new Error(`HTTP ${r.status}`);b.textContent='Enviado a Repeater ✓';}
        catch(err){b.textContent=`Error: ${err.message}`;b.disabled=false;}
      });
      card.querySelectorAll('[data-idea-status]').forEach(b=>b.addEventListener('click',async()=>{
        const fd=new FormData();fd.set('csrf',csrf);fd.set('status',b.dataset.ideaStatus);
        const r=await fetch(`${base}/lead/${leadId}/status`,{method:'POST',body:fd,headers:{Accept:'application/json','X-Requested-With':'NegroFetch'}});const d=await r.json();if(!r.ok){alert(d.detail||`HTTP ${r.status}`);return;}card.querySelector('.state-chip').textContent=({candidate:'Candidata',testing:'En prueba',interesting:'Interesante',negative:'Negativa',postponed:'Para después',confirmed:'Confirmada',discarded:'Descartada'}[d.status]||d.status);await refreshGraphData();
      }));
    });
  }
  aiRunBtn?.addEventListener('click',async()=>{
    aiRunBtn.disabled=true;if(aiStatus)aiStatus.textContent='IA analizando relaciones, evidencia y pruebas previas…';if(aiResults)aiResults.innerHTML='';
    try{
      const fd=new FormData();fd.set('csrf',csrf);fd.set('confirm_cost','yes');fd.set('model',aiModel?.value||'');fd.set('selected_node_id',aiSelectedNodeId);
      const r=await fetch(aiRunUrl,{method:'POST',body:fd,headers:{Accept:'application/json','X-Requested-With':'NegroFetch'}});const d=await r.json();if(!r.ok)throw new Error(d.detail||`HTTP ${r.status}`);
      for(;;){
        await sleep(1200);const jr=await fetch(d.job_url,{headers:{Accept:'application/json'}});const job=await jr.json();
        if(job.status==='error')throw new Error(job.error||'Error en IA');
        if(job.status==='done'){
          const result=job.summary?.result||{};const ideas=result.hypotheses||[];
          if(aiStatus){
            const prefix=result.cached?'Resultado reutilizado desde cache. ':'';
            aiStatus.textContent=prefix+(result.summary||`Generadas ${ideas.length} hipótesis.`);
            if(result.retryable) aiStatus.textContent+=' El resultado inválido NO quedó cacheado: puedes intentarlo de nuevo.';
          }
          if(aiResults){
            let empty='';
            if(result.error_type==='incomplete') empty='<p class="empty">La respuesta quedó incompleta antes de cerrar el JSON. Negro ya intentó ampliar el presupuesto cuando correspondía; no se guardó ni cacheó. Revisa los logs <code>[AI graph]</code> y vuelve a generar.</p>';
            else if(result.error_type==='refusal') empty='<p class="empty">El modelo rechazó esta generación. No se guardó ni cacheó el resultado.</p>';
            else if(result.error_type==='api_error') empty='<p class="empty">La llamada a OpenAI falló. No se guardó ni cacheó el resultado; puedes reintentar.</p>';
            else if(result.retryable) empty='<p class="empty">La respuesta completó pero no pudo validarse como Structured Output. No se guardó ni cacheó. Revisa los logs <code>[AI graph]</code> y vuelve a generar.</p>';
            else if(result.exploratory_retry_used) empty='<p class="empty">Negro hizo también un segundo intento exploratorio y no encontró una hipótesis defendible con la evidencia actual. Captura más tráfico o completa checks pendientes y vuelve a intentarlo.</p>';
            else empty='<p class="empty">La IA no propuso hipótesis nuevas con evidencia suficiente.</p>';
            aiResults.innerHTML=ideas.length?ideas.map(ideaCard).join(''):empty;
          }
          await refreshGraphData();bindIdeaCards();break;
        }
        if(aiStatus)aiStatus.textContent='IA trabajando…';
      }
    }catch(err){if(aiStatus)aiStatus.textContent=`Error: ${err.message}`;}
    finally{aiRunBtn.disabled=false;}
  });

  const initialFocus=new URLSearchParams(window.location.search).get('focus');
  load().then(()=>{if(initialFocus){const n=sceneNodes.find(x=>x.id===initialFocus)||graph.nodes?.find(x=>x.id===initialFocus);if(n){const btn=root.querySelector('[data-graph-preset="interesting"]');if(btn)setPreset('interesting',btn);selected=n.id;showNode(n);focusNeighborhood(n.id,1);}}});
})();
