(() => {
  const root = document.querySelector('[data-graph-root]');
  if (!root) return;

  const svg = root.querySelector('[data-graph-canvas]');
  const detail = root.querySelector('[data-graph-detail]');
  const search = root.querySelector('[data-graph-search]');
  const typeWrap = root.querySelector('[data-graph-types]');
  const hypothesisFilterWrap = root.querySelector('[data-graph-hypothesis-filters]');
  const leadStatusWrap = root.querySelector('[data-graph-lead-statuses]');
  const leadKindWrap = root.querySelector('[data-graph-lead-kinds]');
  const leadPriorityWrap = root.querySelector('[data-graph-lead-priorities]');
  const empty = root.querySelector('[data-graph-empty]');
  const routesWrap = root.querySelector('[data-graph-routes]');
  const routePanel = root.querySelector('.graph-route-panel');
  const fullscreenBtn = root.querySelector('[data-graph-fullscreen]');
  const routeToggleBtn = root.querySelector('[data-graph-route-toggle]');
  const statusEl = root.querySelector('[data-graph-layout-status]');
  const scopeStatusEl = root.querySelector('[data-graph-scope-status]');
  const scopeCopyEl = root.querySelector('[data-graph-scope-copy]');
  const contextPanel = root.querySelector('[data-graph-context-panel]');
  const identityControls = root.querySelector('[data-graph-identity-controls]');
  const flowControls = root.querySelector('[data-graph-flow-controls]');
  const objectControls = root.querySelector('[data-graph-object-controls]');
  const discoveryControls = root.querySelector('[data-graph-discovery-controls]');
  const discoveryQuery = root.querySelector('[data-graph-discovery-query]');
  const identitySelect = root.querySelector('[data-graph-identity-select]');
  const identityCompare = root.querySelector('[data-graph-identity-compare]');
  const identityCompareSummary = root.querySelector('[data-identity-compare-summary]');
  const flowSelect = root.querySelector('[data-graph-flow-select]');
  const objectSelect = root.querySelector('[data-graph-object-select]');
  const pathClearBtn = root.querySelector('[data-graph-path-clear]');
  const narrative = root.querySelector('[data-graph-narrative]');
  const discoveryInsights = root.querySelector('[data-graph-discovery-insights]');
  const discoveryTrailBar = root.querySelector('[data-graph-discovery-trail]');
  const discoveryInsightsToggle = root.querySelector('[data-discovery-insights-toggle]');
  const discoveryInsightsCount = root.querySelector('[data-discovery-insights-count]');
  const discoveryInsightsClose = root.querySelector('[data-discovery-insights-close]');
  const canvasShell = root.querySelector('[data-graph-canvas-shell]');
  const canvasWrap = root.querySelector('.graph-canvas-wrap');
  const graphWorkspace = root.querySelector('.graph-workspace');
  const viewExplainer = root.querySelector('[data-view-explainer]');
  const layerControls = root.querySelector('[data-graph-layer-controls]');
  const layerInputs = [...root.querySelectorAll('[data-graph-layer]')];
  const flowViewSwitch = root.querySelector('[data-flow-view-switch]');
  const intelligenceOnlyInput = root.querySelector('[data-graph-intelligence-only]');
  const discoveryCrossWrap = root.querySelector('[data-discovery-cross-wrap]');
  const discoveryCrossOnlyInput = root.querySelector('[data-discovery-cross-only]');
  const flowViewButtons = [...root.querySelectorAll('[data-flow-view]')];
  const api = root.dataset.api;
  const base = root.dataset.base;
  const targetKey = root.dataset.target || 'target';
  const csrf = root.dataset.csrf || '';
  const aiEstimateUrl = root.dataset.aiEstimate || '';
  const aiRunUrl = root.dataset.aiRun || '';
  const NS = 'http://www.w3.org/2000/svg';

  const typeOrder = ['target','investigation','identifier','parameter','identity','session','flow','object','request','state','requirement','anomaly','host','resource','operation','javascript','source','observation','lead','finding','cluster','external'];
  const typeLabel = {
    source:'Fuentes', target:'Proyecto', host:'Hosts', javascript:'JavaScript', resource:'Endpoints',
    operation:'Métodos', cluster:'Grupos', request:'Requests', observation:'Observaciones', identity:'Identidades',
    investigation:'Investigaciones', identifier:'Pieza seguida', parameter:'Piezas cercanas', session:'Sesiones / auth', flow:'Flujos', object:'Objetos', state:'Estados', requirement:'Dependencias', anomaly:'Anomalías', lead:'Hipótesis', finding:'Hallazgos', external:'Relacionados'
  };
  const stateLabel = {normal:'Normal',untested:'Pendiente',testing:'En prueba',interesting:'Interesante',finding:'Hallazgo',tested:'Revisado'};
  const coverageLabel = {untested:'Pendiente',testing:'En prueba',tested:'Revisado'};
  const signalLabel = {normal:'Normal',interesting:'Interesante',finding:'Hallazgo'};
  const metaKeyLabel = {id:'ID',type:'Tipo',kind:'Tipo',status:'Estado',confidence:'Confianza',priority:'Prioridad',source:'Fuente',why:'Por qué',next_test:'Siguiente prueba',method:'Método',url:'URL',path:'Ruta',host:'Host',hostname:'Host',seen_count:'Veces visto',authenticated:'Con sesión',authenticated_observed:'Sesión observada',content_type:'Content-Type',request_content_type:'Content-Type Request',response_content_type:'Content-Type Response',first_seen:'Primera vez',first_seen_at:'Primera vez',last_seen:'Última vez',last_seen_at:'Última vez',finding_count:'Hallazgos',coverage:'Cobertura',signal:'Señal',count:'Cantidad',requests:'Requests',objects:'Objetos',flows:'Flujos',steps:'Pasos',object_type:'Tipo interno',identifier:'Valor observado',identifier_field:'Campo identificador',methods:'Métodos soportados',method_count:'Métodos',field:'Campo',identity:'Identidad',message:'Qué observó Negro',baseline:'Patrón repetido',current:'Esta instancia',query:'Consulta',mode:'Modo',observations:'Observaciones',endpoints:'Endpoints',hosts:'Hosts',identities:'Identidades',aliases:'Aliases',values:'Valores',distinct_values:'Valores distintos',example:'Ejemplo'};
  const relationLabel = {contains:'contiene',supports:'soporta',observed_in:'observado en',observed_on:'observado en',observed:'observó',discovered:'descubrió',discovered_by:'descubierto por',tested_by:'probado con',produced_lead:'produjo hipótesis',supports_hypothesis:'soporta hipótesis',contradicts_hypothesis:'contradice hipótesis',evidence_for:'evidencia de',affected_by:'afectado por',related_to:'relacionado con',source:'fuente',calls:'llama',accepts:'acepta',produced:'produjo',returned_by:'devuelto por',authenticated_as:'autenticado como',belongs_to:'pertenece a',performed:'hizo Request',participates_in:'participó en',flow_actor:'actor del Flujo',flow_step:'incluye Request',next_step:'siguiente paso',touches:'toca objeto',touches_object:'toca objeto',observed_object:'observó objeto',co_observed:'visto junto con',state_observed:'estado observado',pattern_difference:'diferencia de patrón',attention:'merece atención',called_endpoint:'consumió endpoint',appeared_in_endpoint:'apareció en endpoint',flow_endpoint:'Flujo usó endpoint',observed_request:'evidencia HTTP',seen_in_flow:'aparece en Flujo',seen_with_identity:'aparece con identidad',represented_as_object:'representa objeto',co_observed_key:'key observada cerca',requires:'requiere',unblocked:'desbloqueó',provided_context:'aportó contexto',uses_session:'usa sesión',read_allowed:'leyó',read_denied:'lectura denegada',read_observed:'lectura observada',write_allowed:'escritura aceptada',write_denied:'escritura rechazada',changed_address:'cambió dirección',cancelled_object:'canceló',created_return:'creó devolución',refunded_object:'ejecutó refund',deleted_object:'eliminó',owns_observed:'owner observado'};
  const valueLabel = v => ({candidate:'Candidata',testing:'En prueba',interesting:'Interesante',negative:'Negativa',postponed:'Para después',confirmed:'Confirmada',discarded:'Descartada',pending:'Pendiente',in_progress:'En revisión',reviewed:'Revisado',unknown:'Sin clasificar',lead:'Interesante',finding:'Hallazgo',high:'Alta',medium:'Media',low:'Baja',none:'Sin prioridad'}[String(v)] || v);
  const leadKindLabel = {
    access_object_reference:'IDOR / autorización horizontal', mass_assignment:'Asignación masiva',
    method_access_control:'Método HTTP', redirect_body_access_control:'Datos antes de redirect',
    proxy_path_access_control:'Ruta / proxy', referer_access_control:'Referer',
    javascript_surface:'Superficie JavaScript', cors:'CORS', source_map:'Source map',
    open_redirect:'Open redirect', ssrf_surface:'SSRF', dom_xss:'DOM XSS',
    secret_or_client_config:'Secretos / config', oauth_oidc_surface:'OAuth/OIDC'
  };

  let graph = {nodes:[],edges:[]};
  let sceneNodes = [], sceneEdges = [], visibleNodes = [], visibleEdges = [];
  let selected = null;
  let activeRoute = null;
  let pathStart = null;
  let activePathIds = [];
  let activePathEdgeIds = new Set();
  let preset = 'surface';
  let activeTypes = new Set();
  let activeLeadStatuses = new Set(['candidate','testing','interesting','confirmed']);
  let activeLeadKinds = new Set();
  let activeLeadPriorities = new Set(['high','medium','low']);
  let leadFiltersInitialized = false;
  let expandedClusters = new Set();
  let view = {x:0,y:0,k:1};
  let panDrag = null;
  let nodeDrag = null;
  let suppressClick = false;
  let flowViewMode = (()=>{try{return localStorage.getItem(`negro.flow.map.view:${targetKey}`)||'graph';}catch(_){return 'graph';}})();
  let identityEndpointMode = 'all';
  let intelligenceOnly = false;
  let discoveryTrail = [];
  let discoveryPreviousSeen = '';
  let discoveryInsightsOpen = false;
  let discoveryCrossOnly = false;
  let fullscreenReflow = false;

  const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
  const slugState = s => ['finding','interesting','tested','testing','untested'].includes(s) ? s : 'normal';
  function nodeRadius(t){
    if(t==='identifier')return 17;
    if(t==='investigation')return 16;
    if(t==='parameter'||t==='requirement')return 9;
    if(t==='identity')return 16;
    if(t==='session')return 8;
    if(t==='flow')return 14;
    if(t==='resource')return 11;
    if(t==='object')return 7.5;
    if(t==='request')return preset==='flow'?10:6.5;
    if(t==='operation')return 5.5;
    if(t==='target')return 11;
    if(t==='host')return 10;
    if(t==='finding')return 11;
    if(t==='anomaly'||t==='cluster')return 9;
    return 7;
  }
  const labelLimit = t => ['resource','operation','request','object','identifier','parameter'].includes(t) ? 52 : 36;
  const edgeId = (a,b,r) => `virtual:${a}:${r}:${b}`;
  const byId = () => new Map(graph.nodes.map(n => [n.id,n]));
  const sceneById = () => new Map(sceneNodes.map(n => [n.id,n]));
  const edgesOf = id => graph.edges.filter(e => e.source === id || e.target === id);
  const opposite = (e,id) => e.source === id ? e.target : e.source;


  function identityEndpointSets(){
    const primaryId=Number(graph.meta?.identity_id||0), compareId=Number(graph.meta?.compare_identity_id||0);
    const endpointSet=iid=>new Set(graph.edges.filter(e=>e.source===`identity:${iid}`&&e.relation==='called_endpoint').map(e=>e.target));
    const primary=primaryId?endpointSet(primaryId):new Set();
    const compare=compareId?endpointSet(compareId):new Set();
    const shared=new Set([...primary].filter(x=>compare.has(x)));
    const onlyPrimary=new Set([...primary].filter(x=>!compare.has(x)));
    const onlyCompare=new Set([...compare].filter(x=>!primary.has(x)));
    return {primaryId,compareId,primary,compare,shared,onlyPrimary,onlyCompare};
  }

  function identityEndpointBucket(nodeId){
    const sets=identityEndpointSets();
    if(!sets.compareId)return '';
    if(sets.shared.has(nodeId))return 'shared';
    if(sets.onlyPrimary.has(nodeId))return 'only-primary';
    if(sets.onlyCompare.has(nodeId))return 'only-compare';
    return '';
  }

  function identityEndpointPass(n){
    if(preset!=='identity'||identityEndpointMode==='all'||!Number(graph.meta?.compare_identity_id||0))return true;
    const sets=identityEndpointSets();
    const allowed=identityEndpointMode==='shared'?sets.shared:identityEndpointMode==='only-primary'?sets.onlyPrimary:sets.onlyCompare;
    if(n.type==='identity')return n.id===`identity:${sets.primaryId}`||n.id===`identity:${sets.compareId}`;
    if(n.type==='resource')return allowed.has(n.id);
    if(['operation','request','object','flow'].includes(n.type)){
      return graph.edges.some(e=>{
        if(e.source!==n.id&&e.target!==n.id)return false;
        const other=opposite(e,n.id);
        if(allowed.has(other))return true;
        if(n.type==='flow'){
          return graph.edges.some(x=>(x.source===n.id||x.target===n.id)&&allowed.has(opposite(x,n.id)));
        }
        return false;
      });
    }
    return true;
  }

  function renderIdentityCompareSummary(){
    if(!identityCompareSummary)return;
    const sets=identityEndpointSets();
    if(preset!=='identity'||!sets.primaryId||!sets.compareId){identityCompareSummary.hidden=true;identityCompareSummary.innerHTML='';identityEndpointMode='all';return;}
    const opts=graph.meta?.filter_options?.identities||[];
    const label=id=>opts.find(x=>Number(x.id)===Number(id))?.name||graph.nodes.find(n=>n.id===`identity:${id}`)?.label||`Identidad ${id}`;
    const buttons=[
      ['all',`Todos · ${new Set([...sets.primary,...sets.compare]).size}`],
      ['shared',`Compartidos · ${sets.shared.size}`],
      ['only-primary',`Solo ${label(sets.primaryId)} · ${sets.onlyPrimary.size}`],
      ['only-compare',`Solo ${label(sets.compareId)} · ${sets.onlyCompare.size}`],
    ];
    identityCompareSummary.hidden=false;
    identityCompareSummary.innerHTML=`<span>Lectura rápida</span>${buttons.map(([mode,text])=>`<button type="button" data-identity-endpoint-mode="${mode}" class="${identityEndpointMode===mode?'active':''}">${esc(text)}</button>`).join('')}`;
    identityCompareSummary.querySelectorAll('[data-identity-endpoint-mode]').forEach(btn=>btn.addEventListener('click',()=>{
      identityEndpointMode=btn.dataset.identityEndpointMode||'all';
      renderIdentityCompareSummary();applyFilters({fitAfter:true});
    }));
  }

  function endpointIdentityResults(nodeId){
    if(preset==='identity'){
      const opts=graph.meta?.filter_options?.identities||[];
      const selected=[Number(graph.meta?.identity_id||0),Number(graph.meta?.compare_identity_id||0)].filter(Boolean);
      const label=id=>opts.find(x=>Number(x.id)===Number(id))?.name||graph.nodes.find(n=>n.id===`identity:${id}`)?.label||`Identidad ${id}`;
      return selected.map((iid,index)=>{
        const edge=graph.edges.find(e=>e.source===`identity:${iid}`&&e.target===nodeId&&e.relation==='called_endpoint');
        if(!edge)return null;
        const statuses=[...(edge.meta?.evidence?.statuses||[])].map(String);
        return {id:iid,index,label:label(iid),statuses:statuses.length?statuses:['—'],observed:true};
      }).filter(Boolean);
    }
    if(preset==='discovery'&&layerEnabled('identity')){
      const n=graph.nodes.find(x=>x.id===nodeId);
      const requests=Array.isArray(n?.meta?.discovery_evidence?.requests)?n.meta.discovery_evidence.requests:[];
      const grouped=new Map();
      requests.forEach(r=>{
        const iid=Number(r.identity_id||0); if(!iid)return;
        const key=String(iid); const row=grouped.get(key)||{id:iid,label:r.identity_name||`Identidad ${iid}`,statuses:new Set(),observed:true};
        row.statuses.add(String(r.status??'—')); grouped.set(key,row);
      });
      const pivot=graph.nodes.find(x=>x.type==='identifier');
      const owners=new Set((pivot?.meta?.owner_identity_ids||[]).map(Number));
      const rows=[...grouped.values()].map((r,index)=>({...r,index,statuses:[...r.statuses],owner:owners.has(Number(r.id)),cross:owners.size>0&&!owners.has(Number(r.id))}));
      const branches=Array.isArray(graph.meta?.discovery_branches)?graph.meta.discovery_branches:[];
      const rid=Number(n?.meta?.id||0);
      branches.filter(b=>Number(b.resource_id||0)===rid).forEach(b=>{
        const iid=Number(b.identity_id||0);
        if(rows.some(x=>x.id===iid))return;
        rows.push({id:iid,index:rows.length,label:b.identity_name||`Identidad ${iid}`,statuses:['no observado'],observed:false,untested:true,owner:owners.has(iid),cross:owners.size>0&&!owners.has(iid)});
      });
      return rows;
    }
    return [];
  }

  function nodeIntelligence(n){
    const signalCount=Number(n?.meta?.signal_count||0);
    const correlationCount=Math.min(signalCount,Number(n?.meta?.correlation_count||0));
    const localSignalCount=Math.max(0,signalCount-correlationCount);
    const hypothesisCount=Number(n?.meta?.hypothesis_count||0);
    return {
      signalCount,correlationCount,localSignalCount,hypothesisCount,
      hasSignal:localSignalCount>0,hasCorrelation:correlationCount>0,hasHypothesis:hypothesisCount>0,
      hasAny:signalCount>0||hypothesisCount>0
    };
  }

  function intelligenceBadgesHtml(n,{links=false}={}){
    const intel=nodeIntelligence(n);
    if(!intel.hasAny)return '';
    const wrap=(kind,text,href='')=>links&&href?`<a class="intel-chip ${kind}" href="${base}/${esc(href)}">${text}</a>`:`<span class="intel-chip ${kind}">${text}</span>`;
    const items=[];
    if(intel.localSignalCount)items.push(wrap('signal',`⚡ S${intel.localSignalCount}`));
    if(intel.correlationCount)items.push(wrap('correlation',`↔ C${intel.correlationCount}`));
    if(intel.hypothesisCount)items.push(wrap('hypothesis',`◆ H${intel.hypothesisCount}`));
    return `<span class="intel-chip-row">${items.join('')}</span>`;
  }

  function intelligenceRelevantIds(){
    const keep=new Set();
    const nodes=new Map(sceneNodes.map(n=>[n.id,n]));
    const structural=new Set(['target','host','resource','operation','request','identity','flow','object']);
    sceneNodes.forEach(n=>{if(nodeIntelligence(n).hasAny)keep.add(n.id);});
    // Two linear edge passes keep just enough surrounding context.  Avoid node
    // lookups inside nested scans so the filter stays practical on large targets.
    for(let pass=0;pass<2;pass++){
      sceneEdges.forEach(e=>{
        if(!keep.has(e.source)&&!keep.has(e.target))return;
        const a=nodes.get(e.source), b=nodes.get(e.target);
        if(a&&structural.has(a.type))keep.add(a.id);
        if(b&&structural.has(b.type))keep.add(b.id);
      });
    }
    return keep;
  }

  function semanticCardMode(n){
    if(['identity','flow','objects'].includes(preset)&&['identity','flow','resource'].includes(n.type))return true;
    // When identities are layered into Discovery, switch endpoints/identities to
    // the same card language as Identity Compare instead of adding tiny nodes.
    if(preset==='discovery'&&layerEnabled('identity')&&['identity','resource'].includes(n.type))return true;
    return false;
  }

  function cardWidthFor(n){
    const text=String(n.label||'');
    if(n.type==='resource'){
      const statusText=endpointIdentityResults(n.id).map(x=>`${x.label} · ${x.statuses.join('/')}`).join('   ');
      const intel=nodeIntelligence(n);
      const extra=intel.hasAny?58:0;
      return Math.max(126,Math.min(390,Math.max(text.length*7.2+34+extra,statusText.length*6.2+30+extra)));
    }
    if(n.type==='identity')return Math.max(104,Math.min(190,text.length*7.4+44));
    if(n.type==='flow')return Math.max(110,Math.min(210,text.length*7.2+44));
    return 40;
  }

  function appendNodeVisual(ng,n){
    const r=nodeRadius(n.type);
    const fixed=semanticCardMode(n);
    const vg=document.createElementNS(NS,'g');vg.setAttribute('class','graph-node-visual');
    if(fixed){const inv=1/Math.max(.18,view.k);vg.setAttribute('transform',`scale(${inv})`);}
    let inlineLabel=false,labelAnchor=r+8;
    const addRect=(x,y,w,h,rx,cls='node-shape')=>{const el=document.createElementNS(NS,'rect');el.setAttribute('x',String(x));el.setAttribute('y',String(y));el.setAttribute('width',String(w));el.setAttribute('height',String(h));el.setAttribute('rx',String(rx));el.setAttribute('class',cls);vg.appendChild(el);return el;};
    const addCircle=(cx,cy,rr,cls='node-shape')=>{const el=document.createElementNS(NS,'circle');el.setAttribute('cx',String(cx));el.setAttribute('cy',String(cy));el.setAttribute('r',String(rr));el.setAttribute('class',cls);vg.appendChild(el);return el;};
    const addPath=(d,cls='node-icon')=>{const el=document.createElementNS(NS,'path');el.setAttribute('d',d);el.setAttribute('class',cls);vg.appendChild(el);return el;};
    const addText=(x,y,text,cls='node-inline-label',anchor='start')=>{const el=document.createElementNS(NS,'text');el.setAttribute('x',String(x));el.setAttribute('y',String(y));el.setAttribute('text-anchor',anchor);el.setAttribute('class',cls);el.textContent=text;vg.appendChild(el);return el;};
    if(fixed&&n.type==='resource'){
      const w=cardWidthFor(n), results=endpointIdentityResults(n.id), hasResults=results.length>0;
      const h=hasResults?46:30, top=-h/2;
      const intel=nodeIntelligence(n);
      const intelClass=`${intel.hasSignal?' endpoint-intel-signal':''}${intel.hasCorrelation?' endpoint-intel-correlation':''}${intel.hasHypothesis?' endpoint-intel-hypothesis':''}`;
      addRect(-w/2,top,w,h,9,`node-shape endpoint-card${intelClass}`);
      addPath(`M ${-w/2+12} ${hasResults?-9:-4} L ${-w/2+18} ${hasResults?-5:0} L ${-w/2+12} ${hasResults?-1:4} M ${-w/2+18} ${hasResults?-5:0} H ${-w/2+24}`,'node-icon endpoint-icon');
      const limit=44;const text=String(n.label||'');addText(-w/2+31,hasResults?-2:4,text.length>limit?text.slice(0,limit-1)+'…':text,'node-inline-label endpoint-inline');
      let intelX=w/2-10;
      if(intel.hasHypothesis){const t=`◆H${intel.hypothesisCount}`;intelX-=Math.max(31,t.length*6+9);addText(intelX,hasResults?-2:4,t,'node-intel-badge hypothesis');}
      if(intel.hasCorrelation){const t=`↔C${intel.correlationCount}`;intelX-=Math.max(31,t.length*6+9);addText(intelX,hasResults?-2:4,t,'node-intel-badge correlation');}
      if(intel.hasSignal){const t=`⚡S${intel.localSignalCount}`;intelX-=Math.max(31,t.length*6+9);addText(intelX,hasResults?-2:4,t,'node-intel-badge signal');}
      if(hasResults){
        let x=-w/2+12;
        results.forEach((r,idx)=>{
          const name=String(r.label||'Identidad');const short=name.length>16?name.slice(0,15)+'…':name;
          const val=`${r.cross?'↔ ':''}${short} · ${r.statuses.join('/')}`;
          addText(x,15,`${r.untested?'○ ':''}${val}`,`node-endpoint-status ${r.untested?'untested':r.cross?'cross':idx===0?'primary':'secondary'}`);
          x+=Math.min(145,Math.max(78,val.length*6.1+18));
        });
      }
      inlineLabel=true;labelAnchor=w/2+8;
    }else if(fixed&&n.type==='identity'){
      const pivot=graph.nodes.find(x=>x.type==='identifier');
      const owner=preset==='discovery'&&(pivot?.meta?.owner_identity_ids||[]).map(Number).includes(Number(n.meta?.id||String(n.id).split(':').pop()||0));
      const w=cardWidthFor(n)+(owner?38:0);addRect(-w/2,-17,w,34,11,`node-shape identity-card${owner?' discovery-owner-card':''}`);
      addCircle(-w/2+18,-5,4,'node-icon-fill identity-head');addPath(`M ${-w/2+10} 9 C ${-w/2+11} 2, ${-w/2+25} 2, ${-w/2+26} 9`,'node-icon identity-body');
      const limit=22;const text=String(n.label||'');addText(-w/2+34,4,text.length>limit?text.slice(0,limit-1)+'…':text,'node-inline-label identity-inline');
      if(owner)addText(w/2-30,4,'OWNER','node-identity-role owner');
      inlineLabel=true;labelAnchor=w/2+8;
    }else if(fixed&&n.type==='flow'){
      const w=cardWidthFor(n);addRect(-w/2,-16,w,32,10,'node-shape flow-card');
      addPath(`M ${-w/2+12} -6 H ${-w/2+20} V 0 H ${-w/2+27} M ${-w/2+20} 0 V 6 H ${-w/2+27}`,'node-icon flow-icon');
      const limit=24;const text=String(n.label||'');addText(-w/2+35,4,text.length>limit?text.slice(0,limit-1)+'…':text,'node-inline-label flow-inline');
      inlineLabel=true;labelAnchor=w/2+8;
    }else if(n.type==='resource'){
      const intel=nodeIntelligence(n);
      addRect(-10,-7,20,14,5,`node-shape endpoint-mini${intel.hasSignal?' endpoint-intel-signal':''}${intel.hasCorrelation?' endpoint-intel-correlation':''}${intel.hasHypothesis?' endpoint-intel-hypothesis':''}`);
      addPath('M -5 -3 L 0 0 L -5 3 M 0 0 H 6','node-icon endpoint-icon');
      if(intel.hasAny){
        const flag=document.createElementNS(NS,'g');
        flag.setAttribute('class','node-intel-flag');
        flag.setAttribute('transform',`scale(${1/Math.max(.18,view.k)})`);
        let x=14;
        const badges=[];
        if(intel.localSignalCount)badges.push(['signal',`⚡S${intel.localSignalCount}`]);
        if(intel.correlationCount)badges.push(['correlation',`↔C${intel.correlationCount}`]);
        if(intel.hypothesisCount)badges.push(['hypothesis',`◆H${intel.hypothesisCount}`]);
        badges.forEach(([kind,text])=>{
          const w=Math.max(27,text.length*6+10);
          const r=document.createElementNS(NS,'rect');r.setAttribute('x',String(x));r.setAttribute('y','-19');r.setAttribute('width',String(w));r.setAttribute('height','14');r.setAttribute('rx','7');r.setAttribute('class',`node-intel-flag-bg ${kind}`);flag.appendChild(r);
          const t=document.createElementNS(NS,'text');t.setAttribute('x',String(x+w/2));t.setAttribute('y','-9');t.setAttribute('text-anchor','middle');t.setAttribute('class',`node-intel-flag-text ${kind}`);t.textContent=text;flag.appendChild(t);x+=w+4;
        });
        vg.appendChild(flag);
      }
      labelAnchor=16;
    }else if(n.type==='host'){
      addRect(-9,-8,18,16,3,'node-shape host-server');addPath('M -5 -3 H 5 M -5 1 H 5 M -5 5 H 2','node-icon host-lines');labelAnchor=15;
    }else if(n.type==='target'){
      const poly=document.createElementNS(NS,'polygon');poly.setAttribute('points','0,-10 9,-4 7,7 0,11 -7,7 -9,-4');poly.setAttribute('class','node-shape target-project');vg.appendChild(poly);labelAnchor=17;
    }else if(n.type==='object'){
      const pts='0,-8 7,-4 7,4 0,8 -7,4 -7,-4';const poly=document.createElementNS(NS,'polygon');poly.setAttribute('points',pts);poly.setAttribute('class','node-shape object-hex');vg.appendChild(poly);labelAnchor=15;
    }else if(n.type==='request'){
      const intel=nodeIntelligence(n);
      addRect(-6,-8,12,16,2,`node-shape request-doc${intel.hasSignal?' request-intel-signal':''}${intel.hasCorrelation?' request-intel-correlation':''}${intel.hasHypothesis?' request-intel-hypothesis':''}`);addPath('M 1 -8 V -3 H 6 M -3 1 H 3 M -3 5 H 3','node-icon request-lines');
      if(intel.hasAny){
        const flag=document.createElementNS(NS,'g');flag.setAttribute('class','node-intel-flag');flag.setAttribute('transform',`scale(${1/Math.max(.18,view.k)})`);
        const text=`${intel.localSignalCount?`⚡S${intel.localSignalCount} `:''}${intel.correlationCount?`↔C${intel.correlationCount} `:''}${intel.hypothesisCount?`◆H${intel.hypothesisCount}`:''}`.trim();
        const w=Math.max(38,text.length*6+12);const rr=document.createElementNS(NS,'rect');rr.setAttribute('x','13');rr.setAttribute('y','-18');rr.setAttribute('width',String(w));rr.setAttribute('height','14');rr.setAttribute('rx','7');rr.setAttribute('class','node-intel-flag-bg mixed');flag.appendChild(rr);
        const tt=document.createElementNS(NS,'text');tt.setAttribute('x',String(13+w/2));tt.setAttribute('y','-8');tt.setAttribute('text-anchor','middle');tt.setAttribute('class','node-intel-flag-text mixed');tt.textContent=text;flag.appendChild(tt);vg.appendChild(flag);
      }
      labelAnchor=14;
    }else if(n.type==='state'){
      const poly=document.createElementNS(NS,'polygon');poly.setAttribute('points','0,-8 8,0 0,8 -8,0');poly.setAttribute('class','node-shape state-diamond');vg.appendChild(poly);labelAnchor=15;
    }else if(n.type==='anomaly'){
      const poly=document.createElementNS(NS,'polygon');poly.setAttribute('points','0,-9 9,8 -9,8');poly.setAttribute('class','node-shape anomaly-triangle');vg.appendChild(poly);addText(0,5,'!','node-icon-mark','middle');labelAnchor=16;
    }else if(n.type==='operation'){
      addRect(-9,-6,18,12,6,'node-shape operation-pill');labelAnchor=15;
    }else{
      addCircle(0,0,r,'node-shape');
    }
    ng.appendChild(vg);
    return {inlineLabel,labelAnchor,fixed};
  }

  function leadPassesFilters(n){
    if(!n || n.type!=='lead') return true;
    const status=String(n.meta?.status||'candidate');
    const kind=String(n.meta?.type||'other');
    const priority=String(n.meta?.priority||'low');
    return activeLeadStatuses.has(status) && activeLeadKinds.has(kind) && activeLeadPriorities.has(priority);
  }
  function routePassesFilters(r){
    if(!r) return false;
    return activeLeadStatuses.has(String(r.status||'candidate')) &&
      activeLeadKinds.has(String(r.lead_type||'other')) &&
      activeLeadPriorities.has(String(r.priority||'low'));
  }

  function initLeadFilters(){
    const kinds=new Set(graph.nodes.filter(n=>n.type==='lead').map(n=>String(n.meta?.type||'other')));
    (graph.routes||[]).forEach(r=>kinds.add(String(r.lead_type||'other')));
    if(!leadFiltersInitialized){
      activeLeadKinds=new Set(kinds);
      leadFiltersInitialized=true;
    } else {
      kinds.forEach(k=>activeLeadKinds.add(k));
    }
  }

  function filterButton(label,value,set,wrap,{activeByDefault=true}={}){
    const b=document.createElement('button');
    b.type='button'; b.className='graph-mini-filter'; b.dataset.value=value; b.textContent=label;
    if(activeByDefault && set.has(value))b.classList.add('active');
    b.addEventListener('click',()=>{
      set.has(value)?set.delete(value):set.add(value);
      b.classList.toggle('active',set.has(value));
      buildScene();buildTypeFilters();applyFilters({fitAfter:true});renderRoutes();
    });
    wrap?.appendChild(b);
  }

  function buildLeadFilters(){
    if(!leadStatusWrap||!leadKindWrap||!leadPriorityWrap)return;
    leadStatusWrap.innerHTML='';leadKindWrap.innerHTML='';leadPriorityWrap.innerHTML='';
    ['candidate','testing','interesting','confirmed','postponed','negative','discarded'].forEach(s=>filterButton(valueLabel(s),s,activeLeadStatuses,leadStatusWrap));
    const kinds=[...new Set(graph.nodes.filter(n=>n.type==='lead').map(n=>String(n.meta?.type||'other')).concat((graph.routes||[]).map(r=>String(r.lead_type||'other'))))].sort();
    kinds.forEach(k=>filterButton(leadKindLabel[k]||k.replaceAll('_',' '),k,activeLeadKinds,leadKindWrap));
    ['high','medium','low'].forEach(p=>filterButton(valueLabel(p),p,activeLeadPriorities,leadPriorityWrap));
  }

  function updateLeadFilterVisibility(){
    if(hypothesisFilterWrap) hypothesisFilterWrap.hidden=!['interesting','intelligence','attack','all'].includes(preset);
  }

  function fillSelect(select, rows, valueFn, labelFn, selectedValue, emptyLabel){
    if(!select)return;
    const current=String(selectedValue||'');
    select.innerHTML=`<option value="">${esc(emptyLabel)}</option>`+(rows||[]).map(row=>`<option value="${esc(valueFn(row))}" ${String(valueFn(row))===current?'selected':''}>${esc(labelFn(row))}</option>`).join('');
  }

  function populateContextControls(){
    const opts=graph.meta?.filter_options||{};
    const semantic=['identity','flow','objects','discovery'].includes(preset);
    if(contextPanel)contextPanel.hidden=!semantic;
    if(identityControls)identityControls.hidden=preset!=='identity';
    if(flowControls)flowControls.hidden=preset!=='flow';
    if(objectControls)objectControls.hidden=preset!=='objects';
    if(discoveryControls)discoveryControls.hidden=preset!=='discovery';
    if(preset==='discovery'&&discoveryQuery&&!discoveryQuery.value)discoveryQuery.value=graph.meta?.discovery_query||'';
    if(preset==='identity'){
      fillSelect(identitySelect,opts.identities||[],x=>x.id,x=>`${x.name}${Number(x.request_count||0)?` · ${x.request_count} Requests`:''}`,graph.meta?.identity_id,'Todas las identidades');
      fillSelect(identityCompare,opts.identities||[],x=>x.id,x=>x.name,graph.meta?.compare_identity_id,'— ninguna —');
      renderIdentityCompareSummary();
    } else if(preset==='flow'){
      fillSelect(flowSelect,opts.flows||[],x=>x.id,x=>`${x.name}${Number(x.step_count||0)?` · ${x.step_count} pasos`:''}`,graph.meta?.flow_id,'Elige un Flow');
    } else if(preset==='objects'){
      const objects=[...(opts.objects||[])].sort((a,b)=>(a.ui_quality==='ambiguous')-(b.ui_quality==='ambiguous'));
      fillSelect(objectSelect,objects,x=>x.id,x=>x.ui_quality==='ambiguous'?`Sin clasificar · ${x.identifier_field||'identifier'}=${x.identifier}`:`${x.object_type} ${x.identifier}`,graph.meta?.object_id,'Elige un objeto');
    }
  }

  const layerDefaults={
    surface:{operation:true,flow:false,object:false,request:false,identity:false,parameter:false,context:false},
    identity:{operation:false,flow:false,object:false,request:false,identity:true,parameter:false,context:false},
    flow:{operation:false,flow:true,object:false,request:true,identity:true,parameter:false,context:false},
    objects:{operation:false,flow:true,object:false,request:false,identity:true,parameter:false,context:false},
    // Discovery starts intentionally quiet: pivot + endpoints. Every extra
    // context dimension is opt-in so the graph answers one question at a time.
    discovery:{operation:false,flow:false,object:false,request:false,identity:false,parameter:false,context:false},
    context:{operation:false,flow:true,object:true,request:true,identity:true,parameter:true,context:true},
    intelligence:{operation:false,flow:true,object:true,request:false,identity:true,parameter:false,context:true}
  };
  const layerPrefs={};
  function layerEnabled(type){
    const bucket=layerPrefs[preset]||{};
    if(Object.prototype.hasOwnProperty.call(bucket,type))return !!bucket[type];
    return !!(layerDefaults[preset]?.[type]);
  }
  function layerStorageKey(){return `negro.graph.layers:${targetKey}:${preset}${preset==='discovery'?':focused-v2':''}`;}
  function setLayer(type,value){
    layerPrefs[preset]=layerPrefs[preset]||{};layerPrefs[preset][type]=!!value;
    try{localStorage.setItem(layerStorageKey(),JSON.stringify(layerPrefs[preset]));}catch(_){ }
  }
  function restoreLayerPrefs(){
    try{const v=JSON.parse(localStorage.getItem(layerStorageKey())||'{}');if(v&&typeof v==='object')layerPrefs[preset]={...v};}catch(_){ }
  }
  function configureLayerControls(){
    restoreLayerPrefs();
    const relevance={
      // Keep the same vocabulary of layers across views.  Each perspective has
      // a different default, but the hunter should not have to learn a different
      // filter system every time they change lens.
      surface:new Set(['identity','flow','object','parameter','context','request','operation']),
      identity:new Set(['flow','object','parameter','context','request','operation']),
      flow:new Set(['identity','object','parameter','context','request','operation']),
      objects:new Set(['identity','flow','parameter','context','request','operation']),
      discovery:new Set(['identity','flow','object','parameter','context','request','operation']),
      context:new Set(['identity','flow','object','parameter','context','request','operation']),
      intelligence:new Set([])
    }[preset]||new Set();
    if(layerControls)layerControls.hidden=relevance.size===0;
    if(discoveryCrossWrap)discoveryCrossWrap.hidden=preset!=='discovery';
    if(discoveryCrossOnlyInput)discoveryCrossOnlyInput.checked=discoveryCrossOnly;
    layerInputs.forEach(input=>{
      const typ=input.dataset.graphLayer;const wrap=root.querySelector(`[data-layer-wrap="${typ}"]`);
      if(wrap)wrap.hidden=!relevance.has(typ);
      input.checked=layerEnabled(typ);
    });
    if(flowViewSwitch)flowViewSwitch.hidden=!(preset==='flow'&&Number(graph.meta?.flow_id||0)>0);
    flowViewButtons.forEach(b=>b.classList.toggle('active',b.dataset.flowView===flowViewMode));
  }
  function discoveryResourceHasCross(n){
    if(n?.type!=='resource')return false;
    const pivot=graph.nodes.find(x=>x.type==='identifier');
    const owners=new Set((pivot?.meta?.owner_identity_ids||[]).map(Number));
    const reqs=Array.isArray(n.meta?.discovery_evidence?.requests)?n.meta.discovery_evidence.requests:[];
    if(reqs.some(r=>Number(r.identity_id||0)&&owners.size&&!owners.has(Number(r.identity_id))))return true;
    if(new Set(reqs.map(r=>Number(r.identity_id||0)).filter(Boolean)).size>1)return true;
    return (graph.meta?.discovery_branches||[]).some(b=>Number(b.resource_id||0)===Number(n.meta?.id||0));
  }

  function nodeLayerPasses(n){
    const isContextType=['investigation','lead','requirement','finding','observation','anomaly'].includes(n.type);
    if(preset==='surface'){
      if(['target','host','resource','javascript','source','cluster'].includes(n.type))return true;
      if(n.type==='operation')return layerEnabled('operation');
      if(n.type==='identity')return layerEnabled('identity');
      if(n.type==='flow')return layerEnabled('flow');
      if(n.type==='object')return layerEnabled('object');
      if(n.type==='parameter')return layerEnabled('parameter');
      if(n.type==='request')return layerEnabled('request');
      if(isContextType)return layerEnabled('context');
      return false;
    }
    if(preset==='identity'){
      if(n.type==='target'||n.type==='host'||n.type==='state'||n.type==='anomaly')return false;
      if(n.type==='resource'||n.type==='identity')return identityEndpointPass(n);
      if(n.type==='flow')return layerEnabled('flow');
      if(n.type==='object')return layerEnabled('object');
      if(n.type==='parameter')return layerEnabled('parameter');
      if(n.type==='request')return layerEnabled('request');
      if(n.type==='operation')return layerEnabled('operation');
      if(isContextType)return layerEnabled('context');
      return true;
    }
    if(preset==='flow'){
      if(n.type==='target'||n.type==='host'||n.type==='state'||n.type==='anomaly')return false;
      if(n.type==='flow')return true;
      if(n.type==='identity')return layerEnabled('identity');
      if(n.type==='request')return layerEnabled('request');
      if(n.type==='object')return layerEnabled('object');
      if(n.type==='parameter')return layerEnabled('parameter');
      if(n.type==='operation')return layerEnabled('operation');
      if(isContextType)return layerEnabled('context');
      return n.type!=='resource';
    }
    if(preset==='objects'){
      if(n.type==='target'||n.type==='host'||n.type==='state'||n.type==='anomaly')return false;
      if(n.type==='resource')return true;
      if(n.type==='identity')return layerEnabled('identity');
      if(n.type==='flow')return layerEnabled('flow');
      if(n.type==='request'||n.type==='operation'||n.type==='parameter')return layerEnabled(n.type);
      if(n.type==='object'){
        const focus=`object:${Number(graph.meta?.object_id||0)}`;return n.id===focus||layerEnabled('object');
      }
      if(isContextType)return layerEnabled('context');
      return true;
    }
    if(preset==='discovery'){
      if(n.type==='target'||n.type==='host'||n.type==='state'||n.type==='anomaly'||n.type==='session')return false;
      if(n.type==='identifier')return true;
      if(n.type==='resource')return !discoveryCrossOnly||discoveryResourceHasCross(n);
      if(n.type==='identity')return layerEnabled('identity');
      if(n.type==='flow')return layerEnabled('flow');
      if(n.type==='object')return layerEnabled('object');
      if(n.type==='parameter')return layerEnabled('parameter');
      if(['investigation','lead','requirement','finding','observation'].includes(n.type))return layerEnabled('context');
      if(n.type==='request')return layerEnabled('request');
      if(n.type==='operation')return layerEnabled('operation');
      return false;
    }
    return true;
  }

  function nodeFor(id){ return graph.nodes.find(n=>n.id===id) || sceneNodes.find(n=>n.id===id); }
  function relatedNodes(id, relation=null){
    return graph.edges.filter(e=>(e.source===id||e.target===id) && (!relation || e.relation===relation)).map(e=>nodeFor(opposite(e,id))).filter(Boolean);
  }
  function statusClass(status){ const n=Number(status||0); return n>=200&&n<300?'ok':n>=300&&n<400?'redirect':n>=400?'bad':'neutral'; }
  function requestContext(requestNode){
    const rels=graph.edges.filter(e=>e.source===requestNode.id||e.target===requestNode.id);
    const identities=[], objects=[];
    rels.forEach(e=>{
      const other=nodeFor(opposite(e,requestNode.id)); if(!other)return;
      if(other.type==='identity' && !identities.some(x=>x.id===other.id))identities.push(other);
      if(other.type==='object' && !objects.some(x=>x.id===other.id))objects.push(other);
    });
    const states=graph.nodes.filter(n=>n.type==='state' && Number(n.meta?.request_id||0)===Number(requestNode.meta?.id||0));
    return {identities,objects,states};
  }
  function bindNarrativeActions(){
    narrative?.querySelectorAll('[data-select-flow]').forEach(b=>b.addEventListener('click',()=>{if(flowSelect){flowSelect.value=String(b.dataset.selectFlow);flowSelect.dispatchEvent(new Event('change'));}}));
    narrative?.querySelectorAll('[data-select-identity]').forEach(b=>b.addEventListener('click',()=>{if(identitySelect){identitySelect.value=String(b.dataset.selectIdentity);identitySelect.dispatchEvent(new Event('change'));}}));
    narrative?.querySelectorAll('[data-select-object]').forEach(b=>b.addEventListener('click',()=>{if(objectSelect){objectSelect.value=String(b.dataset.selectObject);objectSelect.dispatchEvent(new Event('change'));}}));
    narrative?.querySelectorAll('[data-request-node]').forEach(b=>b.addEventListener('click',()=>{const n=nodeFor(b.dataset.requestNode);if(n){selected=n.id;showNode(n);}}));
    narrative?.querySelectorAll('[data-object-node]').forEach(b=>b.addEventListener('click',()=>{const n=nodeFor(b.dataset.objectNode);if(n){selected=n.id;showNode(n);}}));
    narrative?.querySelectorAll('[data-discover-value]').forEach(b=>b.addEventListener('click',()=>{const q=String(b.dataset.discoverValue||'').trim();if(!q)return;const btn=root.querySelector('[data-graph-preset="discovery"]');preset='discovery';root.querySelectorAll('[data-graph-preset]').forEach(x=>x.classList.toggle('active',x===btn));discoveryTrail=[q];openDiscoveryPivot(q,{push:false});}));
    narrative?.querySelectorAll('[data-open-graph-focus]').forEach(b=>b.addEventListener('click',()=>{
      const n=nodeFor(b.dataset.openGraphFocus); if(!n)return;
      narrative.hidden=true; canvasShell.hidden=false; selected=n.id; buildScene(); buildTypeFilters(); applyFilters({fitAfter:true}); showNode(n); focusNeighborhood(n.id,1);
    }));
  }
  function renderFlowNarrative(){
    const opts=graph.meta?.filter_options||{};
    const fid=Number(graph.meta?.flow_id||0);
    if(!fid){
      const rows=opts.flows||[];
      narrative.innerHTML=`<div class="narrative-head"><div><span class="eyebrow">FLOW</span><h2>Elige una historia</h2><p>Un Flow sólo tiene valor cuando puedes leer sus Requests en orden. No mostramos objetos ni líneas hasta que elijas uno.</p></div><a class="btn-secondary" href="${base}/flows">Administrar Flows</a></div><div class="narrative-card-grid">${rows.length?rows.map(f=>`<button class="narrative-choice" data-select-flow="${Number(f.id)}"><b>${esc(f.name)}</b><span>${Number(f.step_count||0)} pasos${f.capture_status==='capturing'?' · capturando':''}</span></button>`).join(''):`<div class="empty-state friendly"><b>No hay Flows todavía.</b><span>Captura una operación desde Burp o desde la pantalla Flows.</span><a href="${base}/flows">Crear Flow →</a></div>`}</div>`;
      bindNarrativeActions(); return;
    }
    const flow=nodeFor(`flow:${fid}`);
    const steps=graph.edges.filter(e=>e.source===`flow:${fid}`&&e.relation==='flow_step')
      .map(e=>({edge:e,node:nodeFor(e.target),position:Number(e.meta?.evidence?.position||999999)})).filter(x=>x.node).sort((a,b)=>a.position-b.position);
    const actor=flow?.meta?.identity||relatedNodes(`flow:${fid}`,'flow_actor')[0]?.label||'';
    const stepHtml=steps.map((x,idx)=>{
      const n=x.node,m=n.meta||{},ctx=requestContext(n);
      const objs=ctx.objects.filter(o=>o.meta?.ui_quality!=='ambiguous');
      const identity=ctx.identities[0]?.label||actor||'';
      const states=ctx.states.map(st=>`<span class="story-chip state">${esc(st.meta?.field||'state')}: ${esc(st.label)}</span>`).join('');
      const objectChips=objs.slice(0,4).map(o=>`<button type="button" class="story-chip object" data-object-node="${esc(o.id)}">${esc(o.label)}</button>`).join('');
      const intel=nodeIntelligence(n);
      return `<article class="flow-story-step${intel.hasAny?' has-intelligence':''}"><div class="flow-story-rail"><span>${idx+1}</span>${idx<steps.length-1?'<i></i>':''}</div><div class="flow-story-card"><div class="flow-story-request"><div><b>${esc(m.method||'REQUEST')}</b><code>${esc(m.path||n.label)}</code>${intelligenceBadgesHtml(n)}</div><span class="http-status ${statusClass(m.status)}">${esc(m.status??'—')}</span></div><div class="flow-story-meta">${m.host?`<span>${esc(m.host)}</span>`:''}${identity?`<span>👤 ${esc(identity)}</span>`:''}<span>Request #${Number(m.id||0)}</span></div>${objectChips||states?`<div class="flow-story-context">${objectChips}${states}</div>`:''}<div class="flow-story-actions"><button type="button" class="btn-secondary" data-request-node="${esc(n.id)}">Ver Request</button>${objs.length?`<button type="button" class="btn-secondary" data-open-graph-focus="${esc(objs[0].id)}">Ver relaciones de ${esc(objs[0].label)}</button>${objs[0].meta?.identifier?`<button type="button" class="btn-secondary" data-discover-value="${esc(objs[0].meta.identifier)}">Descubrir dónde más aparece</button>`:''}`:''}</div></div></article>`;
    }).join('');
    narrative.innerHTML=`<div class="narrative-head"><div><span class="eyebrow">FLOW · HISTORIA</span><h2>${esc(flow?.label||`Flow ${fid}`)}</h2><p>${actor?`Actor observado: <b>${esc(actor)}</b> · `:''}${steps.length} Requests incluidas. Lee de arriba hacia abajo.</p></div><div class="narrative-actions"><a class="btn-secondary" href="${base}/flows/${fid}">Editar Flow</a><a class="btn-secondary" href="${base}/flows/compare?a=${fid}">Comparar</a></div></div>${stepHtml?`<div class="flow-story">${stepHtml}</div>`:`<div class="empty-state friendly"><b>Este Flow no tiene Requests incluidas.</b><span>Abre el Flow y marca qué pasos forman realmente la historia.</span></div>`}`;
    bindNarrativeActions();
  }
  function objectContextLabel(o){
    const m=o?.meta||{};
    if(m.ui_quality==='ambiguous') return `${m.identifier_field||'identifier'}=${m.identifier||o?.label||'?'}`;
    return o?.label||`${m.object_type||'Object'} ${m.identifier||''}`;
  }
  function requestNarrativeCard(n,{compact=false}={}){
    if(!n)return '';
    const m=n.meta||{},ctx=requestContext(n);
    const meaningful=ctx.objects.filter(o=>o.meta?.ui_quality!=='ambiguous');
    const contextual=ctx.objects.filter(o=>o.meta?.ui_quality==='ambiguous');
    const states=ctx.states||[];
    const semantic=meaningful.slice(0,4).map(o=>`<button type="button" class="story-chip object" data-object-node="${esc(o.id)}">${esc(objectContextLabel(o))}</button>`).join('');
    const context=contextual.slice(0,5).map(o=>`<span class="story-chip context">${esc(objectContextLabel(o))}</span>`).join('');
    const stateHtml=states.slice(0,4).map(st=>`<span class="story-chip state">${esc(st.meta?.field||'state')}: ${esc(st.label)}</span>`).join('');
    return `<article class="identity-request-card${compact?' compact':''}"><div class="identity-request-main"><div><b>${esc(m.method||'REQUEST')}</b><code>${esc(m.path||n.label)}</code></div><span class="http-status ${statusClass(m.status)}">${esc(m.status??'—')}</span></div><div class="flow-story-meta">${m.host?`<span>${esc(m.host)}</span>`:''}<span>Request #${Number(m.id||0)}</span></div>${semantic?`<div class="request-context-line"><small>Objetos claros</small>${semantic}</div>`:''}${context?`<div class="request-context-line muted-context"><small>Campos / contexto observado</small>${context}</div>`:''}${stateHtml?`<div class="request-context-line"><small>Estados</small>${stateHtml}</div>`:''}<div class="flow-story-actions"><button type="button" class="btn-secondary" data-request-node="${esc(n.id)}">Ver Request</button>${n.href?`<a class="btn-secondary" href="${base}/${esc(n.href)}">Abrir HTTP</a>`:''}</div></article>`;
  }
  function renderIdentityIndex(){
    const rows=graph.meta?.filter_options?.identities||[];
    narrative.innerHTML=`<div class="narrative-head"><div><span class="eyebrow">IDENTIDAD · QUIÉN</span><h2>Elige una cuenta o sesión</h2><p>Negro no presupone Buyer, Seller ni Admin. Tú defines las identidades de cada negocio.</p></div><a class="btn-secondary" href="${base}/identities">Administrar identidades</a></div><div class="narrative-card-grid">${rows.length?rows.map(i=>`<button class="narrative-choice" data-select-identity="${Number(i.id)}"><b>${esc(i.name)}</b><span>${Number(i.request_count||0)} Requests observadas${i.kind?` · ${esc(i.kind)}`:''}</span></button>`).join(''):`<div class="empty-state friendly"><b>No hay identidades todavía.</b><span>Crea una desde una Request de Burp o desde Identidades.</span><a href="${base}/identities">Crear identidad →</a></div>`}</div>`;
    bindNarrativeActions();
  }
  function renderIdentityNarrative(){
    const ids=[Number(graph.meta?.identity_id||0),Number(graph.meta?.compare_identity_id||0)].filter(Boolean);
    if(!ids.length)return renderIdentityIndex();
    const sections=ids.map(iid=>{
      const inode=nodeFor(`identity:${iid}`); if(!inode)return '';
      const requests=graph.edges.filter(e=>e.source===inode.id&&e.relation==='performed').map(e=>nodeFor(e.target)).filter(n=>n?.type==='request');
      const unique=[];const seen=new Set(); requests.forEach(n=>{if(!seen.has(n.id)){seen.add(n.id);unique.push(n);}});
      const flows=relatedNodes(inode.id).filter(n=>n.type==='flow');
      return `<section class="identity-story-section"><div class="identity-story-head"><div><span class="eyebrow">IDENTIDAD</span><h2>${esc(inode.label)}</h2><p>${unique.length} Requests atribuidas${flows.length?` · ${flows.length} Flow(s) relacionados`:''}. Aquí el endpoint es protagonista; los IDs sólo aparecen con la key que les dio contexto.</p></div><div class="narrative-actions"><a class="btn-secondary" href="${base}/identities/view/${iid}">Abrir identidad</a><button type="button" class="btn-secondary" data-open-current-graph>Ver relaciones gráficas · avanzado</button></div></div>${flows.length?`<div class="identity-flow-strip"><small>Flows observados</small>${flows.slice(0,10).map(f=>`<a href="${base}/${esc(f.href||`flows/${f.meta?.id||''}`)}">${esc(f.label)}</a>`).join('')}</div>`:''}<div class="identity-request-list">${unique.length?unique.map(n=>requestNarrativeCard(n)).join(''):`<div class="empty-state friendly"><b>No hay Requests atribuidas a esta identidad.</b><span>Asigna una Request desde Burp o revisa sus resolvers.</span></div>`}</div></section>`;
    }).join('');
    narrative.innerHTML=`<div class="narrative-head"><div><span class="eyebrow">IDENTIDAD · QUÉ HIZO</span><h2>${ids.length>1?'Compara el tráfico de dos identidades':'Requests de la identidad'}</h2><p>Primero mira <b>método + endpoint + HTTP status</b>. Los objetos ambiguos se muestran sólo como <code>key=value</code>, no como entidades inventadas.</p></div><a class="btn-secondary" href="${base}/guide#identities">Cómo leer esta vista</a></div><div class="identity-story-grid ${ids.length>1?'compare':''}">${sections}</div>`;
    bindNarrativeActions();
    narrative.querySelectorAll('[data-open-current-graph]').forEach(b=>b.addEventListener('click',()=>{narrative.hidden=true;canvasShell.hidden=false;buildScene();buildTypeFilters();applyFilters({fitAfter:true});}));
  }
  function renderObjectIndex(){
    const rows=graph.meta?.filter_options?.objects||[];
    const good=rows.filter(o=>o.ui_quality!=='ambiguous'), noisy=rows.filter(o=>o.ui_quality==='ambiguous');
    const card=o=>{const label=o.ui_quality==='ambiguous'?`${o.identifier_field||'identifier'}=${o.identifier}`:`${o.object_type} ${o.identifier}`;return `<button class="narrative-choice" data-select-object="${Number(o.id)}"><b>${esc(label)}</b><span>${o.ui_quality==='ambiguous'?'sin clasificar · ':''}último: ${esc(o.last_seen_at||'—')}</span></button>`;};
    narrative.innerHTML=`<div class="narrative-head"><div><span class="eyebrow">OBJETO · QUÉ COSA</span><h2>Elige una cosa con significado</h2><p>Prioriza <b>Order 123</b>, <b>User 101</b>, <b>Invoice 77</b>. Si sólo conocemos una key, Negro la muestra como <code>order_id=4101</code> en vez de inventar un nombre.</p></div><a class="btn-secondary" href="${base}/objects">Administrar objetos</a></div><div class="narrative-card-grid">${good.length?good.slice(0,80).map(card).join(''):`<div class="empty-state friendly"><b>No hay objetos suficientemente claros.</b><span>Enseña un tipo de dominio inequívoco, por ejemplo <code>orderId → Order</code>.</span><a href="${base}/objects">Revisar objetos →</a></div>`}</div>${noisy.length?`<details class="noisy-object-list"><summary>Mostrar ${noisy.length} identificadores sin clasificar</summary><p>Negro conserva la evidencia, pero no afirma que estos valores sean User, Order u otra entidad hasta que tú lo confirmes.</p><div class="narrative-card-grid">${noisy.slice(0,60).map(card).join('')}</div></details>`:''}`;
    bindNarrativeActions();
  }
  function renderObjectNarrative(){
    const oid=Number(graph.meta?.object_id||0); if(!oid)return renderObjectIndex();
    const obj=nodeFor(`object:${oid}`); if(!obj)return renderObjectIndex();
    const m=obj.meta||{};
    const requests=graph.edges.filter(e=>(e.source===obj.id||e.target===obj.id)&&e.relation==='touches').map(e=>nodeFor(opposite(e,obj.id))).filter(n=>n?.type==='request');
    const unique=[];const seen=new Set();requests.forEach(n=>{if(!seen.has(n.id)){seen.add(n.id);unique.push(n);}});
    const related=graph.edges.filter(e=>(e.source===obj.id||e.target===obj.id)&&e.relation==='co_observed').map(e=>nodeFor(opposite(e,obj.id))).filter(n=>n?.type==='object');
    const meaningful=related.filter(o=>o.meta?.ui_quality!=='ambiguous'), ambiguous=related.filter(o=>o.meta?.ui_quality==='ambiguous');
    const flows=relatedNodes(obj.id).filter(n=>n.type==='flow');
    const states=relatedNodes(obj.id,'state_observed').filter(n=>n.type==='state');
    const title=m.ui_quality==='ambiguous'?`${m.identifier_field||'identifier'} = ${m.identifier||'?'}`:obj.label;
    const intro=m.ui_quality==='ambiguous'?`<div class="callout warning object-meaning-warning"><b>Esto todavía no es una entidad entendida.</b> Negro sólo sabe que la key <code>${esc(m.identifier_field||'identifier')}</code> tuvo el valor <code>${esc(m.identifier||'?')}</code> y apareció en estas Requests. No asumas que representa User, Role, Order, etc. hasta clasificarla.</div>`:`<div class="object-meaning-line"><span>Tipo</span><b>${esc(m.object_type||'Object')}</b><span>Campo observado</span><code>${esc(m.identifier_field||'—')}</code><span>Valor</span><code>${esc(m.identifier||'—')}</code></div>`;
    const relationCards=meaningful.map(o=>`<button type="button" class="narrative-choice mini" data-select-object="${Number(o.meta?.id||String(o.id).split(':')[1]||0)}"><b>${esc(objectContextLabel(o))}</b><span>objeto relacionado observado</span></button>`).join('');
    const noisy=ambiguous.map(o=>`<span class="story-chip context">${esc(objectContextLabel(o))}</span>`).join('');
    narrative.innerHTML=`<div class="narrative-head"><div><span class="eyebrow">OBJETO · CONTEXTO</span><h2>${esc(title)}</h2><p>${unique.length} Requests · ${Number(m.hosts||0)} host(s). La pregunta aquí es: <b>¿dónde apareció este valor y qué pasó alrededor?</b></p></div><div class="narrative-actions"><a class="btn-secondary" href="${base}/objects/${oid}">Abrir ficha completa</a>${m.identifier?`<button type="button" class="btn-secondary" data-discover-value="${esc(m.identifier)}">Descubrir dónde más aparece</button>`:''}<button type="button" class="btn-secondary" data-open-current-graph>Ver relaciones gráficas · avanzado</button></div></div>${intro}${states.length?`<div class="object-state-story"><small>Estados observados</small>${states.map(st=>`<span class="story-chip state">${esc(st.meta?.field||'state')}: ${esc(st.label)}</span>`).join('')}</div>`:''}<section class="narrative-section"><div class="section-heading"><span class="eyebrow">DÓNDE APARECIÓ</span><h2>Requests que contienen o tocan este valor</h2></div><div class="identity-request-list">${unique.length?unique.map(n=>requestNarrativeCard(n,{compact:true})).join(''):`<div class="empty-state friendly"><b>No hay Requests enlazadas.</b><span>La evidencia del objeto puede necesitar una reconstrucción.</span></div>`}</div></section>${flows.length?`<section class="narrative-section"><div class="section-heading"><span class="eyebrow">FLOWS</span><h2>Historias donde apareció</h2></div><div class="identity-flow-strip">${flows.map(f=>`<a href="${base}/${esc(f.href||`flows/${f.meta?.id||''}`)}">${esc(f.label)}</a>`).join('')}</div></section>`:''}${meaningful.length?`<section class="narrative-section"><div class="section-heading"><span class="eyebrow">RELACIONES ÚTILES</span><h2>Objetos con significado vistos junto a éste</h2></div><div class="narrative-card-grid">${relationCards}</div></section>`:''}${ambiguous.length?`<details class="noisy-object-list"><summary>Mostrar ${ambiguous.length} relaciones sin clasificar</summary><p>Se muestran como <code>key=value</code> porque todavía no sabemos qué entidad representan.</p><div class="request-context-line muted-context">${noisy}</div></details>`:''}`;
    bindNarrativeActions();
    narrative.querySelector('[data-open-current-graph]')?.addEventListener('click',()=>{narrative.hidden=true;canvasShell.hidden=false;selected=obj.id;buildScene();buildTypeFilters();applyFilters({fitAfter:true});showNode(obj);focusNeighborhood(obj.id,1);});
  }
  function renderIntelligenceNarrative(){
    const cards=graph.nodes.filter(n=>['anomaly','lead','finding'].includes(n.type));
    const order={finding:0,anomaly:1,lead:2}; cards.sort((a,b)=>(order[a.type]??9)-(order[b.type]??9));
    const html=cards.map(n=>{
      const m=n.meta||{}; const parents=graph.edges.filter(e=>e.target===n.id||e.source===n.id).map(e=>nodeFor(opposite(e,n.id))).filter(Boolean).filter(x=>!['target'].includes(x.type));
      const why=m.message||m.why||''; const next=m.next_test||'';
      return `<article class="attention-card attention-${esc(n.type)}"><div class="attention-card-head"><span>${n.type==='finding'?'HALLAZGO':n.type==='anomaly'?'DIFERENCIA OBSERVADA':'HIPÓTESIS'}</span><b>${esc(n.label)}</b></div>${why?`<p>${esc(why)}</p>`:''}${parents.length?`<div class="attention-context">Contexto: ${parents.slice(0,3).map(x=>`<code>${esc(x.label)}</code>`).join(' ')}</div>`:''}${m.baseline||m.current?`<div class="attention-diff">${m.baseline?`<span><small>Patrón</small>${esc(m.baseline)}</span>`:''}${m.current?`<span><small>Observado</small>${esc(m.current)}</span>`:''}</div>`:''}${next?`<p><b>Siguiente prueba:</b> ${esc(next)}</p>`:''}<div class="flow-story-actions">${n.href?`<a class="btn-secondary" href="${base}/${esc(n.href)}">Abrir detalle</a>`:''}</div></article>`;
    }).join('');
    narrative.innerHTML=`<div class="narrative-head"><div><span class="eyebrow">ATENCIÓN</span><h2>Sólo lo que merece una segunda mirada</h2><p>Esta vista es deliberadamente corta: diferencias, hipótesis activas y hallazgos. Nada de superficie completa.</p></div><a class="btn-secondary" href="${base}/hypotheses">Abrir Hunt</a></div><div class="attention-board">${html||`<div class="empty-state friendly"><b>No hay señales prioritarias.</b><span>Sigue navegando y probando; Negro mostrará aquí únicamente diferencias o investigaciones con contexto.</span></div>`}</div>`;
  }
  function openDiscoveryPivot(query,{push=true}={}){
    const q=String(query||'').trim();
    if(!q)return Promise.resolve();
    const discoveryBtn=root.querySelector('[data-graph-preset="discovery"]');
    root.querySelectorAll('[data-graph-preset]').forEach(x=>x.classList.toggle('active',x===discoveryBtn));
    preset='discovery';
    try{discoveryPreviousSeen=localStorage.getItem(`negro.graph.discovery.seen:${targetKey}:${q}`)||'';}catch(_){discoveryPreviousSeen='';}
    if(push){
      if(!discoveryTrail.length && String(graph.meta?.discovery_query||'').trim()) discoveryTrail=[String(graph.meta.discovery_query).trim()];
      if(discoveryTrail[discoveryTrail.length-1]!==q) discoveryTrail.push(q);
    }
    if(discoveryQuery) discoveryQuery.value=q;
    return load(`${api}?scope=discovery&q=${encodeURIComponent(q)}&exchanges=180`).then(()=>{
      preset='discovery';populateContextControls();renderExperience();
    });
  }

  function renderDiscoveryInsights(){
    if(!discoveryInsights)return;
    const active=preset==='discovery';
    if(discoveryTrailBar)discoveryTrailBar.hidden=!active;
    if(discoveryInsightsToggle)discoveryInsightsToggle.hidden=!active;
    if(!active){
      discoveryInsights.hidden=true;discoveryInsights.innerHTML='';
      renderGenericTrail();
      return;
    }
    const query=String(graph.meta?.discovery_query||'').trim();
    const items=Array.isArray(graph.meta?.discovery_insights)?graph.meta.discovery_insights:[];
    const branches=Array.isArray(graph.meta?.discovery_branches)?graph.meta.discovery_branches:[];
    const evidenceRequests=[];
    (graph.nodes||[]).forEach(n=>{const reqs=n?.meta?.discovery_evidence?.requests;if(Array.isArray(reqs))reqs.forEach(r=>evidenceRequests.push(r));});
    if(!discoveryPreviousSeen){try{discoveryPreviousSeen=localStorage.getItem(`negro.graph.discovery.seen:${targetKey}:${query}`)||'';}catch(_){}}
    const newRequests=discoveryPreviousSeen?evidenceRequests.filter(r=>String(r.seen_at||'')>discoveryPreviousSeen):[];
    const maxSeen=evidenceRequests.map(r=>String(r.seen_at||'')).filter(Boolean).sort().pop()||'';
    const insightCount=items.length+branches.length+(newRequests.length?1:0);
    if(discoveryInsightsCount)discoveryInsightsCount.textContent=String(insightCount);

    if(!query){
      if(discoveryTrailBar)discoveryTrailBar.innerHTML='<span class="muted">Busca una key o valor para iniciar una ruta de exploración.</span>';
      discoveryInsights.innerHTML='<button type="button" class="graph-insights-close" data-discovery-insights-close aria-label="Cerrar insights">×</button><div><span class="eyebrow">DESCUBRIR</span><b>Empieza por una pieza concreta</b><p>Escribe una key o valor arriba. Negro abrirá dónde reaparece y qué relaciones puede ayudarte a seguir.</p></div>';
      discoveryInsights.hidden=!discoveryInsightsOpen;
      discoveryInsights.querySelector('[data-discovery-insights-close]')?.addEventListener('click',()=>{discoveryInsightsOpen=false;renderDiscoveryInsights();});
      return;
    }
    if(!discoveryTrail.length)discoveryTrail=[query];
    const crumbs=discoveryTrail.map((x,i)=>`<button type="button" data-discovery-crumb="${i}" class="discovery-crumb ${i===discoveryTrail.length-1?'active':''}">${esc(x)}</button>`).join('<span>→</span>');
    if(discoveryTrailBar){
      discoveryTrailBar.innerHTML=`<span>Ruta de exploración</span><div>${crumbs}</div>`;
      discoveryTrailBar.querySelectorAll('[data-discovery-crumb]').forEach(btn=>btn.addEventListener('click',()=>{
        const idx=Number(btn.dataset.discoveryCrumb||0);const q=discoveryTrail[idx];if(!q)return;discoveryTrail=discoveryTrail.slice(0,idx+1);openDiscoveryPivot(q,{push:false});
      }));
    }
    const branchHtml=branches.length?`<div class="discovery-branches"><div class="discovery-branch-head"><b>Ramas todavía no comparadas · ${branches.length}</b><span>No son fallos: son operaciones observadas sobre esta pieza que aún no vimos bajo una identidad donde la lectura fue denegada.</span></div>${branches.slice(0,10).map(x=>`<article class="discovery-branch"><div><span class="state-chip state-untested">NO OBSERVADA</span><b>${esc(x.identity_name||'Identidad')} → ${esc(x.method||'')} ${esc(x.path||'')}</b><p>${esc(x.reason||'')}</p>${(x.observed_under||[]).length?`<small>Observada hasta ahora bajo: ${esc(x.observed_under.join(', '))}</small>`:''}</div><button type="button" class="btn-secondary" data-discover-branch-resource="${Number(x.resource_id||0)}">Ver endpoint</button></article>`).join('')}</div>`:'';
    const newHtml=newRequests.length?`<div class="discovery-new-context"><b>Nuevo desde tu última visita · ${new Set(newRequests.map(x=>Number(x.id||0))).size} Request(s)</b><span>Esta pieza volvió a aparecer desde la última vez que abriste este pivote. Revisa si conectó un endpoint, identidad o Flow nuevo.</span></div>`:'';
    discoveryInsights.innerHTML=`<button type="button" class="graph-insights-close" data-discovery-insights-close aria-label="Cerrar insights">×</button>${newHtml}<div class="discovery-insight-head"><span class="eyebrow">INSIGHTS · ${esc(query)}</span><b>Contexto determinista; no son conclusiones de vulnerabilidad</b></div><div class="discovery-insight-grid">${items.length?items.map(x=>`<article class="discovery-insight kind-${esc(x.kind||'context')}"><b>${esc(x.title||'Contexto')}</b><p>${esc(x.detail||'')}</p></article>`).join(''):'<article class="discovery-insight"><b>Sin patrón especial todavía</b><p>El grafo conserva las apariciones y relaciones observadas sin inventar una conclusión.</p></article>'}</div>${branchHtml}`;
    discoveryInsights.hidden=!discoveryInsightsOpen;
    discoveryInsights.querySelector('[data-discovery-insights-close]')?.addEventListener('click',()=>{discoveryInsightsOpen=false;renderDiscoveryInsights();});
    discoveryInsights.querySelectorAll('[data-discover-branch-resource]').forEach(btn=>btn.addEventListener('click',()=>{
      const id=Number(btn.dataset.discoverBranchResource||0);const n=graph.nodes.find(x=>x.id===`resource:${id}`);if(n){selected=n.id;showNode(n);render();focusNeighborhood(n.id,1);}
    }));
    if(maxSeen){try{localStorage.setItem(`negro.graph.discovery.seen:${targetKey}:${query}`,maxSeen);}catch(_){}}
  }

  function renderGenericTrail(){
    if(!discoveryTrailBar || preset==='discovery')return;
    const m=graph.meta||{};
    const labels={surface:'Superficie',identity:'Identidad',flow:'Flujo',objects:'Objeto',context:'Investigation',intelligence:'Atención',untested:'Pendientes',interesting:'Interesante',burp:'Burp',attack:'Qué probar',all:'Vista técnica'};
    const crumbs=[labels[preset]||valueLabel(preset)];
    const opts=m.filter_options||{};
    if(preset==='identity'&&Number(m.identity_id||0)){
      const a=(opts.identities||[]).find(x=>Number(x.id)===Number(m.identity_id)); if(a)crumbs.push(a.name);
      if(Number(m.compare_identity_id||0)){const b=(opts.identities||[]).find(x=>Number(x.id)===Number(m.compare_identity_id));if(b)crumbs.push(`vs ${b.name}`);}
    }
    if(preset==='flow'&&Number(m.flow_id||0)){const f=(opts.flows||[]).find(x=>Number(x.id)===Number(m.flow_id));if(f)crumbs.push(f.name);}
    if(preset==='objects'&&Number(m.object_id||0)){const o=(opts.objects||[]).find(x=>Number(x.id)===Number(m.object_id));if(o)crumbs.push(`${o.object_type||'Objeto'} ${o.identifier||''}`.trim());}
    if(['surface','untested','interesting','all','burp','attack'].includes(preset)){
      if(m.host_label||m.hostname)crumbs.push(m.host_label||m.hostname);
      if(m.resource_label||m.path)crumbs.push(m.resource_label||m.path);
    }
    if(selected){const n=sceneNodes.find(x=>x.id===selected)||graph.nodes.find(x=>x.id===selected);if(n&&!crumbs.includes(n.label))crumbs.push(n.label);}
    discoveryTrailBar.hidden=false;
    discoveryTrailBar.innerHTML=`<span>Ruta</span><div>${crumbs.map((x,i)=>`<span class="discovery-crumb ${i===crumbs.length-1?'active':''}">${esc(x)}</span>`).join('<span>→</span>')}</div>`;
  }

  function renderExperience(){
    if(!narrative||!canvasShell)return;
    configureLayerControls();
    renderDiscoveryInsights();
    const hasIdentity=Number(graph.meta?.identity_id||0)>0;
    const hasFlow=Number(graph.meta?.flow_id||0)>0;
    const hasObject=Number(graph.meta?.object_id||0)>0;
    const showNarrative = preset==='intelligence' ||
      (preset==='identity'&&!hasIdentity) ||
      (preset==='objects'&&!hasObject) ||
      (preset==='flow'&&(!hasFlow||flowViewMode==='timeline'));
    narrative.hidden=!showNarrative; canvasShell.hidden=showNarrative;
    const explanations={
      surface:['Superficie','Hosts y endpoints primero. Los métodos se pueden ocultar o mostrar sin perder la ruta.'],
      identity:['Identidad','Identidades a los lados, endpoints en el centro. Los objetos son contexto opcional, no protagonistas.'],
      flow:['Flow','Alterna entre grafo y línea de tiempo. En ambos casos la secuencia y los endpoints deben ser evidentes.'],
      objects:['Objeto','Objeto focal → endpoints donde apareció → identidades/Flows relacionados. Los objetos secundarios son opcionales.'],
      discovery:['Descubrir','Sigue una key o valor y abre dónde reaparece, bajo qué nombres, identidades, Flows y objetos cercanos.'],
      context:['Investigation','Contexto acumulado de una rama. Úsalo para entender conexiones, no para mostrar toda la superficie.'],
      intelligence:['Atención','Sólo diferencias, hipótesis y hallazgos que justifican volver a mirar.']
    };
    const x=explanations[preset]||[valueLabel(preset),'Vista avanzada']; if(viewExplainer)viewExplainer.innerHTML=`<b>${esc(x[0])}</b><p>${esc(x[1])}</p>`;
    if(showNarrative){
      if(preset==='flow')renderFlowNarrative();
      else if(preset==='identity')renderIdentityNarrative();
      else if(preset==='objects')renderObjectIndex();
      else if(preset==='intelligence')renderIntelligenceNarrative();
    } else {
      buildScene();buildTypeFilters();applyFilters({fitAfter:true});
      const focus=graph.meta?.focus_node;
      if(focus){selected=focus;const n=sceneNodes.find(x=>x.id===focus)||graph.nodes.find(x=>x.id===focus);if(n)showNode(n);}
    }
  }

  function scopeKey(){ const m=graph.meta||{}; return `${m.scope||'overview'}:${m.host_id||0}:${m.resource_id||0}`; }
  function layoutStorageKey(){ return `negro.graph.layout.v3:${targetKey}:${scopeKey()}:${preset}`; }
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

  function load(url=null){
    const endpoint=url || `${api}?scope=overview`;
    detail.innerHTML = `<div class="graph-detail-empty"><div class="graph-detail-icon">⌁</div><h3>Cargando mapa…</h3><p>Negro está trayendo sólo la capa necesaria.</p></div>`;
    return fetch(endpoint, {headers:{'Accept':'application/json'}})
      .then(r => { if(!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then(data => {
        graph = data; selected=null; activeRoute=null; pathStart=null; activePathIds=[];activePathEdgeIds=new Set();expandedClusters.clear();if(pathClearBtn)pathClearBtn.hidden=true;
        initLeadFilters();
        if(scopeStatusEl){ const m=graph.meta||{}; scopeStatusEl.textContent=m.scope_label || 'Vista general'; }
        populateContextControls();
        buildScene(); buildTypeFilters(); buildLeadFilters(); updateLeadFilterVisibility(); applyFilters({fitAfter:true});
        renderRoutes();
        renderExperience();
        detail.innerHTML=emptyDetail();
      })
      .catch(err => { detail.innerHTML = `<div class="graph-detail-empty"><h3>No se pudo cargar el mapa</h3><p>${esc(err.message)}</p></div>`; });
  }

  function navigateScope(n){
    if(!n || n.virtual) return;
    if(n.type==='host' && n.meta?.id){ load(`${api}?scope=host&host_id=${encodeURIComponent(n.meta.id)}`); return; }
    if(n.type==='resource' && n.meta?.id){ load(`${api}?scope=resource&resource_id=${encodeURIComponent(n.meta.id)}`); return; }
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

    if (['identity','flow','objects','discovery','intelligence','context'].includes(preset)) {
      const selectedIdentity=Number(graph.meta?.identity_id||0)>0;
      const selectedObject=Number(graph.meta?.object_id||0)>0;
      const allowed = preset==='identity' && selectedIdentity
        ? new Set(['identity','flow','request','resource','operation','object','state','anomaly'])
        : preset==='objects' && selectedObject
          ? new Set(['identity','flow','request','resource','operation','object','state','anomaly'])
          : preset==='discovery'
            ? new Set(['identifier','parameter','identity','flow','request','resource','operation','object','state','requirement','lead','finding'])
          : preset==='context'
            ? new Set(['investigation','identifier','parameter','identity','flow','request','resource','object','state','requirement','lead','finding','observation'])
            : null;
      graph.nodes.filter(n=>!allowed||allowed.has(n.type)).forEach(addNode);
      graph.edges.filter(e => include.has(e.source) && include.has(e.target)).forEach(addEdge);
    } else if (preset === 'surface' || preset === 'resources') {
      graph.nodes.filter(n => ['target','host','resource','operation','cluster'].includes(n.type)).forEach(addNode);
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
    } else if (preset === 'interesting') {
      // "Interesante" answers: where are the signals?  It shows resources,
      // hypotheses and findings with just enough ancestry to understand context,
      // but it does not turn every raw Burp request into part of a route.
      const seeds = graph.nodes.filter(n => n.type!=='observation' && (
        n.type==='finding' || (n.type==='lead' && leadPassesFilters(n)) ||
        (n.type!=='lead' && (n.state==='finding' || n.state==='interesting'))
      ));
      seeds.forEach(n => addWithAncestors(n.id,5));
      graph.nodes.filter(n=>n.type==='observation' && ['interesting','finding'].includes(slugState(n.state))).forEach(obs=>{
        const parentEdge=graph.edges.find(e=>e.target===obs.id);
        if(parentEdge) addWithAncestors(parentEdge.source,4);
      });
      graph.edges.filter(e => include.has(e.source)&&include.has(e.target)).forEach(addEdge);
    } else if (preset === 'attack') {
      // "Rutas de investigación" is intentionally narrower than Interesante:
      // only evidence-backed routes currently surviving the hypothesis filters.
      const routes=(graph.routes||[]).filter(routePassesFilters);
      routes.forEach(route=>{
        (route.node_ids||[]).forEach(id=>{const n=rawMap.get(id);if(n)addNode(n);});
      });
      // Add structural ancestors needed to read the path, then keep only edges
      // between nodes participating in at least one route/ancestor chain.
      [...include].forEach(id=>addWithAncestors(id,4));
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
    if(preset==='discovery'){
      // Keep the discovery graph semantic and sparse. The default is only
      // pivot → endpoints; optional layers add one relation family at a time.
      const allowed=new Set(['appeared_in_endpoint']);
      if(layerEnabled('identity'))['called_endpoint','owns_observed'].forEach(x=>allowed.add(x));
      if(layerEnabled('flow'))['seen_in_flow','flow_endpoint','participates_in','flow_actor'].forEach(x=>allowed.add(x));
      if(layerEnabled('object'))['represented_as_object','touches','touches_object','observed_object'].forEach(x=>allowed.add(x));
      if(layerEnabled('parameter'))allowed.add('co_observed_key');
      if(layerEnabled('context'))['requires','unblocked','provided_context','supports_hypothesis','evidence_for','contains'].forEach(x=>allowed.add(x));
      if(layerEnabled('request'))['observed_in','observed_request','performed'].forEach(x=>allowed.add(x));
      sceneEdges=sceneEdges.filter(e=>allowed.has(e.relation));
    }
    if(preset==='flow' && Number(graph.meta?.flow_id||0)>0){
      const stepEdges=sceneEdges.filter(e=>e.relation==='flow_step').sort((a,b)=>Number(a.meta?.evidence?.position||999999)-Number(b.meta?.evidence?.position||999999));
      const keepFirst=stepEdges[0]?.id;
      const flowNode=`flow:${Number(graph.meta?.flow_id||0)}`;
      const actorIds=[...new Set(sceneEdges.filter(e=>e.relation==='performed').map(e=>e.source).filter(id=>String(id).startsWith('identity:')))];
      sceneEdges=sceneEdges.filter(e=>(e.relation!=='flow_step'||e.id===keepFirst)&&e.relation!=='performed');
      actorIds.forEach(id=>{if(!sceneEdges.some(e=>(e.source===id&&e.target===flowNode)||(e.target===id&&e.source===flowNode)))sceneEdges.push({id:edgeId(id,flowNode,'flow_actor'),source:id,target:flowNode,relation:'flow_actor',meta:{source:'flow_projection'}});});
    }
    autoLayout();
  }

  function laneFor(n){
    if (preset === 'context') return {target:0,investigation:1,lead:2,requirement:3,identifier:3,identity:2,flow:2,resource:3,request:4,object:4,state:5,finding:5,observation:4}[n.type] ?? 5;
    if (preset === 'discovery') return {target:0,identifier:1,parameter:2,identity:2,flow:2,resource:3,object:3,request:4,operation:4,state:5,lead:5,finding:5}[n.type] ?? 5;
    if (preset === 'identity') return {target:0,identity:1,flow:2,request:3,object:4,state:5,anomaly:5,host:5,resource:5}[n.type] ?? 5;
    if (preset === 'flow') return {target:0,flow:1,identity:2,request:3,object:4,state:5,anomaly:5,host:5}[n.type] ?? 5;
    if (preset === 'objects') return {target:0,identity:1,flow:1,object:2,request:3,state:3,anomaly:4,host:4}[n.type] ?? 4;
    if (preset === 'intelligence') return {target:0,host:1,resource:2,object:2,request:3,lead:3,anomaly:3,finding:4,identity:1,flow:1,state:3}[n.type] ?? 4;
    if (preset === 'surface' || preset === 'resources') {
      return {target:0,host:1,javascript:2,resource:2,operation:3,cluster:4}[n.type] ?? 4;
    }
    if (preset === 'burp') return {source:0,target:0,host:1,resource:2,operation:3,cluster:4,request:5}[n.type] ?? 5;
    if (preset === 'interesting' || preset === 'attack') return {source:0,target:0,host:1,javascript:2,resource:2,operation:3,cluster:4,observation:4,lead:5,finding:5,external:5}[n.type] ?? 5;
    return {source:0,target:0,host:1,javascript:2,resource:2,operation:3,cluster:4,request:5,observation:5,lead:6,finding:6,external:6}[n.type] ?? 6;
  }

  function spreadNodes(arr,x,start,end,sorter=null){
    if(sorter)arr.sort(sorter);
    if(!arr.length)return;
    const span=Math.max(0,end-start),gap=arr.length===1?0:span/(arr.length-1);
    arr.forEach((n,i)=>{n.x=x;n.y=arr.length===1?(start+end)/2:start+i*gap;n.manual=false;});
  }

  function autoLayoutIdentity(width,height){
    const ids=sceneNodes.filter(n=>n.type==='identity');
    const resources=sceneNodes.filter(n=>n.type==='resource');
    const flows=sceneNodes.filter(n=>n.type==='flow');
    const objects=sceneNodes.filter(n=>n.type==='object');
    const requests=sceneNodes.filter(n=>n.type==='request');
    const ops=sceneNodes.filter(n=>n.type==='operation');
    const primary=`identity:${Number(graph.meta?.identity_id||0)}`, compare=`identity:${Number(graph.meta?.compare_identity_id||0)}`;
    const a=ids.find(n=>n.id===primary)||ids[0], b=ids.find(n=>n.id===compare);
    if(a){a.x=105;a.y=height/2;a.manual=false;}
    if(b){b.x=width-105;b.y=height/2;b.manual=false;}
    ids.filter(n=>n!==a&&n!==b).forEach((n,i)=>{n.x=105;n.y=90+i*70;n.manual=false;});
    const identityDegree=n=>sceneEdges.filter(e=>(e.source===n.id||e.target===n.id)&&['called_endpoint'].includes(e.relation)).length;
    spreadNodes(resources,width/2,75,height-75,(x,y)=>identityDegree(y)-identityDegree(x)||x.label.localeCompare(y.label));
    const sideForFlow=f=>{
      const rel=sceneEdges.find(e=>(e.source===f.id||e.target===f.id)&&['participates_in','flow_actor'].includes(e.relation));
      const other=rel?opposite(rel,f.id):'';return b&&other===b.id?'right':'left';
    };
    const leftFlows=flows.filter(f=>sideForFlow(f)==='left'),rightFlows=flows.filter(f=>sideForFlow(f)==='right');
    spreadNodes(leftFlows,235,75,height-75,(x,y)=>x.label.localeCompare(y.label));
    spreadNodes(rightFlows,width-235,75,height-75,(x,y)=>x.label.localeCompare(y.label));
    spreadNodes(objects,width/2+230,90,height-90,(x,y)=>x.label.localeCompare(y.label));
    spreadNodes(requests,width/2-150,70,height-70,(x,y)=>Number(x.meta?.id||0)-Number(y.meta?.id||0));
    // Methods sit close to their endpoint and are hidden by default.
    ops.forEach((n,i)=>{
      const e=sceneEdges.find(e=>(e.source===n.id||e.target===n.id)&&e.relation==='supports');const r=e?sceneNodes.find(x=>x.id===opposite(e,n.id)):null;
      n.x=(r?.x||width/2)+155;n.y=(r?.y||80)+(i%3-1)*18;n.manual=false;
    });
  }

  function autoLayoutObject(width,height){
    const focus=`object:${Number(graph.meta?.object_id||0)}`;
    const object=sceneNodes.find(n=>n.id===focus);
    const related=sceneNodes.filter(n=>n.type==='object'&&n.id!==focus);
    const resources=sceneNodes.filter(n=>n.type==='resource');
    const identities=sceneNodes.filter(n=>n.type==='identity');
    const flows=sceneNodes.filter(n=>n.type==='flow');
    const requests=sceneNodes.filter(n=>n.type==='request');
    const ops=sceneNodes.filter(n=>n.type==='operation');
    if(object){object.x=105;object.y=height/2;object.manual=false;}
    spreadNodes(resources,width*.43,75,height-75,(x,y)=>x.label.localeCompare(y.label));
    spreadNodes(identities,width-115,70,Math.max(120,height*.45),(x,y)=>x.label.localeCompare(y.label));
    spreadNodes(flows,width-115,Math.min(height*.55,height-150),height-70,(x,y)=>x.label.localeCompare(y.label));
    spreadNodes(related,width*.68,80,height-80,(x,y)=>x.label.localeCompare(y.label));
    spreadNodes(requests,width*.62,70,height-70,(x,y)=>Number(x.meta?.id||0)-Number(y.meta?.id||0));
    ops.forEach((n,i)=>{const e=sceneEdges.find(e=>(e.source===n.id||e.target===n.id)&&e.relation==='supports');const r=e?sceneNodes.find(x=>x.id===opposite(e,n.id)):null;n.x=(r?.x||width*.43)+155;n.y=(r?.y||80)+(i%3-1)*18;n.manual=false;});
  }

  function autoLayoutFlow(width,height){
    const fid=`flow:${Number(graph.meta?.flow_id||0)}`;
    const flow=sceneNodes.find(n=>n.id===fid);
    const identities=sceneNodes.filter(n=>n.type==='identity');
    const requests=sceneNodes.filter(n=>n.type==='request');
    const objects=sceneNodes.filter(n=>n.type==='object');
    if(flow){flow.x=105;flow.y=80;flow.manual=false;}
    spreadNodes(identities,105,165,Math.min(height-80,300),(x,y)=>x.label.localeCompare(y.label));
    const pos=n=>{const e=graph.edges.find(e=>e.source===fid&&e.target===n.id&&e.relation==='flow_step');return Number(e?.meta?.evidence?.position||n.meta?.id||999999);};
    spreadNodes(requests,width*.49,70,height-70,(x,y)=>pos(x)-pos(y));
    spreadNodes(objects,width-120,80,height-80,(x,y)=>x.label.localeCompare(y.label));
  }

  function autoLayoutDiscovery(width,height){
    const pivot=sceneNodes.find(n=>n.type==='identifier');
    const resources=sceneNodes.filter(n=>n.type==='resource');
    const identities=sceneNodes.filter(n=>n.type==='identity');
    const flows=sceneNodes.filter(n=>n.type==='flow');
    const objects=sceneNodes.filter(n=>n.type==='object');
    const parameters=sceneNodes.filter(n=>n.type==='parameter');
    const requests=sceneNodes.filter(n=>n.type==='request');
    const contextNodes=sceneNodes.filter(n=>['investigation','lead','requirement','finding','observation'].includes(n.type));
    if(layerEnabled('identity')&&identities.length){
      // Authorization Mix: endpoints are the stable middle column, non-owners
      // on the left and observed owners on the right. This keeps crossings legible.
      if(pivot){pivot.x=width/2;pivot.y=48;pivot.manual=false;}
      spreadNodes(resources,width/2,135,height-70,(a,b)=>a.label.localeCompare(b.label));
      const ownerIds=new Set((pivot?.meta?.owner_identity_ids||[]).map(x=>`identity:${Number(x)}`));
      const owners=identities.filter(n=>ownerIds.has(n.id));
      const actors=identities.filter(n=>!ownerIds.has(n.id));
      spreadNodes(actors,105,130,height-95,(a,b)=>a.label.localeCompare(b.label));
      spreadNodes(owners.length?owners:identities.slice(-1),width-105,130,height-95,(a,b)=>a.label.localeCompare(b.label));
      const used=new Set([...actors,...(owners.length?owners:identities.slice(-1))].map(n=>n.id));
      spreadNodes(identities.filter(n=>!used.has(n.id)),105,90,Math.max(120,height*.35),(a,b)=>a.label.localeCompare(b.label));
    }else{
      if(pivot){pivot.x=125;pivot.y=height/2;pivot.manual=false;}
      spreadNodes(resources,width*.66,75,height-75,(a,b)=>a.label.localeCompare(b.label));
    }
    // Optional context layers live in dedicated side bands instead of being
    // mixed into the endpoint column. They are meant to be toggled briefly.
    if(layerEnabled('parameter'))spreadNodes(parameters,width*.32,85,height-85,(a,b)=>a.label.localeCompare(b.label));
    if(layerEnabled('flow'))spreadNodes(flows,width-125,90,height-90,(a,b)=>a.label.localeCompare(b.label));
    if(layerEnabled('object'))spreadNodes(objects,width*.82,90,height-90,(a,b)=>a.label.localeCompare(b.label));
    if(layerEnabled('request'))spreadNodes(requests,width*.82,70,height-70,(a,b)=>Number(a.meta?.id||0)-Number(b.meta?.id||0));
    if(layerEnabled('context'))spreadNodes(contextNodes,width*.28,90,height-90,(a,b)=>a.label.localeCompare(b.label));
    applySavedLayout();
  }

  function autoLayout(){
    const width=Math.max(980,svg.clientWidth||1100), height=Math.max(620,svg.clientHeight||680);
    if(preset==='identity' && Number(graph.meta?.identity_id||0)>0){autoLayoutIdentity(width,height);return applySavedLayout();}
    if(preset==='discovery'){autoLayoutDiscovery(width,height);return;}
    if(preset==='objects' && Number(graph.meta?.object_id||0)>0){autoLayoutObject(width,height);return applySavedLayout();}
    if(preset==='flow' && Number(graph.meta?.flow_id||0)>0){autoLayoutFlow(width,height);return applySavedLayout();}
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

    applySavedLayout();
  }

  function applySavedLayout(){
    if(fullscreenReflow || document.fullscreenElement===graphWorkspace){
      sceneNodes.forEach(n=>{ n.manual=false; });
      setLayoutStatus('Layout adaptado a pantalla completa');
      return;
    }
    const saved=readSavedLayout();
    sceneNodes.forEach(n=>{ if(saved[n.id] && Number.isFinite(saved[n.id].x) && Number.isFinite(saved[n.id].y)){ n.x=saved[n.id].x;n.y=saved[n.id].y;n.manual=true; } });
    setLayoutStatus(Object.keys(saved).length ? 'Disposición personalizada guardada' : 'Layout automático');
  }

  function layerManagedTypes(){
    return {surface:new Set(['operation']),identity:new Set(['flow','object','request','operation']),flow:new Set(['object']),objects:new Set(['flow','object','request','operation'])}[preset]||new Set();
  }

  function buildTypeFilters(){
    const present=new Set(sceneNodes.map(n=>n.type).filter(t=>t!=='cluster'));
    activeTypes=new Set(present);
    const managed=layerManagedTypes();
    typeWrap.innerHTML='';
    typeOrder.filter(t=>present.has(t)&&!managed.has(t)).forEach(t=>{
      const b=document.createElement('button');b.type='button';b.className='graph-type active';b.dataset.type=t;
      b.textContent=`${typeLabel[t]||t} · ${sceneNodes.filter(n=>n.type===t).length}`;
      b.addEventListener('click',()=>{activeTypes.has(t)?activeTypes.delete(t):activeTypes.add(t);b.classList.toggle('active',activeTypes.has(t));applyFilters();});
      typeWrap.appendChild(b);
    });
  }

  function applyFilters({fitAfter=false}={}){
    const q=(search.value||'').trim().toLowerCase();
    const intelIds=intelligenceOnly?intelligenceRelevantIds():null;
    const baseNodes=sceneNodes.filter(n =>
      (n.type==='cluster'||activeTypes.has(n.type)) &&
      nodeLayerPasses(n) &&
      identityEndpointPass(n) &&
      leadPassesFilters(n) &&
      (!intelIds || intelIds.has(n.id)) &&
      (!q || n.label.toLowerCase().includes(q) || JSON.stringify(n.meta||{}).toLowerCase().includes(q))
    );
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
    if(!['attack','interesting','intelligence'].includes(preset))return false;
    const m=sceneById(),a=m.get(e.source),b=m.get(e.target);
    return [a,b].some(n=>n && (n.state==='interesting'||n.state==='finding'||n.type==='lead'||n.type==='finding'||n.type==='observation'));
  }

  function relationIsRoute(e){
    if(activePathEdgeIds.has(e.id))return true;
    if(!activeRoute || !Array.isArray(activeRoute.node_ids)) return false;
    const ids=activeRoute.node_ids;
    for(let i=0;i<ids.length-1;i++){
      if((e.source===ids[i]&&e.target===ids[i+1])||(e.target===ids[i]&&e.source===ids[i+1]))return true;
    }
    return false;
  }

  function edgeIdentityCompareClass(e){
    if(preset!=='identity'||e.relation!=='called_endpoint')return '';
    const primary=`identity:${Number(graph.meta?.identity_id||0)}`, compare=`identity:${Number(graph.meta?.compare_identity_id||0)}`;
    if(e.source===primary||e.target===primary)return ' graph-edge-identity-primary';
    if(compare!=='identity:0'&&(e.source===compare||e.target===compare))return ' graph-edge-identity-secondary';
    return '';
  }

  function edgeSemanticClass(e){
    const m=sceneById(); const a=m.get(e.source), b=m.get(e.target);
    const lead=[a,b].find(n=>n?.type==='lead');
    if(lead?.meta?.status==='confirmed')return ' graph-edge-confirmed';
    if(['supports_hypothesis','produced_lead','contradicts_hypothesis'].includes(e.relation))return ' graph-edge-hypothesis';
    if(e.relation==='discovered' && String(e.meta?.source||'').includes('js'))return ' graph-edge-discovered';
    if(['observed_in','tested_by','evidence_for'].includes(e.relation))return ' graph-edge-evidence';
    return '';
  }

  function labelVisible(n){
    if(selected===n.id)return true;
    if(n.type==='resource')return true; // endpoints never disappear with zoom
    if(preset==='flow'&&n.type==='request')return true; // each Flow step is an endpoint-bearing Request
    if(preset==='discovery'&&['identifier','parameter','identity','resource'].includes(n.type))return true;
    if(['target','host','operation','finding','lead','cluster','identity','session','flow','object','anomaly','state'].includes(n.type))return true;
    return view.k>=1.15;
  }

  function keepLabelScreenSize(n){
    return n.type==='identity'||n.type==='session'||n.type==='flow'||n.type==='resource'||
      (preset==='discovery'&&['identifier','parameter'].includes(n.type))||
      (preset==='flow'&&n.type==='request');
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
      path.setAttribute('class',`graph-edge relation-${String(e.relation||'related').replace(/[^a-z0-9_-]/gi,'-')}${edgeSemanticClass(e)}${edgeIdentityCompareClass(e)}${relationIsHighlight(e)?' graph-edge-highlight':''}${relationIsRoute(e)?' graph-edge-route':''}`);path.dataset.id=e.id;
      path.addEventListener('click',ev=>{ev.stopPropagation();showEdge(e)});g.appendChild(path);
      if(preset==='discovery'&&['owns_observed','read_denied','read_allowed','write_allowed','write_denied','changed_address','cancelled_object','created_return','refunded_object','deleted_object'].includes(e.relation)){
        const label=document.createElementNS(NS,'text');label.setAttribute('x',String((a.x+b.x)/2));label.setAttribute('y',String((a.y+b.y)/2-5));label.setAttribute('text-anchor','middle');label.setAttribute('class','graph-edge-label');label.textContent=relationLabel[e.relation]||e.relation;g.appendChild(label);
      }
    });

    visibleNodes.forEach(n=>{
      const ng=document.createElementNS(NS,'g');
      const compareBucket=n.type==='resource'?identityEndpointBucket(n.id):'';
      const primaryIdentity=n.id===`identity:${Number(graph.meta?.identity_id||0)}`;
      const compareIdentity=n.id===`identity:${Number(graph.meta?.compare_identity_id||0)}`;
      const intel=nodeIntelligence(n);
      ng.setAttribute('class',`graph-node type-${n.type} state-${slugState(n.state)}${intel.hasSignal?' has-signal':''}${intel.hasCorrelation?' has-correlation':''}${intel.hasHypothesis?' has-hypothesis':''}${preset==='flow'&&n.type==='request'?' flow-endpoint-node':''}${compareBucket?` compare-${compareBucket}`:''}${primaryIdentity?' compare-identity-primary':''}${compareIdentity?' compare-identity-secondary':''}${selected===n.id?' selected':''}${n.manual?' manual':''}${(activeRoute?.node_ids?.includes(n.id)||activePathIds.includes(n.id))?' route-node':''}`);
      ng.setAttribute('transform',`translate(${n.x} ${n.y})`);ng.dataset.id=n.id;
      const visual=appendNodeVisual(ng,n);
      if (n.meta?.coverage && ['host','resource'].includes(n.type) && !semanticCardMode(n)) {
        const dot=document.createElementNS(NS,'circle');
        dot.setAttribute('r','3.2'); dot.setAttribute('cx',String(-nodeRadius(n.type)+1)); dot.setAttribute('cy',String(-nodeRadius(n.type)+1));
        dot.setAttribute('class',`graph-coverage-dot coverage-${esc(n.meta.coverage)}`); ng.appendChild(dot);
      }
      if(n.type==='cluster'){
        const inner=document.createElementNS(NS,'circle');inner.setAttribute('r',Math.max(3,nodeRadius(n.type)-4));inner.setAttribute('class','graph-cluster-inner');ng.appendChild(inner);
      }
      if(labelVisible(n)&&!visual.inlineLabel){
        const label=document.createElementNS(NS,'text');label.setAttribute('x',visual.labelAnchor||nodeRadius(n.type)+8);label.setAttribute('y','4');label.setAttribute('class',`graph-node-label label-${n.type}`);
        if(keepLabelScreenSize(n)){const inv=1/Math.max(.18,view.k);label.setAttribute('transform',`scale(${inv})`);}
        const limit=labelLimit(n.type);label.textContent=n.label.length>limit?n.label.slice(0,limit-1)+'…':n.label;ng.appendChild(label);
      }
      ng.setAttribute('tabindex','0'); ng.setAttribute('role','button'); ng.setAttribute('aria-label',n.label);
      ng.addEventListener('pointerdown',ev=>startNodeDrag(ev,n));
      ng.addEventListener('click',ev=>{ev.stopPropagation();if(suppressClick){suppressClick=false;return;}selected=n.id;showNode(n);render();});
      ng.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();selected=n.id;showNode(n);render();}});
      ng.addEventListener('dblclick',ev=>{ev.stopPropagation();if(n.type==='cluster'){if(Array.isArray(n.childIds))toggleCluster(n);else if(n.href)window.location.assign(`${base}/${n.href}`);}else if(['host','resource'].includes(n.type))navigateScope(n);else focusNeighborhood(n.id,1);});
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

  function groupNodeRelations(n,rels,sourceGraph){
    const groups=new Map();
    rels.forEach(e=>{
      const oid=e.source===n.id?e.target:e.source;
      const other=sourceGraph.find(x=>x.id===oid)||graph.nodes.find(x=>x.id===oid);
      if(!other)return;
      const key=`${e.relation}|${other.type}|${other.label}`;
      if(!groups.has(key))groups.set(key,{relation:e.relation,type:other.type,label:other.label,count:0,ids:[],nodes:[],edges:[]});
      const g=groups.get(key);g.count++;g.ids.push(other.id);g.nodes.push(other);g.edges.push(e);
    });
    return [...groups.values()].sort((a,b)=>a.type.localeCompare(b.type)||a.label.localeCompare(b.label));
  }

  function relationGroupRow(group,{note=''}={}){
    const first=group.nodes[0];
    const count=group.count>1?`<span class="graph-relation-count">×${group.count}</span>`:'';
    const context=note||((group.type==='object'&&first?.meta?.ui_quality==='ambiguous')?'mismo valor observado con varias clasificaciones internas':'');
    return `<button type="button" class="graph-relation compact" data-focus="${esc(first?.id||'')}"><span>${esc(relationLabel[group.relation]||group.relation)}</span><b>${esc(group.label)}${context?` <small class="graph-relation-note">· ${esc(context)}</small>`:''}</b>${count}</button>`;
  }

  function relationSectionsHtml(n,groups){
    if(n.type!=='resource'){
      const rows=groups.slice(0,18).map(g=>relationGroupRow(g)).join('');
      return `<div class="graph-detail-section"><h3>Relaciones · ${groups.length}</h3>${rows||'<small>Sin relaciones visibles.</small>'}</div>`;
    }
    const identities=groups.filter(g=>g.type==='identity'&&g.relation==='called_endpoint');
    const flows=groups.filter(g=>g.type==='flow'&&g.relation==='flow_endpoint');
    const meaningfulObjects=groups.filter(g=>g.type==='object'&&g.relation==='observed_object'&&g.nodes.some(x=>x.meta?.ui_quality!=='ambiguous'));
    const noisyObjects=groups.filter(g=>g.type==='object'&&g.relation==='observed_object'&&g.nodes.every(x=>x.meta?.ui_quality==='ambiguous'));
    const consumed=new Set([...identities,...flows,...meaningfulObjects,...noisyObjects].map(g=>`${g.relation}|${g.type}|${g.label}`));
    // Methods, host containment and individual Request edges are already explained by dedicated endpoint sections.
    const technical=groups.filter(g=>!consumed.has(`${g.relation}|${g.type}|${g.label}`)&&!['supports','contains','calls'].includes(g.relation));
    const section=(title,rows,copy='')=>rows.length?`<div class="graph-detail-group"><h3>${esc(title)}</h3>${copy?`<p>${esc(copy)}</p>`:''}${rows.map(g=>relationGroupRow(g)).join('')}</div>`:'';
    const noisy=noisyObjects.length?`<details class="graph-detail-technical"><summary>Identificadores sin clasificar · ${noisyObjects.reduce((s,g)=>s+g.count,0)}</summary><p>Negro observó estos valores, pero todavía no sabe qué entidad de negocio representan.</p>${noisyObjects.map(g=>relationGroupRow(g)).join('')}</details>`:'';
    const tech=technical.length?`<details class="graph-detail-technical"><summary>Relaciones técnicas · ${technical.length}</summary>${technical.slice(0,18).map(g=>relationGroupRow(g)).join('')}</details>`:'';
    return `${section('Identidades que consumieron este endpoint',identities)}${section('Flujos donde apareció',flows)}${section('Objetos con significado observados aquí',meaningfulObjects)}${noisy}${tech}`;
  }

  function discoveryEndpointEvidenceHtml(n){
    if(preset!=='discovery'||n.type!=='resource')return '';
    const ev=n.meta?.discovery_evidence;
    if(!ev)return '';
    const requests=Array.isArray(ev.requests)?ev.requests:[];
    const identifiers=Array.isArray(ev.identifiers)?ev.identifiers:[];
    const reqHtml=requests.length?requests.map(r=>`<a class="discovery-request-row" href="${base}/resource/${Number(n.meta?.id||0)}?exchange=${Number(r.id||0)}#exchange-${Number(r.id||0)}"><span>#${Number(r.id||0)} · ${esc(r.method||'')} · HTTP ${esc(r.status??'—')}</span><b>${esc(r.identity_name||'Sin identidad')}</b><small>${esc((r.directions||[]).join(' / ')||'contexto')}</small></a>`).join(''):'<small>Sin Requests concretas en esta proyección.</small>';
    const idsHtml=identifiers.length?identifiers.map(x=>`<article class="discovery-identifier-row"><div class="discovery-pivot-line"><span class="discovery-pivot-kind">KEY</span><code>${esc(x.key||'')}</code><button type="button" class="mini-action" data-discover-key="${esc(x.key||'')}">Seguir key</button></div><div class="discovery-pivot-line"><span class="discovery-pivot-kind">VALOR</span><code>${esc(x.value||'')}</code><button type="button" class="mini-action" data-discover-value="${esc(x.value||'')}">Seguir valor</button></div><small>${esc((x.directions||[]).join(' / '))} · ${Number((x.request_ids||[]).length)} Request${Number((x.request_ids||[]).length)===1?'':'s'}</small></article>`).join(''):'<small>No hay otros identificadores indexados en estas Requests.</small>';
    const identityRows=endpointIdentityResults(n.id);
    const identityHtml=identityRows.length?`<div class="discovery-panel-group"><b>Authorization Mix observado</b><div class="discovery-auth-mix">${identityRows.map(r=>`<div class="${r.untested?'untested':r.cross?'cross':''}"><span>${r.owner?'OWNER · ':r.cross?'↔ CRUCE · ':''}${esc(r.label)}</span><b>${r.untested?'○ no observado':esc(r.statuses.join(' / '))}</b></div>`).join('')}</div><small class="muted">No observado no significa permitido ni denegado; sólo indica que Negro aún no vio esa combinación.</small></div>`:'';
    return `<div class="graph-detail-section discovery-endpoint-evidence"><h3>Explorar este endpoint</h3><p>La pieza <code>${esc(ev.pivot||'')}</code> fue observada aquí como ${esc((ev.pivot_keys||[]).join(', ')||'identificador')}. Desde este panel puedes abrir el HTTP o cambiar de pivote sin perder la ruta de exploración.</p>${identityHtml}<div class="discovery-panel-group"><b>Requests que justifican la relación</b>${reqHtml}</div><div class="discovery-panel-group"><b>Keys y valores observados</b><p class="muted"><b>Seguir key</b> busca el mismo concepto con cualquier valor. <b>Seguir valor</b> busca esta pieza aunque cambie de nombre.</p>${idsHtml}</div></div>`;
  }

  async function hydrateGenericResourceEvidence(n){
    if(n?.type!=='resource' || n.meta?.discovery_evidence)return;
    const rid=Number(n.meta?.id||0); if(!rid)return;
    const host=detail.querySelector(`[data-resource-evidence="${rid}"]`); if(!host)return;
    try{
      const r=await fetch(`${api}/resource-evidence/${rid}`,{headers:{Accept:'application/json'}});
      if(!r.ok)throw new Error(`HTTP ${r.status}`);
      const d=await r.json();
      const reqs=Array.isArray(d.requests)?d.requests:[];
      const ids=Array.isArray(d.identifiers)?d.identifiers:[];
      const reqHtml=reqs.length?reqs.map(x=>`<a class="discovery-request-row" href="${base}/resource/${rid}?exchange=${Number(x.id||0)}#exchange-${Number(x.id||0)}"><span><b>${esc(x.method||'REQUEST')}</b> <code>${esc(x.path||'')}</code></span><small>#${Number(x.id||0)} · HTTP ${esc(x.status??'—')}${x.identity_name?` · ${esc(x.identity_name)}`:''}</small></a>`).join(''):'<small>No hay Requests observadas.</small>';
      const idHtml=ids.length?ids.map(x=>`<article class="discovery-pivot-card"><div class="discovery-pivot-line"><span class="discovery-pivot-kind">KEY</span><code>${esc(x.key||'')}</code><button type="button" class="mini-action" data-discover-key="${esc(x.key||'')}">Seguir key</button></div><div class="discovery-pivot-line"><span class="discovery-pivot-kind">VALOR</span><code>${esc(x.value||'')}</code><button type="button" class="mini-action" data-discover-value="${esc(x.value||'')}">Seguir valor</button></div><small>${Number((x.request_ids||[]).length)} Request${Number((x.request_ids||[]).length)===1?'':'s'}</small></article>`).join(''):'<small>No hay keys/valores indexados en estas Requests.</small>';
      host.innerHTML=`<h3>Requests, keys y valores</h3><p class="muted">Disponible en cualquier lente. Sigue una key para explorar el concepto o un valor para seguir la misma pieza aunque cambie de nombre.</p><div class="discovery-panel-group"><b>Requests observadas</b>${reqHtml}</div><div class="discovery-panel-group"><b>Pivotes disponibles</b>${idHtml}</div>`;
      host.querySelectorAll('[data-discover-key]').forEach(btn=>btn.addEventListener('click',()=>{discoveryTrail=[btn.dataset.discoverKey||''];openDiscoveryPivot(btn.dataset.discoverKey||'',{push:false});}));
      host.querySelectorAll('[data-discover-value]').forEach(btn=>btn.addEventListener('click',()=>{discoveryTrail=[btn.dataset.discoverValue||''];openDiscoveryPivot(btn.dataset.discoverValue||'',{push:false});}));
    }catch(err){host.innerHTML=`<h3>Requests, keys y valores</h3><p class="muted">No se pudo cargar esta evidencia: ${esc(err.message)}</p>`;}
  }

  function showNode(n){
    const rels=(n.virtual?sceneEdges:graph.edges).filter(e=>e.source===n.id||e.target===n.id);
    const meta=n.meta||{};
    const metaRows=Object.entries(meta).filter(([k,v])=>!['count','interesting','why','next_test','result_notes','signal_count','hypothesis_count','intelligence'].includes(k)&&v!==null&&v!==''&&typeof v!=='object').slice(0,10).map(([k,v])=>`<div><span>${esc(metaKeyLabel[k]||k.replaceAll('_',' '))}</span><b>${esc(valueLabel(v))}</b></div>`).join('');
    const sourceGraph=n.virtual?sceneNodes:graph.nodes;
    const relationGroups=groupNodeRelations(n,rels,sourceGraph);
    const relationHtml=relationSectionsHtml(n,relationGroups);
    const summary=summarizeNode(n);
    const endpointMethods=n.type==='resource'?[...new Set(graph.edges.filter(e=>(e.source===n.id||e.target===n.id)&&e.relation==='supports').map(e=>nodeFor(opposite(e,n.id))).filter(x=>x?.type==='operation').map(x=>String(x.meta?.method||x.label||'').toUpperCase()).filter(Boolean))]:[];
    const methodHtml=n.type==='resource'&&endpointMethods.length?`<div class="endpoint-method-strip"><small>MÉTODOS SOPORTADOS</small><div>${endpointMethods.map(m=>`<span>${esc(m)}</span>`).join('')}</div></div>`:'';
    const testSummary=meta.test_summary||{};
    const trackedTests=Object.values(testSummary).reduce((a,b)=>a+Number(b||0),0);
    const pendingTests=Number(testSummary.pending||0)+Number(testSummary.testing||0);
    const summaryHtml=['resource','operation'].includes(n.type)?`<div class="graph-coverage"><div><b>${summary.methods||((n.type==='operation')?1:0)}</b><span>Métodos</span></div><div><b>${summary.requests}</b><span>Solicitudes</span></div><div><b>${n.type==='operation'&&trackedTests?trackedTests:summary.tests}</b><span>Pruebas</span></div><div class="${summary.interesting||Number(testSummary.interesting||0)||Number(testSummary.confirmed||0)?'is-interesting':''}"><b>${n.type==='operation'&&trackedTests?pendingTests:summary.interesting}</b><span>${n.type==='operation'&&trackedTests?'Pendientes':'Señales'}</span></div></div>`:'';
    const intelligenceRows=Array.isArray(meta.intelligence)?meta.intelligence:[];
    const intelligenceHtml=intelligenceRows.length?`<div class="graph-detail-section graph-intelligence-section"><div class="graph-intelligence-title"><h3>Inteligencia asociada · ${intelligenceRows.length}</h3><small>Señal = coincidencia observada · Hipótesis = pregunta generada para investigar</small></div>${intelligenceRows.map(item=>`<a class="graph-intelligence-link kind-${esc(item.kind||'signal')}" href="${base}/${esc(item.href||'hypotheses')}"><span>${item.kind==='hypothesis'?'◆':item.kind==='context_match'?'↔':item.signal_level==='correlation'?'↔':'⚡'}</span><div><b>${esc(item.title||'Inteligencia')}</b><small>${item.kind==='hypothesis'?`Hipótesis · ${esc(valueLabel(item.status||'candidate'))}`:item.kind==='context_match'?`Context Match · ${esc(item.status||'candidate')}`:item.signal_level==='correlation'?`Correlación · ${esc(item.source||'memory')}`:`Señal · ${esc(item.source||'motor')}`}</small></div><em>Abrir →</em></a>`).join('')}</div>`:'';
    const clusterHtml=n.type==='cluster'?`<div class="graph-detail-section"><h3>${esc(n.label)}</h3><p>${esc(n.meta?.note || (n.meta?.interesting?`Incluye ${n.meta.interesting} señal(es) interesante(s).`:'Agrupado para mantener el mapa legible.'))}</p>${Array.isArray(n.childIds)?`<button type="button" class="btn-secondary" data-expand-cluster>${expandedClusters.has(n.id)?'Contraer':'Expandir'} elementos</button>`:''}${n.href?`<a class="btn-secondary" href="${base}/${esc(n.href)}">Abrir inventario →</a>`:''}</div>`:'';
    const semanticNeutral=['identity','flow','object','request','state','target','host','resource','identifier','parameter','investigation','requirement'].includes(n.type) && slugState(n.state)==='normal';
    const statusHtml=(meta.coverage||meta.signal)
      ? `<div class="graph-dual-state">${meta.coverage?`<span class="state-chip coverage-chip coverage-${esc(meta.coverage)}">Cobertura · ${esc(coverageLabel[meta.coverage]||meta.coverage)}</span>`:''}${meta.signal?`<span class="state-chip signal-chip signal-${esc(meta.signal)}">Señal · ${esc(signalLabel[meta.signal]||meta.signal)}</span>`:''}${Number(meta.finding_count||0)>0?`<span class="state-chip signal-chip signal-finding">${esc(meta.finding_count)} hallazgo${Number(meta.finding_count)===1?'':'s'}</span>`:''}</div>`
      : semanticNeutral ? '' : `<span class="state-chip state-${slugState(n.state)}">${esc(stateLabel[slugState(n.state)]||n.state)}</span>`;
    const exploreAction=['host','resource'].includes(n.type)?`<button type="button" class="button" data-explore-scope>Explorar ${n.type==='host'?'host':'recurso'} en mapa →</button>`:'';
    const discoveryValue=n.type==='object'?String(meta.identifier||''):n.type==='parameter'?String(n.label||''):n.type==='requirement'?String(meta.key||''):'';
    const discoveryAction=discoveryValue?`<button type="button" class="button" data-discover-value="${esc(discoveryValue)}">Abrir relaciones de ${esc(discoveryValue)}</button>`:'';
    const pathAction=!pathStart?`<button type="button" class="btn-secondary" data-path-start>Camino · empezar aquí</button>`:(pathStart===n.id?`<button type="button" class="btn-secondary" data-path-clear-local>Cancelar inicio de camino</button>`:`<button type="button" class="button" data-path-to>Ver camino desde ${esc((sceneNodes.find(x=>x.id===pathStart)||graph.nodes.find(x=>x.id===pathStart))?.label||'inicio')}</button><button type="button" class="btn-secondary" data-path-start>Cambiar inicio</button>`);
    const hypothesisHtml=n.type==='lead'?`<div class="graph-detail-section graph-hypothesis-editor"><h3>Trabajo de hipótesis</h3>${meta.why?`<p><b>Por qué:</b> ${esc(meta.why)}</p>`:''}${meta.next_test?`<p><b>Siguiente prueba:</b> ${esc(meta.next_test)}</p>`:''}<label>Estado<select data-lead-edit-status>${['candidate','testing','interesting','negative','postponed','confirmed','discarded'].map(s=>`<option value="${s}" ${String(meta.status||'candidate')===s?'selected':''}>${esc(valueLabel(s))}</option>`).join('')}</select></label><label>Resultado / qué pasó<textarea data-lead-edit-notes placeholder="Qué probaste, por qué falló o qué evidencia confirmó la hipótesis…">${esc(meta.result_notes||'')}</textarea></label><button type="button" class="button" data-lead-edit-save>Guardar en la misma hipótesis</button><small data-lead-edit-feedback></small></div>`:'';
    const discoveryEndpointHtml=discoveryEndpointEvidenceHtml(n);
    const genericEndpointHtml=(n.type==='resource' && !discoveryEndpointHtml)?`<div class="graph-detail-section discovery-endpoint-evidence" data-resource-evidence="${Number(meta.id||0)}"><h3>Requests, keys y valores</h3><p class="muted">Cargando evidencia observada de este endpoint…</p></div>`:'';
    detail.innerHTML=`<div class="graph-detail-head"><span class="graph-node-kind">${esc(typeLabel[n.type]||n.type)}</span><h2>${esc(n.label)}</h2>${statusHtml}</div>${summaryHtml}${methodHtml}<div class="graph-detail-actions">${exploreAction}${discoveryAction}<button type="button" class="btn-secondary" data-focus-one>Enfocar 1 salto</button><button type="button" class="btn-secondary" data-focus-two>2 saltos</button>${pathAction}${n.href?`<a class="btn" href="${base}/${esc(n.href)}">Abrir detalle →</a>`:''}<button type="button" class="btn-secondary" data-ai-selected>🧠 Ideas con IA</button></div><div class="graph-detail-meta">${metaRows||'<small>Sin datos adicionales.</small>'}</div>${discoveryEndpointHtml}${genericEndpointHtml}${intelligenceHtml}${hypothesisHtml}${clusterHtml}${relationHtml}`;
    renderGenericTrail();
    hydrateGenericResourceEvidence(n);
    detail.querySelector('[data-explore-scope]')?.addEventListener('click',()=>navigateScope(n));
        detail.querySelectorAll('[data-discover-value]').forEach(btn=>btn.addEventListener('click',()=>openDiscoveryPivot(btn.dataset.discoverValue||'')));
    detail.querySelectorAll('[data-discover-key]').forEach(btn=>btn.addEventListener('click',()=>openDiscoveryPivot(btn.dataset.discoverKey||'')));
    detail.querySelector('[data-focus-one]')?.addEventListener('click',()=>focusNeighborhood(n.id,1));
    detail.querySelector('[data-focus-two]')?.addEventListener('click',()=>focusNeighborhood(n.id,2));
    detail.querySelector('[data-path-start]')?.addEventListener('click',()=>{pathStart=n.id;activePathIds=[];activePathEdgeIds=new Set();if(pathClearBtn)pathClearBtn.hidden=false;showNode(n);render();});
    detail.querySelector('[data-path-clear-local]')?.addEventListener('click',()=>clearPath());
    detail.querySelector('[data-path-to]')?.addEventListener('click',()=>showPath(pathStart,n.id));
    detail.querySelector('[data-expand-cluster]')?.addEventListener('click',()=>toggleCluster(n));
    detail.querySelector('[data-ai-selected]')?.addEventListener('click',()=>openAiPanel(n.type==='cluster'?(n.parentId||''):n.id,n.type==='cluster'?(n.meta?.parent||n.label):n.label));
    detail.querySelector('[data-lead-edit-save]')?.addEventListener('click',async()=>{
      const button=detail.querySelector('[data-lead-edit-save]');
      const feedback=detail.querySelector('[data-lead-edit-feedback]');
      const status=detail.querySelector('[data-lead-edit-status]')?.value||'candidate';
      const notes=detail.querySelector('[data-lead-edit-notes]')?.value||'';
      button.disabled=true;if(feedback)feedback.textContent='Guardando…';
      try{
        const fd=new FormData();fd.set('csrf',csrf);fd.set('status',status);fd.set('result_notes',notes);
        const r=await fetch(`${base}/lead/${Number(meta.id||0)}/status`,{method:'POST',headers:{'X-Requested-With':'NegroFetch','Accept':'application/json'},body:fd});
        if(!r.ok)throw new Error(`HTTP ${r.status}`);
        meta.status=status;meta.result_notes=notes;
        n.state=['negative','discarded'].includes(status)?'tested':status==='confirmed'?'finding':'interesting';
        const raw=graph.nodes.find(x=>x.id===n.id);if(raw){raw.meta.status=status;raw.meta.result_notes=notes;raw.state=n.state;}
        (graph.routes||[]).filter(x=>Number(x.lead_id||0)===Number(meta.id||0)).forEach(x=>x.status=status);
        if(feedback)feedback.textContent='Guardado.';
        buildLeadFilters();buildScene();buildTypeFilters();applyFilters();renderRoutes();
        const fresh=sceneNodes.find(x=>x.id===n.id)||graph.nodes.find(x=>x.id===n.id);if(fresh){selected=fresh.id;showNode(fresh);render();}
      }catch(err){if(feedback)feedback.textContent=`No se pudo guardar: ${err.message}`;}
      finally{button.disabled=false;}
    });
    detail.querySelectorAll('[data-focus]').forEach(b=>b.addEventListener('click',()=>{const x=sceneNodes.find(n=>n.id===b.dataset.focus)||graph.nodes.find(n=>n.id===b.dataset.focus);if(x){selected=x.id;showNode(x);render();}}));
  }

  function showEdge(e){
    const map=sceneById(),a=map.get(e.source)||graph.nodes.find(n=>n.id===e.source),b=map.get(e.target)||graph.nodes.find(n=>n.id===e.target),m=e.meta||{};
    const rel=relationLabel[e.relation]||e.relation;
    detail.innerHTML=`<div class="graph-detail-head"><span class="graph-node-kind">RELACIÓN</span><h2>${esc(rel)}</h2></div><div class="graph-edge-explain"><b>${esc(a?.label||e.source)}</b><span>— ${esc(rel)} →</span><b>${esc(b?.label||e.target)}</b></div><div class="graph-detail-meta"><div><span>Fuente</span><b>${esc(m.source||'—')}</b></div></div>${m.evidence?`<div class="graph-detail-section"><h3>Por qué existe</h3><pre>${esc(JSON.stringify(m.evidence,null,2))}</pre></div>`:''}`;
  }

  function toggleCluster(n){
    if(!n || n.type!=='cluster' || !Array.isArray(n.childIds))return;
    expandedClusters.has(n.id)?expandedClusters.delete(n.id):expandedClusters.add(n.id);
    const keepSelected=n.id;buildScene();buildTypeFilters();applyFilters();selected=keepSelected;const x=sceneNodes.find(a=>a.id===keepSelected);if(x)showNode(x);fit();
  }

  function clearPath(){
    pathStart=null;activePathIds=[];activePathEdgeIds=new Set();if(pathClearBtn)pathClearBtn.hidden=true;applyFilters({fitAfter:true});
    if(selected){const n=sceneNodes.find(x=>x.id===selected)||graph.nodes.find(x=>x.id===selected);if(n)showNode(n);}
  }

  function showPath(startId,endId){
    if(!startId||!endId||startId===endId)return;
    const adjacency=new Map();
    sceneEdges.forEach(e=>{
      const a=adjacency.get(e.source)||[];a.push({id:e.target,edge:e});adjacency.set(e.source,a);
      const b=adjacency.get(e.target)||[];b.push({id:e.source,edge:e});adjacency.set(e.target,b);
    });
    const queue=[startId],prev=new Map([[startId,null]]),prevEdge=new Map();
    while(queue.length){const cur=queue.shift();if(cur===endId)break;for(const step of adjacency.get(cur)||[]){if(prev.has(step.id))continue;prev.set(step.id,cur);prevEdge.set(step.id,step.edge);queue.push(step.id);}}
    if(!prev.has(endId)){alert('No hay un camino observado entre estos nodos en la vista actual. Prueba ampliar el contexto o 2 saltos.');return;}
    const ids=[];const edgeIds=new Set();let cur=endId;
    while(cur){ids.push(cur);const pe=prevEdge.get(cur);if(pe)edgeIds.add(pe.id);cur=prev.get(cur);}
    ids.reverse();activePathIds=ids;activePathEdgeIds=edgeIds;
    const keep=new Set(ids);visibleNodes=sceneNodes.filter(n=>keep.has(n.id));visibleEdges=sceneEdges.filter(e=>edgeIds.has(e.id));
    if(pathClearBtn)pathClearBtn.hidden=false;render();fit();
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
    const fullscreen=document.fullscreenElement===graphWorkspace;
    // Fullscreen must use the extra canvas instead of keeping the same tiny
    // scale that was comfortable inside the normal three-column page.
    const sidePad=preset==='discovery'?(fullscreen?80:190):(fullscreen?45:70);
    const rightPad=preset==='discovery'?(fullscreen?130:340):(fullscreen?70:160);
    const minX=Math.min(...visibleNodes.map(n=>n.x))-sidePad,maxX=Math.max(...visibleNodes.map(n=>n.x))+rightPad,minY=Math.min(...visibleNodes.map(n=>n.y))-(fullscreen?45:75),maxY=Math.max(...visibleNodes.map(n=>n.y))+(fullscreen?45:75);
    const w=Math.max(220,maxX-minX),h=Math.max(180,maxY-minY);
    const maxK=fullscreen?2.15:1.35;
    const k=Math.max(.24,Math.min(maxK,Math.min(box.width/w,box.height/h)));
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

  function routePriorityLabel(v){return v==='high'?'Alta':v==='medium'?'Media':'Quick check';}
  function renderRoutes(){
    if(!routesWrap)return;
    const routes=(graph.routes||[]).filter(routePassesFilters).slice(0,8);
    if(!routes.length){routesWrap.innerHTML='<p class="empty">Todavía no hay una ruta defendible. Captura tráfico o genera hipótesis para que Negro pueda conectar evidencia con una prueba.</p>';return;}
    routesWrap.innerHTML=routes.map(r=>{
      const selectedRoute=activeRoute?.lead_id===r.lead_id?' active':'';
      const source=String(r.source||'ENGINE').toUpperCase().startsWith('AI')?'IA':'Motor';
      const endpoint=[r.method,r.path].filter(Boolean).join(' ');
      return `<button type="button" class="graph-route-card${selectedRoute}" data-route-lead="${Number(r.lead_id||0)}"><span class="graph-route-rank">${Number(r.score||0)}</span><span class="graph-route-copy"><span class="badges"><span class="badge priority-${esc(r.priority||'low')}">${esc(routePriorityLabel(r.priority))}</span><span class="chip">${source}</span>${endpoint?`<code>${esc(endpoint)}</code>`:''}</span><b>${esc(r.title||'Ruta de investigación')}</b><small>${esc(r.next_test||r.why||'Abrir evidencia y validar manualmente.')}</small></span><span class="graph-route-arrow">→</span></button>`;
    }).join('');
    routesWrap.querySelectorAll('[data-route-lead]').forEach(btn=>btn.addEventListener('click',async()=>{
      const leadId=Number(btn.dataset.routeLead||0);let route=(graph.routes||[]).find(r=>Number(r.lead_id||0)===leadId);if(!route)return;
      const resourceNode=route.resource_id?`resource:${Number(route.resource_id)}`:'';
      if(resourceNode && !graph.nodes.some(n=>n.id===resourceNode)){
        await load(`${api}?scope=resource&resource_id=${encodeURIComponent(route.resource_id)}`);
        route=(graph.routes||[]).find(r=>Number(r.lead_id||0)===leadId)||route;
      }
      activeRoute=route;
      const attackBtn=root.querySelector('[data-graph-preset="attack"]');
      if(attackBtn)setPreset('attack',attackBtn);else{buildScene();buildTypeFilters();applyFilters({fitAfter:true});}
      const leadNode=`lead:${leadId}`;const n=sceneNodes.find(x=>x.id===leadNode)||graph.nodes.find(x=>x.id===leadNode);
      if(n){selected=leadNode;showNode(n);focusNeighborhood(leadNode,2);render();}
      renderRoutes();
    }));
  }

  function setPreset(next,button){
    preset=next;selected=null;expandedClusters=new Set();pathStart=null;activePathIds=[];activePathEdgeIds=new Set();if(pathClearBtn)pathClearBtn.hidden=true;
    root.querySelectorAll('[data-graph-preset]').forEach(x=>x.classList.toggle('active',x===button));
    if(routePanel) routePanel.hidden = !['interesting','attack'].includes(next);
    const perspectiveCopy={
      surface:'Superficie · ¿qué existe?',identity:'Identidades · ¿qué endpoints tocó cada cuenta/sesión?',flow:'Flujos · ¿qué ocurrió y en qué orden?',objects:'Objetos · ¿en qué endpoints apareció esta cosa?',discovery:'Descubrir · ¿dónde más aparece esta pieza y qué conecta?',intelligence:'Inteligencia · ¿qué merece atención?',
      untested:'Pendientes · ¿qué no he revisado?',interesting:'Interesante · ¿dónde hay señales?',burp:'Burp · Requests observadas',attack:'Qué probar ahora · rutas de investigación',all:'Todo · vista técnica ampliada'
    };
    const helpCopy={surface:'Infraestructura y endpoints. Profundiza sólo cuando necesites detalle.',identity:'Selecciona una o dos identidades: quedan a los lados y los endpoints compartidos en el centro.',flow:'Alterna entre grafo y línea de tiempo. Las rutas siempre conservan protagonismo.',objects:'Selecciona un objeto y mira directamente los endpoints donde apareció; identidades y Flujos quedan como contexto lateral.',discovery:'Parte de una key o valor y expande únicamente relaciones observadas: endpoints, Requests, identidades, Flows y objetos cercanos.',intelligence:'Una bandeja corta de diferencias, hipótesis y hallazgos. Si no aporta una decisión, no aparece aquí.'};
    if(scopeStatusEl) scopeStatusEl.textContent=perspectiveCopy[next]||'Mapa de investigación';
    if(scopeCopyEl) scopeCopyEl.textContent=helpCopy[next]||'Cambia de lente sin perder la evidencia original.';
    updateLeadFilterVisibility();
    if(contextPanel)contextPanel.hidden=!['identity','flow','objects','discovery'].includes(next);

    const semanticScope={identity:'identities',flow:'flows',objects:'objects',discovery:'discovery',intelligence:'intelligence'}[next];
    if(semanticScope){
      detail.innerHTML=emptyDetail();search.value='';
      load(`${api}?scope=${semanticScope}`).then(()=>{
        preset=next;if(scopeStatusEl)scopeStatusEl.textContent=perspectiveCopy[next];if(scopeCopyEl)scopeCopyEl.textContent=helpCopy[next]||'';
        populateContextControls();buildScene();buildTypeFilters();buildLeadFilters();applyFilters({fitAfter:true});renderRoutes();
      });
      return;
    }

    if(next==='attack' && String(graph.meta?.scope||'overview')!=='routes') {
      detail.innerHTML=emptyDetail();search.value='';
      load(`${api}?scope=routes`).then(()=>{preset='attack';if(scopeStatusEl)scopeStatusEl.textContent=perspectiveCopy.attack;buildScene();buildTypeFilters();buildLeadFilters();applyFilters({fitAfter:true});renderRoutes();});
      return;
    }
    if(next==='burp' && String(graph.meta?.scope||'overview')!=='burp') {
      detail.innerHTML=emptyDetail();search.value='';
      load(`${api}?scope=burp&exchanges=160`).then(()=>{preset='burp';if(scopeStatusEl)scopeStatusEl.textContent=perspectiveCopy.burp;buildScene();buildTypeFilters();buildLeadFilters();applyFilters({fitAfter:true});renderRoutes();});
      return;
    }
    const current=String(graph.meta?.scope||'overview');
    if(['surface','untested','interesting','all'].includes(next) && !['overview','host','resource'].includes(current)) {
      detail.innerHTML=emptyDetail();search.value='';
      load(`${api}?scope=overview`).then(()=>{preset=next;if(scopeStatusEl)scopeStatusEl.textContent=perspectiveCopy[next]||'Vista general';buildScene();buildTypeFilters();buildLeadFilters();applyFilters({fitAfter:true});renderRoutes();});
      return;
    }
    detail.innerHTML=emptyDetail();buildScene();buildTypeFilters();buildLeadFilters();search.value='';populateContextControls();applyFilters({fitAfter:true});renderRoutes();renderExperience();
  }

  search.addEventListener('input',()=>applyFilters());
  root.querySelectorAll('[data-graph-preset]').forEach(b=>b.addEventListener('click',()=>setPreset(b.dataset.graphPreset,b)));
  root.querySelector('[data-graph-overview]')?.addEventListener('click',()=>{const b=root.querySelector('[data-graph-preset="surface"]');setPreset('surface',b);});
  identitySelect?.addEventListener('change',()=>{
    identityEndpointMode='all';
    const iid=Number(identitySelect.value||0),cid=Number(identityCompare?.value||0);
    load(iid?`${api}?scope=identity&identity_id=${iid}${cid&&cid!==iid?`&compare_identity_id=${cid}`:''}`:`${api}?scope=identities`).then(()=>{preset='identity';populateContextControls();renderExperience();});
  });
  identityCompare?.addEventListener('change',()=>{
    identityEndpointMode='all';
    const iid=Number(identitySelect?.value||0),cid=Number(identityCompare.value||0);
    if(!iid&&cid){identitySelect.value=String(cid);identityCompare.value='';return identitySelect.dispatchEvent(new Event('change'));}
    load(iid?`${api}?scope=identity&identity_id=${iid}${cid&&cid!==iid?`&compare_identity_id=${cid}`:''}`:`${api}?scope=identities`).then(()=>{preset='identity';populateContextControls();renderExperience();});
  });
  flowSelect?.addEventListener('change',()=>{const id=Number(flowSelect.value||0);load(id?`${api}?scope=flow&flow_id=${id}`:`${api}?scope=flows`).then(()=>{preset='flow';populateContextControls();renderExperience();});});
  objectSelect?.addEventListener('change',()=>{const id=Number(objectSelect.value||0);load(id?`${api}?scope=object&object_id=${id}`:`${api}?scope=objects`).then(()=>{preset='objects';populateContextControls();renderExperience();});});
  discoveryControls?.addEventListener('submit',ev=>{ev.preventDefault();const q=String(discoveryQuery?.value||'').trim();if(!q)return;discoveryTrail=[q];openDiscoveryPivot(q,{push:false});});
  discoveryInsightsToggle?.addEventListener('click',()=>{discoveryInsightsOpen=!discoveryInsightsOpen;renderDiscoveryInsights();});
  discoveryInsightsClose?.addEventListener('click',()=>{discoveryInsightsOpen=false;renderDiscoveryInsights();});
  layerInputs.forEach(input=>input.addEventListener('change',()=>{setLayer(input.dataset.graphLayer,input.checked);buildScene();buildTypeFilters();applyFilters({fitAfter:true});configureLayerControls();}));
  discoveryCrossOnlyInput?.addEventListener('change',()=>{discoveryCrossOnly=!!discoveryCrossOnlyInput.checked;applyFilters({fitAfter:true});});
  intelligenceOnlyInput?.addEventListener('change',()=>{intelligenceOnly=Boolean(intelligenceOnlyInput.checked);applyFilters({fitAfter:true});});
  flowViewButtons.forEach(btn=>btn.addEventListener('click',()=>{
    flowViewMode=btn.dataset.flowView||'graph';
    try{localStorage.setItem(`negro.flow.map.view:${targetKey}`,flowViewMode);}catch(_){ }
    flowViewButtons.forEach(x=>x.classList.toggle('active',x===btn));
    renderExperience();
  }));
  pathClearBtn?.addEventListener('click',clearPath);
  root.querySelector('[data-graph-fit]')?.addEventListener('click',fit);
  root.querySelector('[data-graph-reset-layout]')?.addEventListener('click',()=>{clearSavedLayout();autoLayout();applyFilters({fitAfter:true});});
  root.querySelector('[data-graph-neighborhood]')?.addEventListener('click',()=>selected&&focusNeighborhood(selected,1));
  root.querySelector('[data-graph-two-hop]')?.addEventListener('click',()=>selected&&focusNeighborhood(selected,2));
  root.querySelector('[data-graph-all]')?.addEventListener('click',()=>{search.value='';activeTypes=new Set(sceneNodes.map(n=>n.type).filter(t=>t!=='cluster'));buildTypeFilters();applyFilters({fitAfter:true});});
  root.querySelector('[data-graph-lead-filter-reset]')?.addEventListener('click',()=>{
    activeLeadStatuses=new Set(['candidate','testing','interesting','confirmed']);
    activeLeadPriorities=new Set(['high','medium','low']);
    activeLeadKinds=new Set(graph.nodes.filter(n=>n.type==='lead').map(n=>String(n.meta?.type||'other')));
    buildLeadFilters();buildScene();buildTypeFilters();applyFilters({fitAfter:true});renderRoutes();
  });



  // Perspective order is personal UX state, independent of target evidence.
  const presetWrap=root.querySelector('[data-graph-presets]');
  const presetOrderKey=`negro.graph.presetOrder:${targetKey}`;
  const defaultPresetOrder=['surface','identity','flow','objects','intelligence'];
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
    const refs=(h.evidence_refs||[]).slice(0,5).map(r=>{const ex=Number(r.exchange_id||0);const href=ex?`${base}/resource/${Number(r.resource_id||0)}?exchange=${ex}#exchange-${ex}`:`${base}/resource/${Number(r.resource_id||0)}#http`;return `<a class="evidence-ref" href="${href}"><span>${r.method?`<b>${esc(r.method)}</b> `:''}<code>${esc((r.path||'')+(r.query?'?'+r.query:''))}</code></span><small>${ex?`Solicitud Burp #${ex} · `:''}${r.status!=null?`HTTP ${esc(r.status)}`:''}${r.source?` · ${esc(r.source)}`:''}</small></a>`}).join('');
    const resourceId=Number(h.resource_id||0), method=String(h.primary_method||'');
    return `<article class="graph-ai-card priority-view-${esc(priority)}" data-idea="${Number(h.lead_id||0)}"><div class="graph-ai-card-top"><div class="badges"><span class="badge hypothesis-priority priority-${esc(priority)}">${priorityLabel}</span><span class="graph-ai-kind">${esc(h.type||'hypothesis')}</span>${reasons}</div><span class="state-chip">${esc(statusUi)}</span></div><h3>${esc(h.title||'Hipótesis')}</h3>${steps?`<div class="test-plan test-plan-now"><div class="test-plan-title"><span>▶</span><h3>Prueba esto ahora</h3></div><ol class="ai-steps">${steps}</ol></div>`:''}${h.plain_language?`<div class="hypothesis-plain"><b>En simple:</b> ${esc(h.plain_language)}</div>`:''}<p><b>Por qué merece tiempo:</b> ${esc(h.why_interesting||'')}</p><p><b>Objetivo ofensivo:</b> ${esc(h.suggested_investigation||'')}</p>${refs?`<div class="hypothesis-evidence"><h3>Evidencia real</h3><div class="evidence-ref-list">${refs}</div></div>`:''}<p><b>Se vuelve interesante si:</b> ${esc(h.confirm_if||'')}</p><p><b>Descartar si:</b> ${esc(h.discard_if||'')}</p><div class="graph-ai-card-actions">${resourceId?`<a class="btn-secondary" href="${base}/resource/${resourceId}#http">Abrir evidencia HTTP</a>`:''}${resourceId&&method?`<button type="button" class="btn-secondary" data-send-repeater data-resource="${resourceId}" data-method="${esc(method)}">Enviar a Repeater →</button>`:''}<button type="button" class="btn-secondary" data-view-idea>Ver en mapa</button><button type="button" class="btn-secondary" data-idea-status="testing">Empezar prueba</button><button type="button" class="btn-secondary" data-idea-status="negative">Negativa</button><button type="button" class="btn-secondary" data-idea-status="interesting">Interesante</button><button type="button" class="btn-secondary" data-idea-status="postponed">Para después</button><button type="button" class="btn-secondary" data-idea-status="confirmed">Confirmada</button><a class="btn-secondary" href="${base}/hypotheses">Abrir hipótesis</a></div></article>`;
  }
  async function refreshGraphData(){
    const m=graph.meta||{};let u=`${api}?scope=${encodeURIComponent(m.scope||'overview')}`;if(m.host_id)u+=`&host_id=${encodeURIComponent(m.host_id)}`;if(m.resource_id)u+=`&resource_id=${encodeURIComponent(m.resource_id)}`;if(m.identity_id)u+=`&identity_id=${encodeURIComponent(m.identity_id)}`;if(m.compare_identity_id)u+=`&compare_identity_id=${encodeURIComponent(m.compare_identity_id)}`;if(m.flow_id)u+=`&flow_id=${encodeURIComponent(m.flow_id)}`;if(m.object_id)u+=`&object_id=${encodeURIComponent(m.object_id)}`;if(m.request_id)u+=`&request_id=${encodeURIComponent(m.request_id)}`;if(m.finding_id)u+=`&finding_id=${encodeURIComponent(m.finding_id)}`;
    const r=await fetch(u,{headers:{Accept:'application/json'}});if(!r.ok)throw new Error(`HTTP ${r.status}`);graph=await r.json();initLeadFilters();buildScene();buildTypeFilters();buildLeadFilters();updateLeadFilterVisibility();applyFilters({fitAfter:false});renderRoutes();renderExperience();
  }
  function bindIdeaCards(){
    aiResults?.querySelectorAll('[data-idea]').forEach(card=>{
      const leadId=Number(card.dataset.idea||0);
      card.querySelector('[data-view-idea]')?.addEventListener('click',async()=>{
        const btn=root.querySelector('[data-graph-preset="intelligence"]');if(btn)setPreset('intelligence',btn);
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

  function updateFullscreenUi(){
    const active=document.fullscreenElement===graphWorkspace;
    root.classList.toggle('is-fullscreen',active);
    graphWorkspace?.classList.toggle('is-fullscreen',active);
    if(fullscreenBtn) fullscreenBtn.textContent=active?'⤢ Salir de pantalla completa':'⛶ Pantalla completa';
    // Reflow against the *new* canvas dimensions. Reusing normal-mode or dragged
    // coordinates is what made a small graph look microscopic in fullscreen.
    fullscreenReflow=active;
    const reflow=()=>{
      try{
        if(sceneNodes.length){ autoLayout(); render(); fit(); }
      }catch(_){}
    };
    requestAnimationFrame(()=>requestAnimationFrame(reflow));
    window.setTimeout(()=>{ try{ reflow(); } finally{ fullscreenReflow=false; } },280);
  }
  if(typeof ResizeObserver!=="undefined" && canvasWrap){
    const fullscreenCanvasObserver=new ResizeObserver(()=>{
      if(document.fullscreenElement===graphWorkspace && sceneNodes.length){
        requestAnimationFrame(()=>{ try{ render(); fit(); }catch(_){} });
      }
    });
    fullscreenCanvasObserver.observe(canvasWrap);
  }
  fullscreenBtn?.addEventListener('click',async()=>{
    try{
      if(document.fullscreenElement===graphWorkspace) await document.exitFullscreen();
      else if(graphWorkspace) await graphWorkspace.requestFullscreen();
    }catch(err){ console.warn('Fullscreen no disponible',err); }
  });
  document.addEventListener('fullscreenchange',updateFullscreenUi);

  function setRoutesCollapsed(collapsed){
    root.classList.toggle('routes-collapsed',!!collapsed);
    if(routeToggleBtn) routeToggleBtn.textContent=collapsed?'Mostrar ideas':'Ocultar ideas';
    try{ localStorage.setItem(`negro.graph.routesCollapsed:${targetKey}`,collapsed?'1':'0'); }catch(_){}
    window.setTimeout(()=>{ try{fit();}catch(_){} },80);
  }
  routeToggleBtn?.addEventListener('click',()=>setRoutesCollapsed(!root.classList.contains('routes-collapsed')));
  try{ if(localStorage.getItem(`negro.graph.routesCollapsed:${targetKey}`)==='1') setRoutesCollapsed(true); }catch(_){}

  const initialParams=new URLSearchParams(window.location.search);
  const initialFocus=initialParams.get('focus');
  const initialDiscover=initialParams.get('discover');
  const initialObservation=Number(initialParams.get('observation')||0);
  let inferred='surface';
  if(routePanel) routePanel.hidden=true;
  if(initialDiscover||initialObservation){
    inferred='discovery';preset='discovery';
    root.querySelectorAll('[data-graph-preset]').forEach(x=>x.classList.toggle('active',x.dataset.graphPreset==='discovery'));
    if(discoveryQuery&&initialDiscover)discoveryQuery.value=initialDiscover;
  } else if(initialFocus){
    const typ=String(initialFocus).split(':',1)[0];
    inferred=typ==='identity'?'identity':typ==='flow'?'flow':['object','business_object'].includes(typ)?'objects':typ==='investigation'?'context':['lead','finding','anomaly'].includes(typ)?'intelligence':['request','exchange'].includes(typ)?'context':'surface';
    preset=inferred;
    root.querySelectorAll('[data-graph-preset]').forEach(x=>x.classList.toggle('active',x.dataset.graphPreset===inferred));
  }
  const initialUrl=initialObservation?`${api}?scope=discovery&observation_id=${initialObservation}&exchanges=180`:initialDiscover?`${api}?scope=discovery&q=${encodeURIComponent(initialDiscover)}&exchanges=180`:initialFocus?`${api}?focus=${encodeURIComponent(initialFocus)}`:null;
  load(initialUrl).then(()=>{
    populateContextControls();
    if(initialFocus&&!initialDiscover&&!initialObservation){
      const canonical=graph.meta?.focus_node||initialFocus;
      const n=sceneNodes.find(x=>x.id===canonical)||graph.nodes?.find(x=>x.id===canonical);
      if(n){selected=n.id;showNode(n);if(!canvasShell?.hidden){if(['identity','flow','objects'].includes(inferred))fit();else focusNeighborhood(n.id,1);}}
    }
  });
})();
