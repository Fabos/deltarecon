(() => {
  const root = document.querySelector('[data-surface-root]');
  if (!root) return;

  const api = root.dataset.api;
  const rootDomain = root.dataset.rootDomain || '';
  const svg = root.querySelector('[data-surface-svg]');
  const stage = root.querySelector('[data-map-stage]');
  const workspace = root.querySelector('[data-surface-workspace]');
  const detail = root.querySelector('[data-surface-detail]');
  const grid = root.querySelector('[data-host-grid]');
  const runList = root.querySelector('[data-run-list]');
  const empty = root.querySelector('[data-map-empty]');
  const visibleCount = root.querySelector('[data-visible-count]');
  const search = root.querySelector('[data-filter-search]');
  const layerEls = [...root.querySelectorAll('[data-layer]')];
  const collapseFamilies = root.querySelector('[data-collapse-families]');
  const viewBtns = [...root.querySelectorAll('[data-surface-view]')];
  const viewPanels = [...root.querySelectorAll('[data-view-panel]')];
  const importPanel = root.querySelector('[data-import-panel]');
  const fullscreenBtn = root.querySelector('[data-surface-fullscreen]');
  const NS = 'http://www.w3.org/2000/svg';

  let data = {hosts:[], filters:{}, summary:{}, tool_runs:[]};
  let selectedHost = '';
  let view = {x: 20, y: 20, k: 1};
  let pan = null;
  let nodeDrag = null;
  let suppressClickUntil = 0;
  let sceneExtent = {width:1460,height:760};
  const manualPositions = new Map();
  const expandedHosts = new Set();
  const expandedFamilies = new Set();
  const expandedRoots = new Set([rootDomain]);
  const expandedRootsStateKey = `negro.surface.expandedRoots:${window.location.pathname}`;
  try{
    const saved=JSON.parse(sessionStorage.getItem(expandedRootsStateKey)||'[]');
    if(Array.isArray(saved)) saved.forEach(x=>{if(x)expandedRoots.add(String(x));});
  }catch(_){}
  const persistExpandedRoots=()=>{try{sessionStorage.setItem(expandedRootsStateKey,JSON.stringify([...expandedRoots]));}catch(_){}};
  const selectedFilters = {root:new Set(), technology:new Set(), server:new Set(), provider:new Set(), environment:new Set(), status:new Set(), family:new Set(), source:new Set()};
  const facetLabels = {root:'Target',technology:'Tecnología',server:'Servidor',provider:'Proveedor',environment:'Ambiente',status:'Status',family:'Familia',source:'Fuente'};

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
  const brandVisual = value => {
    const text=String(value||'').toLowerCase();
    const rules=[
      [/cloudflare/,['cloudflare','CF']],
      [/fastly/,['fastly','F']],
      [/amazon web services|amazon cloudfront|amazon s3|amazon alb|aws/,['aws','AWS']],
      [/google cloud/,['gcp','GCP']],
      [/microsoft asp\.net|asp\.net|microsoft iis|iis windows|microsoft-httpapi|office365|microsoft/,['microsoft','MS']],
      [/platform\.sh/,['platformsh','P.SH']],
      [/keycloak/,['keycloak','KC']],
      [/next\.js|nextjs/,['nextjs','N']],
      [/node\.js|nodejs/,['nodejs','JS']],
      [/react/,['react','⚛']],
      [/php/,['php','PHP']],
      [/symfony/,['symfony','SF']],
      [/ibexa/,['ibexa','IX']],
      [/sap/,['sap','SAP']],
      [/salesforce/,['salesforce','SFDC']],
      [/express/,['express','EX']],
      [/apache/,['apache','AP']],
      [/nginx/,['nginx','NG']],
      [/varnish/,['varnish','V']],
      [/envoy/,['envoy','EV']],
      [/cloudfront/,['aws','AWS']],
      [/webpack/,['webpack','WP']],
      [/bootstrap/,['bootstrap','BS']],
      [/jquery/,['jquery','jQ']]
    ];
    for(const [re,v] of rules){if(re.test(text))return {key:v[0],icon:v[1]};}
    return null;
  };

  function fillSelect(){ /* legacy no-op: facets replaced single-selects in v0.82 */ }
  function allHosts(){ return (data.project_hosts && data.project_hosts.length) ? data.project_hosts : (data.hosts||[]); }
  function facetHostValues(h,name){
    if(name==='root') return [h.root_domain||rootDomain];
    if(name==='technology') return h.technologies||[];
    if(name==='server') return h.servers||[];
    if(name==='provider') return h.providers||[];
    if(name==='environment') return [h.environment||'UNKNOWN'];
    if(name==='status') return h.status_code!==null&&h.status_code!==undefined?[String(h.status_code)]:[];
    if(name==='family') return [h.family||'other'];
    if(name==='source') return h.sources||[];
    return [];
  }
  function exactFacetCount(name,value){
    return allHosts().filter(h=>facetHostValues(h,name).map(String).includes(String(value))).length;
  }
  function renderFacet(name, values){
    const box=root.querySelector(`[data-filter-facet="${name}"]`); if(!box)return;
    const uniq=[...new Set((values||[]).map(String))].sort((a,b)=>a.localeCompare(b));
    box.dataset.values=JSON.stringify(uniq);
    box.innerHTML=`<span>${esc(facetLabels[name]||name)}</span>
      <button type="button" class="surface-facet-trigger" data-facet-trigger><b data-facet-caption>Todas</b><i>⌄</i></button>
      <div class="surface-facet-menu" data-facet-menu hidden>
        <input type="search" class="surface-facet-search" data-facet-search placeholder="Buscar ${esc((facetLabels[name]||name).toLowerCase())}…" autocomplete="off">
        <div class="surface-facet-tools"><small data-facet-summary></small><span><button type="button" data-facet-select-all>Seleccionar visibles</button><button type="button" data-facet-clear>Limpiar</button></span></div>
        <div class="surface-facet-options" data-facet-options></div>
      </div>`;
    const trigger=box.querySelector('[data-facet-trigger]'), menu=box.querySelector('[data-facet-menu]'), q=box.querySelector('[data-facet-search]');
    const draw=()=>{
      const needle=(q?.value||'').trim().toLowerCase();
      const shown=uniq.filter(v=>!needle||v.toLowerCase().includes(needle));
      const sel=selectedFilters[name];
      box.querySelector('[data-facet-options]').innerHTML=shown.length?shown.map(v=>`<label class="surface-facet-option"><input type="checkbox" value="${esc(v)}" ${sel.has(v)?'checked':''}><span>${esc(v)}</span><small>${exactFacetCount(name,v)} hosts</small></label>`).join(''):'<div class="surface-facet-none">Sin coincidencias</div>';
      const hostUnion=new Set(); shown.forEach(v=>allHosts().forEach(h=>{if(facetHostValues(h,name).map(String).includes(v))hostUnion.add(h.hostname)}));
      box.querySelector('[data-facet-summary]').textContent=`${shown.length} opciones · ${hostUnion.size} hosts`;
      const caption=box.querySelector('[data-facet-caption]'); caption.textContent=sel.size?`${sel.size} seleccionados`:'Todas';
      trigger.classList.toggle('active',sel.size>0);
      box.querySelectorAll('.surface-facet-option input').forEach(cb=>cb.addEventListener('change',()=>{
        if(cb.checked)sel.add(cb.value);else sel.delete(cb.value); draw(); refresh();
      }));
    };
    trigger.addEventListener('click',e=>{e.stopPropagation();document.querySelectorAll('.surface-facet-menu').forEach(x=>{if(x!==menu)x.hidden=true});menu.hidden=!menu.hidden;if(!menu.hidden){q?.focus();draw();}});
    menu.addEventListener('click',e=>e.stopPropagation());
    q?.addEventListener('input',draw);
    box.querySelector('[data-facet-select-all]')?.addEventListener('click',()=>{const needle=(q?.value||'').trim().toLowerCase();uniq.filter(v=>!needle||v.toLowerCase().includes(needle)).forEach(v=>selectedFilters[name].add(v));draw();refresh();});
    box.querySelector('[data-facet-clear]')?.addEventListener('click',()=>{selectedFilters[name].clear();draw();refresh();});
    box._facetDraw=draw; draw();
  }
  function redrawFacets(){root.querySelectorAll('[data-filter-facet]').forEach(box=>box._facetDraw?.());}
  function selectedLayers(){ return new Set(layerEls.filter(x=>x.checked).map(x=>x.dataset.layer)); }
  function filters(){ return {q:(search?.value||'').trim().toLowerCase()}; }
  function haystack(h){
    return [h.root_domain,h.hostname,h.title,h.url,h.webserver,h.location,h.family,h.environment,h.status_code,h.takeover_state,h.takeover_confidence,h.takeover_target,
      ...(h.technologies||[]),...(h.providers||[]),...(h.servers||[]),...(h.ips||[]),...(h.historical_ips||[]),...(h.candidate_ips||[]),...(h.possible_origin_ips||[]),...(h.direct_infra_ips||[]),...(h.edge_ips||[]),...(h.cnames||[]),...(h.sources||[])].join(' ').toLowerCase();
  }
  function matchesSelected(h,name){
    const sel=selectedFilters[name]; if(!sel||!sel.size)return true;
    const vals=facetHostValues(h,name).map(String);
    return vals.some(v=>sel.has(v));
  }
  function visibleHosts(){
    const f=filters();
    return allHosts().filter(h => {
      if(f.q && !haystack(h).includes(f.q)) return false;
      for(const name of Object.keys(selectedFilters)){if(!matchesSelected(h,name))return false;}
      return true;
    });
  }
  function setSingleFilter(name,value){selectedFilters[name].clear();if(value)selectedFilters[name].add(String(value));redrawFacets();}
  function addFilter(name,value){if(value)selectedFilters[name].add(String(value));redrawFacets();}
  function node(type,id,label,meta={}){ return {type,id:`${type}:${id}`,key:id,label,meta}; }
  function edge(source,target,relation,kind='observed'){ return {source,target,relation,kind}; }

  function addHostLayers(scene, h, hid, layers){
    const {add, edges} = scene;
    if(layers.has('provider')) (h.providers||[]).forEach(p=>{const id=add(node('provider',p,p));edges.push(edge(hid,id,'PROXIED_BY','observed'));});
    if(layers.has('technology')) (h.technologies||[]).forEach(t=>{const id=add(node('technology',t,t));edges.push(edge(hid,id,'USES','fingerprint'));});
    if(layers.has('server')) (h.servers||[]).forEach(s=>{const id=add(node('server',s,s));edges.push(edge(hid,id,'SERVED_BY','fingerprint'));});
    if(layers.has('ip')) {
      const origins=new Set(h.possible_origin_ips||[]), direct=new Set(h.direct_infra_ips||[]), edgeIps=new Set(h.edge_ips||[]);
      const elevated=new Set([...origins,...direct]);
      [...origins].slice(0,6).forEach(ip=>{const id=add(node('ip',ip,ip,{origin:true}));edges.push(edge(hid,id,'POSSIBLE_ORIGIN','correlated'));});
      [...direct].filter(ip=>!origins.has(ip)).slice(0,6).forEach(ip=>{const id=add(node('ip',ip,ip,{direct:true}));edges.push(edge(hid,id,'DIRECT_INFRA_IP','hypothesis'));});
      (h.ips||[]).filter(ip=>!elevated.has(ip)).slice(0,6).forEach(ip=>{const isEdge=edgeIps.has(ip);const id=add(node('ip',ip,ip,{historical:false,edge:isEdge}));edges.push(edge(hid,id,isEdge?'EDGE_IP':'OBSERVED_IP',isEdge?'edge':'observed'));});
      (h.historical_ips||[]).filter(ip=>!(h.ips||[]).includes(ip) && !elevated.has(ip)).slice(0,6).forEach(ip=>{const id=add(node('ip',ip,ip,{historical:true}));edges.push(edge(hid,id,'HISTORICAL_RESOLVES_TO','historical'));});
      (h.candidate_ips||[]).filter(ip=>!(h.ips||[]).includes(ip) && !(h.historical_ips||[]).includes(ip) && !elevated.has(ip)).slice(0,6).forEach(ip=>{const id=add(node('ip',ip,ip,{candidate:true}));edges.push(edge(hid,id,'CANDIDATE_INFRA_IP','hypothesis'));});
    }
  }

  function buildScene(hosts){
    const layers=selectedLayers();
    const grouped=!!collapseFamilies?.checked;
    const nodes=[]; const edges=[]; const seen=new Set();
    const add=n=>{ if(!seen.has(n.id)){seen.add(n.id);nodes.push(n);} return n.id; };
    const roots=(data.roots||[rootDomain]);
    const multiRoot=(data.roots||[]).length>1;
    const projectId=multiRoot?add(node('project','project',`PROJECT · ${(data.roots||[]).length} targets`,{count:(data.roots||[]).length})):null;
    const scene={nodes,edges,add,multiRoot,roots};

    roots.forEach(rr=>{
      const rootHosts=hosts.filter(h=>(h.root_domain||rootDomain)===rr);
      const rootAsset=rootHosts.find(h=>h.hostname===rr)||null;
      const childHosts=rootHosts.filter(h=>h.hostname!==rr);
      const rid=add(node('root',rr,`ROOT · ${rr}`,{count:childHosts.length,active:rr===rootDomain,host:rootAsset}));
      if(projectId) edges.push(edge(projectId,rid,'CONTAINS','observed'));
      const shouldOpen=!multiRoot || expandedRoots.has(rr);
      if(!shouldOpen)return;
      // The recon root is also a real hostname.  Its technical context belongs
      // directly to the ROOT node instead of being duplicated as a fake child.
      if(rootAsset) addHostLayers(scene,rootAsset,rid,layers);

      const rawFamilies=new Map();
      childHosts.forEach(h=>{
        const family=(h.family||'other').trim()||'other';
        if(!rawFamilies.has(family))rawFamilies.set(family,[]);
        rawFamilies.get(family).push(h);
      });
      const families=new Map(); const singletons=[];
      for(const [family,items] of rawFamilies.entries()){
        if(grouped&&items.length===1)singletons.push(items[0]); else families.set(family,items);
      }
      if(grouped&&singletons.length)families.set('__ungrouped__',singletons);

      [...families.entries()].sort((a,b)=>a[0].localeCompare(b[0])).forEach(([family,items])=>{
        items.sort((a,b)=>a.hostname.localeCompare(b.hostname));
        if(!grouped){
          items.forEach(h=>{const hid=add(node('host',h.hostname,h.hostname,h));edges.push(edge(rid,hid,'CONTAINS','observed'));if(expandedHosts.has(h.hostname)) addHostLayers(scene,h,hid,layers);});
          return;
        }
        const isUngrouped=family==='__ungrouped__';
        const label=isUngrouped?'Otros / sin agrupar':family;
        const familyKey=`${rr}::${family}`;
        const fid=add(node('family',familyKey,label,{count:items.length,heuristic:!isUngrouped,hosts:items.map(x=>x.hostname),ungrouped:isUngrouped,root_domain:rr,family}));
        edges.push(edge(rid,fid,isUngrouped?'CONTAINS':'POSSIBLE_FAMILY',isUngrouped?'observed':'heuristic'));
        // Single-root equivalent retained conceptually: if(!expandedFamilies.has(family)) return;
        if(!expandedFamilies.has(familyKey))return;
        items.forEach(h=>{const hid=add(node('host',h.hostname,h.hostname,h));edges.push(edge(fid,hid,isUngrouped?'CONTAINS':'GROUPS',isUngrouped?'observed':'heuristic'));if(expandedHosts.has(h.hostname)) addHostLayers(scene,h,hid,layers);});
      });
    });

    const visibleHostNodes=new Set(scene.nodes.filter(n=>n.type==='host').map(n=>n.key));
    hosts.forEach(h=>(h.redirects||[]).forEach(dst=>{if(visibleHostNodes.has(h.hostname)&&visibleHostNodes.has(dst))edges.push(edge(`host:${h.hostname}`,`host:${dst}`,'REDIRECTS_TO','observed'));}));
    return {nodes,edges,collapsed:grouped,multiRoot,roots};
  }

  function layout(scene){
    const pos=new Map();
    const project=scene.nodes.find(n=>n.type==='project');
    const roots=scene.nodes.filter(n=>n.type==='root');
    const familyChildren=new Map();
    scene.edges.filter(e=>e.source.startsWith('family:')&&e.target.startsWith('host:')).forEach(e=>{if(!familyChildren.has(e.source))familyChildren.set(e.source,[]);familyChildren.get(e.source).push(e.target);});
    const rootFamilies=new Map(); const rootHosts=new Map();
    scene.edges.forEach(e=>{
      if(e.source.startsWith('root:')&&e.target.startsWith('family:')){if(!rootFamilies.has(e.source))rootFamilies.set(e.source,[]);rootFamilies.get(e.source).push(e.target);}
      if(e.source.startsWith('root:')&&e.target.startsWith('host:')){if(!rootHosts.has(e.source))rootHosts.set(e.source,[]);rootHosts.get(e.source).push(e.target);}
    });
    const rootX=scene.multiRoot?330:110, familyX=scene.multiRoot?620:390, hostX=scene.multiRoot?920:690;
    let y=55;
    roots.forEach(r=>{
      const famIds=rootFamilies.get(r.id)||[]; const directIds=rootHosts.get(r.id)||[];
      const startY=y;
      if(famIds.length||directIds.length){
        famIds.forEach(fid=>{
          const kids=familyChildren.get(fid)||[]; const block=kids.length?Math.max(82,kids.length*58):58;
          pos.set(fid,{x:familyX,y:y+block/2}); kids.forEach((id,i)=>pos.set(id,{x:hostX,y:y+30+i*56})); y+=block+28;
        });
        directIds.forEach(id=>{pos.set(id,{x:hostX,y:y+24});y+=62;});
        pos.set(r.id,{x:rootX,y:Math.max(startY+28,(startY+y)/2)}); y+=34;
      }else{pos.set(r.id,{x:rootX,y:y+28});y+=82;}
    });
    if(project)pos.set(project.id,{x:90,y:Math.max(110,Math.min(Math.max(220,y/2),620))});

    const typeBase=hostX+290;
    const typeX={provider:typeBase,technology:typeBase+230,server:typeBase+460,ip:typeBase+690};
    const rightTypes=['provider','technology','server','ip']; let maxRightY=0;
    rightTypes.forEach(type=>{
      const list=scene.nodes.filter(n=>n.type===type).map(n=>{const sourceY=scene.edges.filter(e=>e.target===n.id).map(e=>pos.get(e.source)?.y).filter(v=>Number.isFinite(v));return {n,desired:sourceY.length?sourceY.reduce((a,b)=>a+b,0)/sourceY.length:80};}).sort((a,b)=>a.desired-b.desired||a.n.label.localeCompare(b.n.label));
      let cursor=46; list.forEach(({n,desired})=>{const yy=Math.max(desired,cursor);pos.set(n.id,{x:typeX[type],y:yy});cursor=yy+48;maxRightY=Math.max(maxRightY,yy);});
    });
    for(const n of scene.nodes){if(manualPositions.has(n.id))pos.set(n.id,{...manualPositions.get(n.id)});}
    const activeTypes=rightTypes.filter(t=>scene.nodes.some(n=>n.type===t));
    const width=activeTypes.length?typeX[activeTypes[activeTypes.length-1]]+150:hostX+220;
    const height=Math.max(560,y+40,maxRightY+70);
    return {pos,width,height};
  }

  function svgEl(tag,attrs={}){const el=document.createElementNS(NS,tag);Object.entries(attrs).forEach(([k,v])=>el.setAttribute(k,String(v)));return el;}
  function canvasSize(){ return {width:Math.max(720,stage?.clientWidth||1460),height:Math.max(480,stage?.clientHeight||760)}; }
  function relatedHosts(scene,n){
    if(n.type==='host') return [n.meta];
    if(n.type==='family') return (n.meta?.hosts||[]).map(h=>allHosts().find(x=>x.hostname===h)).filter(Boolean);
    if(n.type==='root') return allHosts().filter(h=>(h.root_domain||rootDomain)===n.key);
    if(n.type==='project') return allHosts();
    const ids=new Set(scene.edges.filter(e=>e.target===n.id&&e.source.startsWith('host:')).map(e=>e.source.slice(5)));
    return allHosts().filter(h=>ids.has(h.hostname));
  }

  function renderGraph(){
    const hosts=visibleHosts();
    if(visibleCount) visibleCount.textContent=String(hosts.length);
    const scene=buildScene(hosts);
    if(empty) empty.hidden=hosts.length>0;
    svg.innerHTML='';
    const {pos,width,height}=layout(scene); sceneExtent={width,height};
    const cs=canvasSize();
    svg.setAttribute('viewBox',`0 0 ${cs.width} ${cs.height}`);
    const world=svgEl('g',{transform:`translate(${view.x} ${view.y}) scale(${view.k})`}); svg.appendChild(world);

    scene.edges.forEach(e=>{
      const a=pos.get(e.source), b=pos.get(e.target); if(!a||!b)return;
      const path=svgEl('path',{d:`M ${a.x+72} ${a.y} C ${a.x+155} ${a.y}, ${b.x-155} ${b.y}, ${b.x-72} ${b.y}`,class:`surface-edge ${e.kind}`});
      const title=svgEl('title'); title.textContent=e.relation; path.appendChild(title); world.appendChild(path);
    });

    scene.nodes.forEach(n=>{
      const p=pos.get(n.id); if(!p)return;
      const brand=['provider','technology','server'].includes(n.type)?brandVisual(n.label):null;
      const g=svgEl('g',{class:`surface-node ${n.type}${brand?` brand-${brand.key}`:''}${n.type==='host'&&selectedHost===n.key?' selected':''}${n.type==='root'&&n.meta?.active?' active-root':''}${n.type==='ip'&&n.meta?.origin?' possible-origin':''}${n.type==='ip'&&n.meta?.direct?' direct-infra':''}${n.type==='ip'&&n.meta?.edge?' shared-edge':''}${n.type==='ip'&&n.meta?.historical?' historical-ip':''}`,transform:`translate(${p.x} ${p.y})`,tabindex:'0','data-node-id':n.id});
      const hostEnv=n.type==='host'?String(n.meta?.environment||'UNKNOWN').toUpperCase():'UNKNOWN';
      const showHostEnv=n.type==='host' && hostEnv && hostEnv!=='UNKNOWN';
      const w=n.type==='host'?(showHostEnv?260:230):n.type==='family'?210:n.type==='root'?220:n.type==='project'?190:(brand?210:190);
      const h=n.type==='family'&&scene.collapsed?44:n.type==='host'?40:32;
      const rect=svgEl('rect',{x:-w/2,y:-h/2,width:w,height:h,rx:n.type==='host'?9:14}); g.appendChild(rect);
      const hostTextX=showHostEnv?(-w/2+21):0;
      const branded=!!brand && n.type!=='host';
      const textX=branded?(-w/2+44):hostTextX;
      const text=svgEl('text',{x:textX,y:scene.collapsed&&n.type==='family'?-2:4,'text-anchor':branded||showHostEnv?'start':'middle'});
      text.textContent=short(n.label,n.type==='host'?(showHostEnv?27:31):(branded?24:28)); g.appendChild(text);
      if(branded){
        const mark=svgEl('g',{class:`surface-brand-mark brand-${brand.key}`,transform:`translate(${-w/2+22} 0)`});
        mark.appendChild(svgEl('rect',{x:-15,y:-10,width:30,height:20,rx:7}));
        const markText=svgEl('text',{x:0,y:3,'text-anchor':'middle'});markText.textContent=brand.icon;mark.appendChild(markText);
        g.appendChild(mark);
      }
      if(n.type==='family'&&scene.collapsed){const count=svgEl('text',{x:0,y:13,'text-anchor':'middle',class:'surface-node-sub'});count.textContent=`${n.meta.count} hosts${expandedFamilies.has(n.key)?' · abierto':''}`;g.appendChild(count);}
      if(n.type==='host'){
        const dot=svgEl('circle',{cx:-w/2+10,cy:0,r:4,class:`status-dot ${codeClass(n.meta.status_code)}`});g.appendChild(dot);
        if(showHostEnv){
          const badgeW=Math.max(36,hostEnv.length*6+14);
          const badge=svgEl('g',{class:`surface-env-badge ${envClass(hostEnv)}`,transform:`translate(${w/2-badgeW/2-8} 0)`});
          badge.appendChild(svgEl('rect',{x:-badgeW/2,y:-9,width:badgeW,height:18,rx:9}));
          const badgeText=svgEl('text',{x:0,y:3,'text-anchor':'middle'});badgeText.textContent=hostEnv==='STAGING'?'STG':hostEnv;badge.appendChild(badgeText);
          g.appendChild(badge);
        }
      }
      const title=svgEl('title'); title.textContent=`${n.label} · ${n.type==='root'?(expandedRoots.has(n.key)?'clic para recoger target':'clic para abrir target'):n.type==='family'?(expandedFamilies.has(n.key)?'clic para recoger familia':'clic para abrir familia'):n.type==='host'?(expandedHosts.has(n.key)?'clic para recoger capas':'clic para abrir capas'):'clic para revisar'} · arrastra para reorganizar`; g.appendChild(title);

      const activateNode=()=>{
        if(n.type==='project'){renderNodeDetail(n,scene);return;}
        if(n.type==='root'){
          if(expandedRoots.has(n.key)) expandedRoots.delete(n.key); else expandedRoots.add(n.key);
          persistExpandedRoots();
          if(n.meta?.host) renderDetail(n.meta.host); else renderNodeDetail(n,scene);
          renderGraph();
          return;
        }
        if(n.type==='family'){toggleFamily(n.key);return;}
        if(n.type==='host'){
          const wasExpanded=expandedHosts.has(n.key);
          selectedHost=n.key;
          if(wasExpanded) expandedHosts.delete(n.key);
          else expandedHosts.add(n.key);
          renderDetail(n.meta);
          renderGraph();
          // Host drill-down is a true toggle: first click opens technical layers,
          // second click folds them back while keeping the evidence panel selected.
          // The user's current pan/zoom remains untouched.
          return;
        }
        renderNodeDetail(n,scene);
      };
      g.addEventListener('pointerdown',ev=>{
        ev.stopPropagation();
        nodeDrag={id:n.id,g,startX:ev.clientX,startY:ev.clientY,baseX:p.x,baseY:p.y,x:p.x,y:p.y,moved:false,pointerId:ev.pointerId,activate:activateNode};
        svg.setPointerCapture?.(ev.pointerId);
        g.classList.add('dragging');
      });
      // Pointer-up owns activation. Rendering the SVG on pointer-up before the native
      // click fires removes the original node from the DOM and swallows the click.
      // Keeping activation here makes family/host drill-down reliable while still
      // allowing the exact same gesture to become a drag once movement is detected.
      g.addEventListener('click',ev=>{
        ev.stopPropagation();
        if(Date.now()<suppressClickUntil)return;
        activateNode();
      });
      g.addEventListener('dblclick',ev=>{ev.stopPropagation();if(n.type==='family')enterFamily(n.meta?.family||n.key,n.meta?.root_domain||'');else if(n.type==='root')window.location.href=`${window.location.pathname}?root=${encodeURIComponent(n.key)}`;});
      g.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();activateNode();}});
      world.appendChild(g);
    });
  }

  function tags(items,cls=''){return (items||[]).map(x=>`<span class="surface-chip ${cls}">${esc(x)}</span>`).join('');}
  function renderDetail(h){
    if(!h){detail.innerHTML='<div class="surface-detail-empty"><span class="surface-detail-icon">◎</span><b>Selecciona una rama</b><p>Abre una familia o hostname para reducir ruido y revisar evidencia.</p></div>';return;}
    const sharedEdge=(h.providers||[]).some(x=>/cloudflare|fastly|cloudfront|akamai/i.test(x)) || (h.edge_ips||[]).length>0;
    const isReconRoot=(data.roots||[]).includes(h.hostname);
    detail.innerHTML=`
      <div class="surface-detail-head"><div><span class="eyebrow">${isReconRoot?'ROOT / HOSTNAME':'HOSTNAME'}</span><h2>${esc(h.hostname)}</h2></div>${h.status_code?`<span class="surface-status ${codeClass(h.status_code)}">${esc(h.status_code)}</span>`:'<span class="surface-status unknown">HTTP ?</span>'}</div>
      ${isReconRoot?`<a class="button ghost full" href="${window.location.pathname}?root=${encodeURIComponent(h.hostname)}">${h.hostname===rootDomain?'Target activo':'Trabajar este target →'}</a>`:''}
      ${h.title?`<p class="surface-title">${esc(h.title)}</p>`:''}
      <div class="surface-detail-grid"><div><span>Ambiente</span><b class="env-${envClass(h.environment)}">${esc(h.environment||'UNKNOWN')}</b></div><div><span>Familia</span><b>${esc(h.family||'—')}</b><small>heurística</small></div><div><span>DNS</span><b>${esc(h.dns_state||'UNKNOWN')}</b></div><div><span>HTTP</span><b>${esc(h.http_state||'UNKNOWN')}</b></div></div>
      ${h.takeover_state==='CANDIDATE'?`<div class="callout warning"><b>Takeover candidate · ${esc(h.takeover_confidence||'')}</b><p>CNAME → ${esc(h.takeover_target||'—')} · claimability no validada.</p></div>`:''}
      <section><h3>Tecnologías</h3><div class="surface-chips">${tags(h.technologies,'technology')||'<span class="muted">Sin fingerprint</span>'}</div></section>
      <section><h3>Entrega / proveedor</h3><div class="surface-chips">${tags(h.providers,'provider')||'<span class="muted">No identificado</span>'}</div></section>
      <section><h3>Servidor observado</h3><div class="surface-chips">${tags(h.servers,'server')||'<span class="muted">No identificado</span>'}</div></section>
      <section><h3>DNS / red</h3><dl class="surface-kv"><dt>IP actual observada</dt><dd>${(h.ips||[]).map(esc).join('<br>')||'—'}</dd><dt>IP histórica</dt><dd>${(h.historical_ips||[]).map(ip=>`<span class="surface-historical-ip">${esc(ip)} · HISTÓRICA</span>`).join('<br>')||'—'}</dd><dt>IP candidata manual</dt><dd>${(h.candidate_ips||[]).map(ip=>`<span>${esc(ip)} · SIN CORRELACIONAR</span>`).join('<br>')||'—'}</dd><dt>CNAME</dt><dd>${(h.cnames||[]).map(esc).join('<br>')||'—'}</dd><dt>Possible origin</dt><dd>${(h.possible_origin_ips||[]).map(ip=>`<b>${esc(ip)}</b> · HIGH/CORRELATED`).join('<br>')||'UNKNOWN'}</dd><dt>Direct infra</dt><dd>${(h.direct_infra_ips||[]).map(ip=>`${esc(ip)} · CANDIDATE`).join('<br>')||'—'}</dd></dl></section>
      ${(h.infrastructure||[]).length?`<section><h3>Infrastructure Classification</h3><div class="surface-infra-list">${(h.infrastructure||[]).map(x=>`<div><b>${esc(x.ip||'')}</b><span>${esc(x.classification||'UNCLASSIFIED')} · ${esc(x.confidence||'')}</span><small>${x.tls_hostname_match?'TLS/SNI match · ':''}${x.content_hash_match?'SHA256 match · ':''}${x.owner?esc(x.owner):''}</small><em>Nmap: ${esc(x.nmap_eligibility||'NOT_READY')}</em></div>`).join('')}</div></section>`:''}
      ${h.location?`<section><h3>Redirect</h3><code class="surface-code">${esc(h.location)}</code></section>`:''}
      <section><h3>Siguiente lectura</h3><div class="surface-action-note ${(h.nmap_candidate_ips||[]).length?'':'caution'}">${(h.nmap_candidate_ips||[]).length?`Hay ${h.nmap_candidate_ips.length} IP(s) candidata(s) para enumeración de servicios DESPUÉS de validar scope: ${(h.nmap_candidate_ips||[]).map(esc).join(', ')}.`:(sharedEdge?'Nmap no se recomienda sobre la IP observada: parece edge/CDN compartido. Profundiza por hostname, TLS, HTTP o busca origin con evidencia.':'Aún no hay una IP elevada por Infrastructure Classification. Valida propiedad/scope y correlación antes de Nmap.')}</div></section>
      <section><h3>Evidencia</h3><div class="surface-chips">${tags(h.sources,'source')}</div><small class="muted">Última observación: ${esc(h.last_seen_at||'—')}</small></section>
      ${h.url?`<a class="button ghost full" target="_blank" rel="noopener noreferrer" href="${esc(h.url)}">Abrir host ↗</a>`:''}`;
  }


  function toggleFamily(name){
    if(expandedFamilies.has(name)) expandedFamilies.delete(name);
    else expandedFamilies.add(name);
    selectedHost='';
    renderDetail(null);
    renderGraph();
    // Expanding/collapsing a family must not steal the user's viewport.
  }

  function enterFamily(name){
    const rr=arguments[1]||'';
    setSingleFilter('family',name); if(rr)setSingleFilter('root',rr);
    if(collapseFamilies) collapseFamilies.checked=false;
    selectedHost=''; renderDetail(null); refresh(); fit();
  }

  function applyNodeFilter(n){
    if(n.type==='technology')addFilter('technology',n.key);
    else if(n.type==='provider')addFilter('provider',n.key);
    else if(n.type==='server')addFilter('server',n.key);
    else if(n.type==='root')addFilter('root',n.key);
    else if(n.type==='ip'){if(search)search.value=n.key;}
    refresh();fit();
  }

  function renderNodeDetail(n,scene){
    const related=relatedHosts(scene,n);
    const family=n.type==='family';
    const filterable=['technology','provider','server','ip'].includes(n.type);
    detail.innerHTML=`
      <div class="surface-detail-head"><div><span class="eyebrow">${esc(n.type.toUpperCase())}</span><h2>${esc(n.label)}</h2></div></div>
      <p class="muted">${family?'Agrupación heurística: sirve para reducir el mapa, no afirma que todos los hosts compartan backend.':n.type==='project'?'Vista de proyecto: contiene todos los targets/root de recon confirmados.':n.type==='root'?'Target/root de recon. Un clic abre o recoge su árbol; las cards de fases pertenecen al root activo.':'Nodo contextual derivado de la evidencia. Úsalo para pivotar sobre los hosts relacionados.'}</p>
      <div class="surface-big-number">${esc(related.length || n.meta?.count || 0)} <small>hosts relacionados</small></div>
      ${n.type==='root'?`<a class="button full" href="${window.location.pathname}?root=${encodeURIComponent(n.key)}">${n.meta?.active?'Target activo':'Trabajar este target →'}</a>`:''}
      ${related.length?`<section><h3>Relacionados</h3><div class="surface-related-hosts">${related.slice(0,14).map(h=>`<button type="button" data-related-host="${esc(h.hostname)}">${esc(h.hostname)}</button>`).join('')}${related.length>14?`<small>+${related.length-14} más</small>`:''}</div></section>`:''}
      ${family?'<button class="button full" type="button" data-enter-family>Enfocar solo esta familia</button>':''}
      ${filterable?'<button class="button ghost full" type="button" data-filter-node>Filtrar mapa por este nodo</button>':''}`;
    detail.querySelector('[data-enter-family]')?.addEventListener('click',()=>enterFamily(n.meta?.family||n.key,n.meta?.root_domain||''));
    detail.querySelector('[data-filter-node]')?.addEventListener('click',()=>applyNodeFilter(n));
    detail.querySelectorAll('[data-related-host]').forEach(btn=>btn.addEventListener('click',()=>{
      const h=allHosts().find(x=>x.hostname===btn.dataset.relatedHost);if(!h)return;
      selectedHost=h.hostname; expandedHosts.add(h.hostname); if(collapseFamilies) collapseFamilies.checked=false; renderDetail(h); renderGraph();
    }));
  }

  function renderInventory(){
    const hosts=visibleHosts(); if(visibleCount)visibleCount.textContent=String(hosts.length);
    grid.innerHTML = hosts.length ? hosts.map(h=>`<article class="surface-host-card" data-host-card="${esc(h.hostname)}"><div class="surface-host-card-head"><div><span class="surface-host-dot ${codeClass(h.status_code)}"></span><b>${esc(h.hostname)}</b><small>${esc(h.title||'')}</small></div>${h.status_code?`<span class="surface-status ${codeClass(h.status_code)}">${esc(h.status_code)}</span>`:'<span class="surface-status unknown">?</span>'}</div><div class="surface-card-meta"><span class="surface-root-mini">${esc(h.root_domain||rootDomain)}</span><span class="env-pill env-${envClass(h.environment)}">${esc(h.environment||'UNKNOWN')}</span><span>${esc(h.family||'—')}</span>${h.webserver?`<span>${esc(h.webserver)}</span>`:''}</div><div class="surface-chips compact">${tags(h.technologies,'technology')}</div><div class="surface-card-rel"><span>${(h.providers||[]).map(esc).join(' · ')||'Proveedor no identificado'}</span><span>${(h.sources||[]).map(esc).join(' + ')}</span></div></article>`).join('') : '<div class="panel empty-state"><strong>No hay hosts con estos filtros.</strong><span>Quita algún filtro o ejecuta una fase adicional.</span></div>';
    grid.querySelectorAll('[data-host-card]').forEach(card=>card.addEventListener('click',()=>{selectedHost=card.dataset.hostCard;expandedHosts.add(selectedHost);const h=allHosts().find(x=>x.hostname===selectedHost);renderDetail(h);switchView('map');renderGraph();}));
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
  function switchView(name){viewBtns.forEach(b=>b.classList.toggle('active',b.dataset.surfaceView===name));viewPanels.forEach(p=>p.hidden=p.dataset.viewPanel!==name);if(name==='map'){renderGraph();setTimeout(fit,0);}else if(name==='inventory')renderInventory();else renderRuns();}
  function fit(){
    const {width,height}=canvasSize();
    const k=Math.max(.18,Math.min(1.25,(width-90)/Math.max(700,sceneExtent.width),(height-90)/Math.max(480,sceneExtent.height)));
    view={x:Math.max(24,(width-sceneExtent.width*k)/2),y:Math.max(24,(height-sceneExtent.height*k)/2),k};
    renderGraph();
  }
  function zoomAt(factor,sx=null,sy=null){
    const cs=canvasSize(); sx=sx??cs.width/2; sy=sy??cs.height/2;
    const old=view.k; const next=Math.max(.28,Math.min(2.6,old*factor));
    const wx=(sx-view.x)/old, wy=(sy-view.y)/old;
    view.x=sx-wx*next; view.y=sy-wy*next; view.k=next; renderGraph();
  }
  function resetDrill(){
    if(search)search.value=''; Object.values(selectedFilters).forEach(set=>set.clear()); redrawFacets();
    if(collapseFamilies)collapseFamilies.checked=true;
    selectedHost='';expandedHosts.clear();expandedFamilies.clear();expandedRoots.clear();expandedRoots.add(rootDomain);persistExpandedRoots();renderDetail(null);refresh();fit();
  }
  function resetLayout(){manualPositions.clear();fit();}
  function openPhaseCard(card){ const href=card?.dataset?.phaseHref; if(href) window.location.href=href; }


  function bind(){
    search?.addEventListener('input',refresh);
    document.addEventListener('click',()=>document.querySelectorAll('.surface-facet-menu').forEach(x=>x.hidden=true));
    layerEls.forEach(el=>el.addEventListener('change',()=>{renderGraph();fit();}));
    collapseFamilies?.addEventListener('change',()=>{renderGraph();fit();});
    root.querySelector('[data-filter-clear]')?.addEventListener('click',()=>{if(search)search.value='';Object.values(selectedFilters).forEach(set=>set.clear());redrawFacets();refresh();fit();});
    root.querySelector('[data-drill-reset]')?.addEventListener('click',resetDrill);
    root.querySelectorAll('[data-surface-fit]').forEach(btn=>btn.addEventListener('click',fit));
    root.querySelector('[data-surface-reset-layout]')?.addEventListener('click',resetLayout);
    root.querySelector('[data-surface-zoom-in]')?.addEventListener('click',()=>zoomAt(1.2));
    root.querySelector('[data-surface-zoom-out]')?.addEventListener('click',()=>zoomAt(.82));
    root.querySelector('[data-import-toggle]')?.addEventListener('click',()=>{importPanel.hidden=!importPanel.hidden;});
    viewBtns.forEach(b=>b.addEventListener('click',()=>switchView(b.dataset.surfaceView)));
    root.querySelector('[data-copy-visible]')?.addEventListener('click',async()=>{const text=visibleHosts().map(h=>h.hostname).join('\n');try{await navigator.clipboard.writeText(text);}catch(_){}});

    root.querySelectorAll('[data-phase-card]').forEach(card=>{
      card.addEventListener('click',e=>{if(e.target.closest('button,form,input,a,select'))return;openPhaseCard(card);});
      card.addEventListener('keydown',e=>{if((e.key==='Enter'||e.key===' ')&&!e.target.closest('button,form,input,a,select')){e.preventDefault();openPhaseCard(card);}});
    });

    svg.addEventListener('click',e=>{
      // A short node gesture is activated on pointerup. That activation re-renders
      // the SVG, so the browser's synthetic follow-up click can land on the new
      // background instead of the original node. Ignore it during the same
      // suppression window or it would immediately clear the selected host/detail.
      if(Date.now()<suppressClickUntil)return;
      if(e.target.closest('.surface-node'))return;
      selectedHost='';renderDetail(null);renderGraph();
    });
    svg.addEventListener('wheel',e=>{
      e.preventDefault();
      const rect=svg.getBoundingClientRect(); const cs=canvasSize();
      const sx=(e.clientX-rect.left)*(cs.width/Math.max(1,rect.width)); const sy=(e.clientY-rect.top)*(cs.height/Math.max(1,rect.height));
      zoomAt(e.deltaY<0?1.1:.9,sx,sy);
    },{passive:false});
    svg.addEventListener('pointerdown',e=>{if(e.target.closest('.surface-node'))return;pan={x:e.clientX,y:e.clientY,vx:view.x,vy:view.y,pointerId:e.pointerId};svg.setPointerCapture?.(e.pointerId);});
    svg.addEventListener('pointermove',e=>{
      if(nodeDrag){
        const dx=(e.clientX-nodeDrag.startX)/view.k, dy=(e.clientY-nodeDrag.startY)/view.k;
        nodeDrag.x=nodeDrag.baseX+dx; nodeDrag.y=nodeDrag.baseY+dy;
        if(Math.abs(dx)+Math.abs(dy)>3)nodeDrag.moved=true;
        nodeDrag.g?.setAttribute('transform',`translate(${nodeDrag.x} ${nodeDrag.y})`);
        return;
      }
      if(!pan)return; view.x=pan.vx+(e.clientX-pan.x);view.y=pan.vy+(e.clientY-pan.y);renderGraph();
    });
    const endPointer=ev=>{
      if(nodeDrag){
        const drag=nodeDrag;
        drag.g?.classList.remove('dragging');
        nodeDrag=null;
        if(drag.moved){
          manualPositions.set(drag.id,{x:drag.x,y:drag.y});
          suppressClickUntil=Date.now()+260;
          renderGraph();
        }else if(ev?.type==='pointerup'){
          // Activate before any re-render destroys the SVG node. Suppress the
          // browser's follow-up click so the node is not toggled twice.
          suppressClickUntil=Date.now()+320;
          drag.activate?.();
        }
      }
      pan=null;
    };
    svg.addEventListener('pointerup',endPointer); svg.addEventListener('pointercancel',endPointer);

    fullscreenBtn?.addEventListener('click',async()=>{
      try{if(document.fullscreenElement===workspace)await document.exitFullscreen();else await workspace?.requestFullscreen();}catch(err){console.warn('Fullscreen no disponible',err);}
    });
    document.addEventListener('fullscreenchange',()=>{
      if(fullscreenBtn)fullscreenBtn.textContent=document.fullscreenElement===workspace?'⤢ Salir de pantalla completa':'⛶ Pantalla completa';
      setTimeout(()=>{renderGraph();fit();},120);
    });
    window.addEventListener('resize',()=>{if(!root.querySelector('[data-view-panel="map"]')?.hidden){renderGraph();}});
  }

  fetch(api).then(r=>r.json()).then(payload=>{
    data=payload||data;
    renderFacet('root',data.filters?.roots||data.roots||[]); renderFacet('technology',data.filters?.technologies||[]); renderFacet('server',data.filters?.servers||[]); renderFacet('provider',data.filters?.providers||[]);
    renderFacet('environment',data.filters?.environments||[]); renderFacet('status',data.filters?.statuses||[]); renderFacet('family',data.filters?.families||[]); renderFacet('source',data.filters?.sources||[]);
    bind(); refresh(); fit();
  }).catch(err=>{stage.innerHTML=`<div class="callout warning">No pude cargar la superficie: ${esc(err.message||err)}</div>`;});
})();


// Project baseline polling is intentionally separate from the graph renderer.
// The graph remains usable while other roots continue in the local job queue.
(()=>{
  const panel=document.querySelector('[data-baseline-panel]');
  if(!panel)return;
  const api=panel.dataset.baselineApi;
  let sawActive=panel.dataset.baselineActive==='1';
  const labels={queued:'EN COLA',running:'EJECUTANDO',done:'LISTO',failed:'FALLÓ',not_run:'SIN EJECUTAR'};
  const setText=(sel,value)=>{const el=panel.querySelector(sel);if(el)el.textContent=String(value??0);};
  const update=payload=>{
    const baseline=payload?.baseline||{};
    const summary=payload?.project_summary||{};
    const counts=baseline.counts||{};
    setText('[data-baseline-running]',counts.running||0);
    setText('[data-baseline-queued]',counts.queued||0);
    setText('[data-baseline-done]',counts.done||0);
    setText('[data-baseline-failed]',counts.failed||0);
    Object.entries(summary).forEach(([key,value])=>{
      const el=panel.querySelector(`[data-project-metric="${CSS.escape(key)}"]`);
      if(el)el.textContent=String(value??0);
    });
    (payload?.root_overview||[]).forEach(item=>{
      const card=panel.querySelector(`[data-baseline-root="${CSS.escape(item.root_domain||'')}"]`);
      if(!card)return;
      const status=item.baseline_status||'not_run';
      card.classList.remove('queued','running','done','failed','not_run');
      card.classList.add(status);
      const statusEl=card.querySelector('[data-root-status]');
      if(statusEl)statusEl.textContent=labels[status]||String(status).toUpperCase();
      const progress=card.querySelector('[data-root-progress]');
      if(progress)progress.style.width=`${Math.max(0,Math.min(100,Number(item.baseline_percent)||0))}%`;
      const phase=card.querySelector('[data-root-phase]');
      if(phase)phase.textContent=item.baseline_phase||'Sin baseline todavía';
    });
    const active=!!baseline.active;
    const live=panel.querySelector('[data-baseline-live]');
    if(live)live.textContent=active?'Actualizando en vivo…':'';
    if(active){
      sawActive=true;
      window.setTimeout(poll,2200);
    }else if(sawActive){
      // Refresh once so the graph, triage list and per-root statistics consume
      // the final persisted evidence instead of maintaining a second renderer.
      window.setTimeout(()=>window.location.reload(),700);
    }
  };
  const poll=()=>fetch(api,{headers:{'Accept':'application/json'}})
    .then(r=>{if(!r.ok)throw new Error(`HTTP ${r.status}`);return r.json();})
    .then(update)
    .catch(()=>window.setTimeout(poll,4000));
  if(sawActive)window.setTimeout(poll,900);
})();
