(function(){
  const root=document.getElementById('inbox-list');
  const make=(tag,cls,text)=>{const el=document.createElement(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=text;return el};
  const age=s=>s<60?`${Math.floor(s)}s`:s<3600?`${Math.floor(s/60)}m`:s<86400?`${Math.floor(s/3600)}h`:`${Math.floor(s/86400)}d`;
  function card(w,now){
    const waiting=w.queued_human+w.queued_agent;
    const el=make('section','connector-card inbox-card'+(w.queued_human?' human':'')+(w.held?' held':''));
    el.append(make('div','connector-icon',w.queued_human?'✉':'📭'));
    const copy=make('div','connector-copy');
    copy.append(make('div','connector-name',w.wolt));
    const counts=[`${w.queued_human} from you`,`${w.queued_agent} from agents`,`${w.claimed} being read`];
    if(w.held)counts.push(`${w.held} held`);
    copy.append(make('div','connector-line',counts.join(' · ')));
    const state=w.state!=='open'?w.state:waiting?`waiting · oldest ${age(Math.max(0,now-w.oldest_queued_at))}`:w.held?'held: its reader is gone':'nothing waiting';
    copy.append(make('div','connector-state'+(w.held?' warn':''),state));
    el.append(copy);
    return el;
  }
  async function load(){
    try{
      const r=await fetch('/inbox/summary');const data=await r.json();
      if(r.status===404&&data.error==='inbox_disabled'){root.replaceChildren(make('p','','The inbox is off in this lodge.'));return}
      if(!r.ok)throw new Error(data.error||r.status);
      root.replaceChildren(...(data.wolts.length?data.wolts.map(w=>card(w,data.now)):[make('p','','No mail yet.')]));
    }catch(e){root.replaceChildren(make('p','',`Could not load the inbox: ${e.message}`))}
  }
  load();setInterval(load,15000);
})();
