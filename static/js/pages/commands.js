/* VAULT - pages/commands.js
   Session Log (/radius/commands): who logged in to which network device and what they did there, read from
   the devices' syslog (vault-syslog receiver) and the RADIUS logins. Three views of the same sessions, laid out
   like the Change Reports page:
     Sessions   one card per login (the default): user on device, from -> to, changes and commands; opening
                it shows that session's log. A new login after a logout is a new card ("Session 2 of 2").
     By device  one card per device; opening it lists every session on it, newest first: which user, from
                where, login -> every command in order -> logout. #device=<address> opens a card.
     By user    one card per user; opening it lists that user's sessions on every device. #user=<name>
   Inside a card "Changes only" hides the view-only commands. Searches run on the server; Export CSV
   downloads every matching action (up to 50,000). Refreshes itself every 30 seconds while the page is open. */
let cmdData=null,cmdSess=null,cmdTab="session",cmdDetail={},cmdJump=null,cmdOnlyChg=new Set();
const CMD_PERIOD={24:"in the last 24 hours",168:"in the last 7 days",720:"in the last 30 days"};
const CMD_STATUS={active:["Active","UP"],closed:["Logged out","k-logout"],"no-logout":["No logout","k-command"],failed:["Failed login","k-fail"]};
const CMD_VIEW={
  session:{title:"Session log",help:"One card per login, newest first: who, on which device, from when to when and what they did. A new login after a logout is a new card. Open a card to see every command.",noun:"session"},
  device:{title:"Sessions by device",help:"One card per device. Open it to see who logged in, every command they ran and when they logged out, session by session.",noun:"device",
          key:s=>s.device_ip,param:"device"},
  user:{title:"Sessions by user",help:"One card per user. Open it to see everything that user did on every device, session by session.",noun:"user",
        key:s=>s.username,param:"user"}};
const CMD_IC={
  user:'<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/></svg>',
  device:'<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="13" width="20" height="8" rx="2"/><path d="M6 17h.01M10 17h.01M12 13V8m-4 0h8M9 4h6"/></svg>'};
const cmdHours=()=>$("#cmdHours").value||"24";
const cmdSearch=()=>$("#cmdSQ").value.trim();
const cmdFromHash=()=>{const m=/^#(user|device)=(.+)$/.exec(location.hash);try{return m?{kind:m[1],key:decodeURIComponent(m[2])}:null}catch(e){return null}};
const cmdDur=s=>{if(s==null)return "-";if(s<60)return `${s} s`;if(s<3600)return `${Math.round(s/60)} min`;const h=Math.floor(s/3600),m=Math.round(s%3600/60);return m?`${h} h ${m} min`:`${h} h`};
const cmdDevice=(name,ip)=>`<span class="dn">${esc(name||ip)}</span>${name?`<span class="sub m">${esc(ip)}</span>`:""}`;
const cmdPlural=(n,w)=>`${fmtNum(n)} ${w}${n===1?"":"s"}`;
const cmdPill=st=>{const [label,cls]=CMD_STATUS[st]||[st,""];return `<span class="pill ${cls}">${esc(label)}</span>`};
const cmdDate=s=>esc(fmtBdDateTime(s).split(", ")[0]);
const cmdId=(kind,key)=>kind+":"+key;
const cmdOpenCards=()=>[...document.querySelectorAll("#cmdSessList details[open]")].map(d=>({kind:d.dataset.kind,key:d.dataset.key}));
/* the sessions of one device or one user, with their commands (same period and search as the list) */
const cmdFetch=(kind,key)=>{
  const sq=cmdSearch();
  /* a session's key is "user|device address|start": fetch that user's sessions on that device */
  const by=kind==="session"?(([u,ip])=>({user:u,device:ip}))(key.split("|")):{[CMD_VIEW[kind].param]:key};
  return api("/api/radius/commands/sessions?"+new URLSearchParams({hours:cmdHours(),...by,...(sq?{q:sq}:{})}))
    .then(d=>{cmdDetail[cmdId(kind,key)]=d}).catch(e=>{cmdDetail[cmdId(kind,key)]={error:e}});
};

async function loadCommands(){
  const jump=cmdFromHash();
  if(jump){cmdTab=jump.kind;cmdJump=jump}
  const sq=cmdSearch(),hours=cmdHours();
  const want=[...cmdOpenCards().filter(c=>c.kind===cmdTab),...(jump?[jump]:[])];
  try{
    const [act,sess]=await Promise.all([
      api("/api/radius/commands?"+new URLSearchParams({hours})),
      api("/api/radius/commands/sessions?"+new URLSearchParams({hours,...(sq?{q:sq}:{})})),
      ...want.map(c=>cmdFetch(c.kind,c.key))]);
    cmdData=act;cmdSess=sess;
    const keep=new Set(want.map(c=>cmdId(c.kind,c.key)));
    for(const k of Object.keys(cmdDetail))if(!keep.has(k))delete cmdDetail[k];
    renderCmdStatus();renderCmdKpis();renderCmdSources();renderCmdView();renderCmdSessions();
  }catch(e){
    $("#cmdSessList").innerHTML=errorState("Could not load the session log",e);
    ["#cmdKpis","#cmdSources","#cmdStatus"].forEach(s=>{const el=$(s);if(el)el.innerHTML=""});
    $("#cmdSCount").textContent="";
  }
}
function renderCmdView(){
  const v=CMD_VIEW[cmdTab];
  $("#cmdSessTitle").textContent=v.title;$("#cmdSessHelp").textContent=v.help;
  $("#cmdTabs").querySelectorAll("[data-cmd-tab]").forEach(b=>{const on=b.dataset.cmdTab===cmdTab;b.classList.toggle("on",on);b.setAttribute("aria-selected",on)});
}

function renderCmdStatus(){
  const r=cmdData.receiver||{},box=$("#cmdStatus");
  const notes=[];
  if(!r.seen)notes.push(`<div class="rad-note"><b>The syslog receiver is not installed yet.</b> It listens for the devices' logs on UDP 514. Run this once on the server:<code>sudo bash /opt/vault/deploy/enable_syslog.sh</code>Then turn on command logging on each device (Device Setup, step "Command logging").</div>`);
  else if(!r.running)notes.push(`<div class="rad-note"><b>The syslog receiver is not running</b>${r.heartbeat?` (last seen ${esc(fmtWhen(r.heartbeat).replace(/<[^>]+>/g," ").replace(/\s+/g," ").trim())})`:""}. Logs that arrive now are lost. Check it on the server:<code>sudo systemctl status vault-syslog --no-pager</code><code>sudo journalctl -u vault-syslog -n 30 --no-pager</code></div>`);
  else if(!(cmdData.sources||[]).length)notes.push(`<div class="rad-note"><b>Waiting for the first device.</b> The receiver is listening on UDP ${esc(r.port||514)}, but no device has sent a log yet. Turn on command logging on a device: <a href="${esc(PAGE_URL["radius-setup"]||"/radius/setup")}">Device Setup</a>, step "Command logging". Only devices on NAS Clients are accepted.</div>`);
  if(r.rejected)notes.push(`<div class="rad-note"><b>${fmtNum(r.rejected)} log message${r.rejected===1?" was":"s were"} ignored</b> because the sender is not on NAS Clients${r.rejected_last_ip?` (last one from <span class="m">${esc(r.rejected_last_ip)}</span>)`:""}. If that is one of your devices, add the address it sends from (often its loopback or management interface).</div>`);
  if(r.dropped)notes.push(`<div class="rad-note"><b>${fmtNum(r.dropped)} message${r.dropped===1?" was":"s were"} dropped</b> because a device sent more than 200 per second. Lower the log level that device sends to VAULT.</div>`);
  box.innerHTML=notes.join("");
}
function renderCmdKpis(){
  const t=cmdSess.totals||{},per=CMD_PERIOD[cmdSess.hours]||"";
  const by={};(cmdSess.sessions||[]).forEach(s=>{if(s.changes)by[s.username]=(by[s.username]||0)+s.changes});
  const top=Object.entries(by).sort((a,b)=>b[1]-a[1])[0];
  radKpis("#cmdKpis",[
    ["Sessions",t.sessions||0,t.active?`${fmtNum(t.active)} active now`:`Device logins ${per}`,"g"],
    ["Changes",t.changes||0,top?`Most by ${top[0]} (${fmtNum(top[1])})`:"No configuration changed",t.changes?"warn":""],
    ["Commands",t.commands||0,"Show / display and other view-only commands"],
    ["Users",t.users||0,`On ${fmtNum(t.devices||0)} device${t.devices===1?"":"s"}`]]);
}

/* ---- the list: one card per device (or per user) ---- */
function cmdKeep(s){
  const f=$("#cmdSFilter").value;
  return f==="changes"?s.changes>0:f==="active"?s.status==="active":true;
}
function cmdGroups(){
  const by=new Map(),key=CMD_VIEW[cmdTab].key;
  for(const s of (cmdSess.sessions||[]).filter(cmdKeep)){        /* newest first, so the first one is the latest */
    const k=key(s);let g=by.get(k);
    if(!g)by.set(k,g={key:k,name:cmdTab==="device"?(s.device||s.device_ip):s.username,ip:s.device_ip,named:!!s.device,
      sessions:0,failed:0,changes:0,commands:0,active:0,users:new Set(),devices:new Set(),last:s.end||s.last,lastStart:s.start});
    if(s.failed)g.failed++;else g.sessions++;
    g.changes+=s.changes;g.commands+=s.commands;
    if(s.status==="active")g.active++;
    g.users.add(s.username);g.devices.add(s.device||s.device_ip);
  }
  return [...by.values()];
}
function renderCmdSessions(){
  if(cmdTab==="session")return renderCmdSessionCards();
  const list=cmdGroups(),all=cmdSess.sessions||[],filtered=cmdSearch()||$("#cmdSFilter").value,noun=CMD_VIEW[cmdTab].noun;
  const n=list.reduce((a,g)=>a+g.sessions+g.failed,0);
  $("#cmdSCount").textContent=list.length?`${cmdPlural(list.length,noun)} · ${cmdPlural(n,"session")}`:"";
  if(!list.length){$("#cmdSessList").innerHTML=`<div class="empty"><b>${filtered&&all.length?"No matching sessions":"No sessions "+esc(CMD_PERIOD[cmdSess.hours]||"")}</b>${filtered?"Try another user, device, address or command, or a longer period.":"A session appears when a user logs in to a device that sends its logs to VAULT."}</div>`;return}
  const jump=cmdJump&&cmdJump.kind===cmdTab?cmdJump.key:"";
  if(jump){const i=list.findIndex(g=>g.key===jump);if(i>=0)PAGES.cmdSess=Math.floor(i/SIZES.cmdSess)+1}
  const open=new Set([...cmdOpenCards().filter(c=>c.kind===cmdTab).map(c=>c.key),...(jump?[jump]:[])]);
  const {rows,bar}=paginate("cmdSess",list);
  morph($("#cmdSessList"),rows.map(g=>cmdCard(g,open.has(g.key))).join("")+bar);
  cmdJump=null;
  if(jump){
    const el=[...document.querySelectorAll("#cmdSessList details")].find(d=>d.dataset.key===jump);
    if(el){el.open=true;setTimeout(()=>el.scrollIntoView({behavior:"smooth",block:"start"}),60)}
  }
}
function cmdCard(g,isOpen){
  const work=g.changes+g.commands,chgPct=work?Math.round(g.changes/work*100):0;
  const badges=(g.sessions?`<span class="rep-badge ${g.changes?"chg":"same"}">${cmdPlural(g.sessions,"session")}</span>`:"")+
    (g.failed?`<span class="rep-badge fail">${cmdPlural(g.failed,"failed login")}</span>`:"")+
    (g.active?'<span class="rep-badge is-live">Active now</span>':"");
  const users=[...g.users],devs=[...g.devices];
  const names=a=>esc(a.slice(0,2).join(", "))+(a.length>2?` +${a.length-2} more`:"");
  const sub=cmdTab==="device"?`${g.named?`<span class="m">${esc(g.ip)}</span> · `:""}<span class="cmd-who-ic">${CMD_IC.user}</span>${names(users)}`:
    `<span class="cmd-who-ic">${CMD_IC.device}</span>${names(devs)}`;
  const title=cmdTab==="device"?users.join(", "):devs.join(", ");
  const last=g.lastStart?["Last login",g.lastStart]:["Last activity",g.last];
  return `<details class="rep-card cmd-card${g.changes?" has-chg":""}${g.active?" is-live":""}" data-kind="${cmdTab}" data-key="${esc(g.key)}"${isOpen?" open":""}>
    <summary>
      <span class="rep-dev"><b>${esc(g.name)}</b><small title="${esc(title)}">${sub}</small></span>
      <span class="cmd-badges">${badges}</span>
      <span class="rep-bar" title="${cmdPlural(g.changes,"change")} / ${cmdPlural(g.commands,"view command")}"><i class="chg" style="width:${chgPct}%"></i><i class="cmdv" style="width:${work?100-chgPct:0}%"></i></span>
      <span class="rep-lines"><span class="cmd-c">${cmdPlural(g.changes,"change")}</span><span class="cmd-v">${fmtNum(g.commands)} view</span></span>
      <span class="rep-last">${last[0]}<br> <b>${cmdDate(last[1])}</b> <span class="t">${esc(bdClock(last[1]))}</span></span>
      <svg class="rep-chev" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
    </summary>
    <div class="rep-body">${isOpen?cmdBody(cmdTab,g.key):""}</div></details>`;
}

/* ---- Sessions view: one card per login (user on a device, login -> logout) ---- */
function renderCmdSessionCards(){
  const all=cmdNumber(cmdSess.sessions||[]),list=all.filter(cmdKeep),filtered=cmdSearch()||$("#cmdSFilter").value;
  $("#cmdSCount").textContent=list.length?cmdPlural(list.length,"session"):"";
  if(!list.length){$("#cmdSessList").innerHTML=`<div class="empty"><b>${filtered&&all.length?"No matching sessions":"No sessions "+esc(CMD_PERIOD[cmdSess.hours]||"")}</b>${filtered?"Try another user, device, address or command, or a longer period.":"A session appears when a user logs in to a device that sends its logs to VAULT."}</div>`;return}
  const open=new Set(cmdOpenCards().filter(c=>c.kind==="session").map(c=>c.key));
  const {rows,bar}=paginate("cmdSess",list);
  morph($("#cmdSessList"),rows.map(s=>cmdSessCard(s,open.has(s.key))).join("")+bar);
}
function cmdSessCard(s,isOpen){
  const work=s.changes+s.commands,chgPct=work?Math.round(s.changes/work*100):0;
  const at=s.start||s.end||s.last,until=s.failed?"":s.status==="active"?"now":s.end?bdClock(s.end):"no logout";
  return `<details class="rep-card cmd-card cmd-scard st-${esc(s.status)}${s.changes?" has-chg":""}${s.status==="active"?" is-live":""}" data-kind="session" data-key="${esc(s.key)}"${isOpen?" open":""}>
    <summary>
      <span class="cmd-sid"><span class="cmd-av-s">${esc(s.username.slice(0,1).toUpperCase())}</span>
        <span class="rep-dev"><b>${esc(s.username)} <span class="cmd-on">on</span> ${esc(s.device||s.device_ip)}</b>
        <small>${s.device?`<span class="m">${esc(s.device_ip)}</span>`:""}${s.source_ip?`${s.device?" · ":""}from <span class="m">${esc(s.source_ip)}</span>`:""}</small></span></span>
      <span class="cmd-badges">${cmdPill(s.status)}${s.of>1&&!s.failed?`<span class="cmd-no">Session ${s.no} of ${s.of}</span>`:""}</span>
      <span class="rep-bar" title="${cmdPlural(s.changes,"change")} / ${cmdPlural(s.commands,"view command")}"><i class="chg" style="width:${chgPct}%"></i><i class="cmdv" style="width:${work?100-chgPct:0}%"></i></span>
      <span class="rep-lines">${s.failed?'<span class="bad-t">Login refused</span>':`<span class="cmd-c">${cmdPlural(s.changes,"change")}</span><span class="cmd-v">${fmtNum(s.commands)} view</span>`}</span>
      <span class="rep-last cmd-when"><b>${s.start?esc(bdClock(s.start)):"Before period"}${until?` → ${esc(until)}`:""}</b><br><span>${cmdDate(at)}${s.failed?"":" · "+cmdDur(s.duration)}</span></span>
      <svg class="rep-chev" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
    </summary>
    <div class="rep-body">${isOpen?cmdBody("session",s.key):""}</div></details>`;
}
/* inside a session card: the log of that one session */
function cmdSessBody(key){
  const d=cmdDetail[cmdId("session",key)];
  const s=(d.sessions||[]).find(x=>x.key===key);
  if(!s)return `<p class="rep-note" style="padding:12px 0">This session is no longer in the chosen period. Refresh the page.</p>`;
  const only=cmdOnlyChg.has(cmdId("session",key));
  return `<div class="rep-head"><span>What ${esc(s.username)} did on ${esc(s.device||s.device_ip)}</span>
      <span class="cmd-head-r"><span class="cmd-sum"><b class="cmd-c">${cmdPlural(s.changes,"change")}</b> · ${cmdPlural(s.commands,"view command")}</span>
      ${s.changes&&s.commands?`<button type="button" class="b cmd-only${only?" on":""}" data-only aria-pressed="${only}">Changes only</button>`:""}</span></div>
    <div class="cmd-tl cmd-one${only?" only-chg":""}"><pre class="rep-prev cmd-log">${cmdLog(s)}</pre>
      <p class="cmd-links"><button type="button" class="cmd-user" data-go="user" data-key="${esc(s.username)}">All sessions of ${esc(s.username)} →</button>
        <button type="button" class="cmd-user" data-go="device" data-key="${esc(s.device_ip)}">Everyone on ${esc(s.device||s.device_ip)} →</button></p></div>`;
}

/* ---- inside a card: each session as login -> commands -> logout ---- */
function cmdBody(kind,key){
  const d=cmdDetail[cmdId(kind,key)];
  if(!d)return `<div class="loading-block" role="status"><span class="spin"></span>Loading sessions…</div>`;
  if(d.error)return errorState("Could not load these sessions",d.error);
  if(kind==="session")return cmdSessBody(key);
  const list=(d.sessions||[]).filter(cmdKeep);
  if(!list.length)return `<p class="rep-note" style="padding:12px 0">No sessions ${esc(CMD_PERIOD[d.hours]||"")}.</p>`;
  const chg=list.reduce((n,s)=>n+s.changes,0),only=cmdOnlyChg.has(cmdId(kind,key));
  /* who did what here (by device) / where they did it (by user): one chip per person or device */
  const other=kind==="device"?"user":"device",by=new Map();
  for(const s of list){
    const k=kind==="device"?s.username:s.device_ip;let w=by.get(k);
    if(!w)by.set(k,w={key:k,name:kind==="device"?s.username:(s.device||s.device_ip),sessions:0,changes:0,failed:0});
    s.failed?w.failed++:w.sessions++;w.changes+=s.changes;
  }
  const who=[...by.values()].sort((a,b)=>b.changes-a.changes||b.sessions-a.sessions).map(w=>
    `<button type="button" class="cmd-chip${w.changes?" has-chg":""}" data-go="${other}" data-key="${esc(w.key)}" title="Open ${esc(w.name)}">
      <span class="cmd-av-s${other==="device"?" dev":""}">${other==="device"?CMD_IC.device:esc(w.name.slice(0,1).toUpperCase())}</span>
      <span><b>${esc(w.name)}</b><small>${w.changes?`<span class="cmd-c">${cmdPlural(w.changes,"change")}</span> · `:"No changes · "}${w.sessions?cmdPlural(w.sessions,"session"):""}${w.failed?`${w.sessions?" · ":""}<span class="bad-t">${cmdPlural(w.failed,"failed login")}</span>`:""}</small></span></button>`).join("");
  return `<div class="cmd-who"><span class="cmd-who-t">${kind==="device"?"Who logged in":"Devices used"}</span>${who}</div>
    <div class="rep-head"><span>Sessions, newest first</span>
      <span class="cmd-head-r"><span class="cmd-sum">${cmdPlural(list.length,"session")} · <b class="cmd-c">${cmdPlural(chg,"change")}</b></span>
      <button type="button" class="b cmd-only${only?" on":""}" data-only aria-pressed="${only}">Changes only</button></span></div>
    <ol class="rep-tl cmd-tl${only?" only-chg":""}">${cmdNumber(list).map(s=>cmdSessionItem(s,kind)).join("")}</ol>`;
}
/* each visit of one user to one device is its own session: number them in time order (1 = earliest) */
function cmdNumber(list){
  const seen={},total={};
  for(const s of list)total[s.username+"|"+s.device_ip]=(total[s.username+"|"+s.device_ip]||0)+1;
  for(const s of [...list].reverse()){const k=s.username+"|"+s.device_ip;seen[k]=(seen[k]||0)+1;s.no=seen[k];s.of=total[k]}
  return list;
}
/* one session's log: logged in -> every command in order -> logged out */
/* a configuration change that takes something away: undo (Huawei), no (Cisco), delete / deactivate (Juniper),
   unset (FortiGate), remove (MikroTik). Shown as "- remove" in red; every other change as "+ add" in green. */
const CMD_REMOVE=/^(undo|no|delete|deactivate|unset|purge)\b|(^\/|\s)remove\b/i;
const cmdMark=e=>e.kind!=="change"?["cmd","view"]:CMD_REMOVE.test((e.command||"").trim())?["chg del","− remove"]:["chg add","+ add"];
function cmdLog(s){
  const line=(t,cls,text)=>`<span class="l ${cls}"><time>${t?esc(bdClock(t,true)):""}</time><span>${text}</span></span>`;
  let log;
  if(s.failed)log=line(s.start,"fail",`✕ Login refused${s.source_ip?" from "+esc(s.source_ip):""}`);
  else{
    const steps=s.events.filter(e=>e.kind==="change"||e.kind==="command").map(e=>{
      const bad=e.result&&!/^succ/i.test(e.result);
      const [cls,tag]=cmdMark(e);
      return line(e.ts,cls,`<i>${tag}</i>${esc(e.command)}${bad?` <em>(${esc(e.result)})</em>`:""}`)}).join("");
    log=(s.start?line(s.start,"in",`▶ Logged in${s.source_ip?" from "+esc(s.source_ip):""}`):line(null,"in","▶ Logged in before this period"))+
      (steps||`<span class="l none"><time></time><span>No commands in this session</span></span>`)+
      (s.status==="closed"?line(s.end,"out",`◀ Logged out · ${cmdDur(s.duration)} on the device`):
       s.status==="active"?line(null,"now","● Still logged in"):line(s.last,"out","◀ No logout recorded (last activity)"));
  }
  return log;
}
function cmdSessionItem(s,kind){
  const at=s.start||s.events[0]?.ts||s.end||s.last;
  const until=s.failed?"":s.status==="active"?"now":s.end?bdClock(s.end):"no logout";
  const log=cmdLog(s);
  /* by device: the session is about a user; by user: about a device. Each name opens the other view. */
  const who=kind==="device"?`<span class="cmd-av-s">${esc(s.username.slice(0,1).toUpperCase())}</span><button type="button" class="cmd-user" data-go="user" data-key="${esc(s.username)}" title="Everything ${esc(s.username)} did">${esc(s.username)}</button>`:
    `<span class="cmd-av-s dev">${CMD_IC.device}</span><button type="button" class="cmd-user" data-go="device" data-key="${esc(s.device_ip)}" title="Everyone on this device">${esc(s.device||s.device_ip)}</button>${s.device?` <span class="m">${esc(s.device_ip)}</span>`:""}`;
  return `<li class="st-${esc(s.status)}${s.changes?" has-chg":""}">
    <div class="rep-when"><b>${cmdDate(at)}</b><span class="cmd-range">${s.start?esc(bdClock(s.start)):"Before this period"}${until?` <i aria-hidden="true">→</i> ${esc(until)}`:""}</span>
      ${s.of>1&&!s.failed?`<span class="cmd-no">Session ${s.no} of ${s.of}</span>`:""}</div>
    <div class="rep-what">
      <p class="cmd-sline">${who}
        ${s.source_ip&&kind==="device"?`<span>from <span class="m">${esc(s.source_ip)}</span></span>`:""}
        ${s.failed?"":`<span>${cmdDur(s.duration)}</span>`}
        ${s.changes?`<span class="cmd-c">${cmdPlural(s.changes,"change")}</span>`:""}${s.commands?`<span>${cmdPlural(s.commands,"view command")}</span>`:""}</p>
      <pre class="rep-prev cmd-log">${log}</pre></div>
    <div class="rep-act">${cmdPill(s.status)}</div></li>`;
}
/* opening a card loads its sessions */
$o("#cmdSessList").addEventListener("toggle",e=>{
  const d=e.target;if(!d.matches||!d.matches("details[data-kind]")||!d.open)return;
  const {kind,key}=d.dataset,body=d.querySelector(".rep-body");
  body.innerHTML=cmdBody(kind,key);
  if(!cmdDetail[cmdId(kind,key)])cmdFetch(kind,key).then(()=>{if(d.open)body.innerHTML=cmdBody(kind,key)});
},true);
$o("#cmdSessList").addEventListener("click",e=>{
  const only=e.target.closest("[data-only]");
  if(only){
    const d=only.closest("details"),id=cmdId(d.dataset.kind,d.dataset.key),on=!cmdOnlyChg.has(id);
    on?cmdOnlyChg.add(id):cmdOnlyChg.delete(id);
    only.classList.toggle("on",on);only.setAttribute("aria-pressed",on);d.querySelector(".cmd-tl")?.classList.toggle("only-chg",on);
    return;
  }
  const go=e.target.closest("[data-go]");
  if(go){e.preventDefault();cmdOpen(go.dataset.go,go.dataset.key)}
});
function cmdOpen(kind,key){
  history.pushState(null,"",`#${kind}=${encodeURIComponent(key)}`);
  PAGES.cmdSess=1;loadCommands();
}
addEventListener("popstate",()=>{if(PAGE==="radius-commands")loadCommands()});

/* ---- devices that send logs ---- */
function renderCmdSources(){
  const list=cmdData.sources||[],box=$("#cmdSources");
  if(!list.length){box.innerHTML=`<div class="empty"><b>No device has sent logs yet</b>Devices appear here with their first message.</div>`;return}
  const {rows,bar}=paginate("cmdSources",list);
  box.innerHTML=`<div class="tbl"><table><thead><tr><th>Device</th><th>Last message</th><th>Messages</th><th>User actions</th><th>Status</th></tr></thead><tbody>`+
    rows.map(s=>`<tr><td>${cmdDevice(s.device,s.ip)}</td>
      <td class="when">${fmtWhen(s.last_seen)}</td><td>${fmtNum(s.received)}</td><td>${fmtNum(s.recognized)}</td>
      <td>${s.recognized?'<span class="pill UP">Working</span>':`<span class="pill k-change">No user actions yet</span>`}
        ${!s.recognized&&s.sample?`<details class="cmd-sample"><summary>Last message received</summary><code>${esc(s.sample)}</code></details>`:""}</td></tr>`).join("")+`</tbody></table></div>`+bar;
}

PAGES.cmdSources=PAGES.cmdSess=1;
for(const k of ["cmdSources","cmdSess"]){const v=+localStorage.getItem("dbms_page_size_"+k);SIZES[k]=PAGE_SIZES.includes(v)?v:10}
REDRAW.cmdSources=renderCmdSources;REDRAW.cmdSess=renderCmdSessions;
let cmdT=0;
$o("#cmdSQ").addEventListener("input",()=>{clearTimeout(cmdT);cmdT=setTimeout(()=>{PAGES.cmdSess=1;loadCommands()},350)});
$o("#cmdSFilter").addEventListener("change",()=>{PAGES.cmdSess=1;renderCmdSessions()});
$o("#cmdHours").addEventListener("change",()=>{PAGES.cmdSess=1;loadCommands()});
$o("#cmdRefresh").addEventListener("click",()=>loadCommands());
$o("#cmdTabs").addEventListener("click",e=>{
  const b=e.target.closest("[data-cmd-tab]");if(!b||b.dataset.cmdTab===cmdTab)return;
  cmdTab=b.dataset.cmdTab;PAGES.cmdSess=1;
  if(location.hash)history.pushState(null,"",location.pathname+location.search);
  renderCmdView();renderCmdSessions();
});
$o("#cmdCsv").addEventListener("click",()=>{
  const p=new URLSearchParams({hours:cmdHours(),format:"csv"}),q=cmdSearch();if(q)p.set("q",q);
  location.href="/api/radius/commands?"+p;
});
if(PAGE==="radius-commands")setInterval(()=>{if(!document.hidden&&cmdData)loadCommands()},30000);
