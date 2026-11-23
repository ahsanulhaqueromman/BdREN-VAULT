/* VAULT - pages/commands.js
   Command History (/radius/commands): what users did on the network devices, read from the devices' syslog by
   the vault-syslog receiver.
     Sessions      one card per user (laid out like the Reports page); opening it shows that user's sessions,
                   newest first, each as login -> every command in order -> logout. #user=<name> opens a card.
     All activity  every recorded action, newest first, with a type filter
   Searches run on the server; Export CSV downloads every matching action (up to 50,000).
   Refreshes itself every 30 seconds while the page is open. */
let cmdData=null,cmdSess=null,cmdTab="sessions",cmdUsers={},cmdJump="";
const CMD_PERIOD={24:"in the last 24 hours",168:"in the last 7 days",720:"in the last 30 days"};
const CMD_KIND={change:["Change","k-change"],command:["Command","k-command"],login:["Login","k-login"],logout:["Logout","k-logout"],"login-failed":["Failed login","k-fail"]};
const CMD_STATUS={active:["Active","UP"],closed:["Logged out","k-logout"],"no-logout":["No logout","k-command"],failed:["Failed login","k-fail"]};
const cmdHours=()=>$("#cmdHours").value||"24";
const cmdUserFromHash=()=>{const m=/^#user=(.+)$/.exec(location.hash);try{return m?decodeURIComponent(m[1]):""}catch(e){return ""}};
const cmdDur=s=>s==null?"-":s<60?`${s} s`:s<3600?`${Math.round(s/60)} min`:`${Math.floor(s/3600)} h ${Math.round(s%3600/60)} min`;
const cmdDevice=(name,ip)=>`<span class="dn">${esc(name||ip)}</span>${name?`<span class="sub m">${esc(ip)}</span>`:""}`;
const cmdPlural=(n,w)=>`${fmtNum(n)} ${w}${n===1?"":"s"}`;
const cmdPill=st=>{const [label,cls]=CMD_STATUS[st]||[st,""];return `<span class="pill ${cls}">${esc(label)}</span>`};
const cmdDate=s=>esc(fmtBdDateTime(s).split(", ")[0]);
const cmdActQuery=()=>{
  const p=new URLSearchParams({hours:cmdHours()});
  const q=$("#cmdQ").value.trim(),k=$("#cmdKind").value;
  if(q)p.set("q",q);if(k)p.set("kind",k);
  return p;
};
const cmdOpenCards=()=>[...document.querySelectorAll("#cmdSessList details[open]")].map(d=>d.dataset.user);
/* one user's sessions with their commands (the same period and search as the list) */
const cmdFetchUser=u=>{
  const sq=$("#cmdSQ").value.trim();
  return api("/api/radius/commands/sessions?"+new URLSearchParams({hours:cmdHours(),user:u,...(sq?{q:sq}:{})}))
    .then(d=>{cmdUsers[u]=d}).catch(e=>{cmdUsers[u]={error:e}});
};

async function loadCommands(){
  const jump=cmdUserFromHash();
  if(jump){cmdTab="sessions";cmdJump=jump}
  const sq=$("#cmdSQ").value.trim(),hours=cmdHours();
  const want=[...new Set([...cmdOpenCards(),...(jump?[jump]:[])])];
  try{
    const [act,sess]=await Promise.all([
      api("/api/radius/commands?"+cmdActQuery()),
      api("/api/radius/commands/sessions?"+new URLSearchParams({hours,...(sq?{q:sq}:{})})),
      ...want.map(cmdFetchUser)]);
    cmdData=act;cmdSess=sess;
    for(const u of Object.keys(cmdUsers))if(!want.includes(u))delete cmdUsers[u];
    renderCmdStatus();renderCmdKpis();renderCmdSources();renderCmdEvents();renderCmdView();renderCmdSessions();
  }catch(e){
    $("#cmdSessList").innerHTML=errorState("Could not load the command history",e);
    ["#cmdKpis","#cmdSources","#cmdStatus","#cmdList"].forEach(s=>{const el=$(s);if(el)el.innerHTML=""});
    $("#cmdCount").textContent=$("#cmdSCount").textContent="";
  }
}
/* which card is visible: the session log or all activity */
function renderCmdView(){
  $("#cmdSessCard").hidden=cmdTab!=="sessions";
  $("#cmdActCard").hidden=cmdTab!=="activity";
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
    ["Failed logins",t.failed||0,t.failed?"Reported by the devices":"None reported",t.failed?"bad":""],
    ["Users",t.users||0,`On ${fmtNum(t.devices||0)} device${t.devices===1?"":"s"}`]]);
}

/* ---- Session log: one card per user ---- */
function cmdKeep(s){
  const f=$("#cmdSFilter").value;
  return f==="changes"?s.changes>0:f==="active"?s.status==="active":f==="failed"?s.failed:true;
}
function cmdUserRows(){
  const by=new Map();
  for(const s of (cmdSess.sessions||[]).filter(cmdKeep)){
    let u=by.get(s.username);
    if(!u)by.set(s.username,u={user:s.username,sessions:0,failed:0,changes:0,commands:0,active:0,devices:new Set(),last:s.end||s.last,lastStart:s.start});
    if(s.failed)u.failed++;else u.sessions++;
    u.changes+=s.changes;u.commands+=s.commands;
    if(s.status==="active")u.active++;
    u.devices.add(s.device||s.device_ip);
  }
  return [...by.values()];
}
function renderCmdSessions(){
  const list=cmdUserRows(),all=cmdSess.sessions||[],filtered=$("#cmdSQ").value.trim()||$("#cmdSFilter").value;
  const n=list.reduce((a,u)=>a+u.sessions+u.failed,0);
  $("#cmdSCount").textContent=list.length?`${cmdPlural(list.length,"user")} · ${cmdPlural(n,"session")}`:"";
  if(!list.length){$("#cmdSessList").innerHTML=`<div class="empty"><b>${filtered&&all.length?"No matching sessions":"No sessions "+esc(CMD_PERIOD[cmdSess.hours]||"")}</b>${filtered?"Try another user, device, address or command, or a longer period.":"A session appears when a user logs in to a device that sends its logs to VAULT."}</div>`;return}
  if(cmdJump){const i=list.findIndex(u=>u.user===cmdJump);if(i>=0)PAGES.cmdSess=Math.floor(i/SIZES.cmdSess)+1}
  const open=new Set([...cmdOpenCards(),...(cmdJump?[cmdJump]:[])]);
  const {rows,bar}=paginate("cmdSess",list);
  morph($("#cmdSessList"),rows.map(u=>cmdCard(u,open.has(u.user))).join("")+bar);
  if(cmdJump){
    const el=[...document.querySelectorAll("#cmdSessList details")].find(d=>d.dataset.user===cmdJump);
    cmdJump="";
    if(el){el.open=true;setTimeout(()=>el.scrollIntoView({behavior:"smooth",block:"start"}),60)}
  }
}
function cmdCard(u,isOpen){
  const work=u.changes+u.commands,chgPct=work?Math.round(u.changes/work*100):0;
  const badges=(u.sessions?`<span class="rep-badge ${u.changes?"chg":"same"}">${cmdPlural(u.sessions,"session")}</span>`:"")+
    (u.failed?`<span class="rep-badge fail">${cmdPlural(u.failed,"failed login")}</span>`:"")+
    (u.active?'<span class="rep-badge is-live">Active now</span>':"");
  const devs=[...u.devices];
  return `<details class="rep-card cmd-card${u.changes?" has-chg":""}${u.active?" is-live":""}" data-key="${esc(u.user)}" data-user="${esc(u.user)}"${isOpen?" open":""}>
    <summary>
      <span class="rep-dev"><b>${esc(u.user)}</b><small title="${esc(devs.join(", "))}">${devs.length===1?esc(devs[0]):cmdPlural(devs.length,"device")}</small></span>
      <span class="cmd-badges">${badges}</span>
      <span class="rep-bar" title="${cmdPlural(u.changes,"change")} / ${cmdPlural(u.commands,"view command")}"><i class="chg" style="width:${chgPct}%"></i><i class="cmdv" style="width:${work?100-chgPct:0}%"></i></span>
      <span class="rep-lines"><span class="cmd-c">${cmdPlural(u.changes,"change")}</span><span class="cmd-v">${fmtNum(u.commands)} cmd</span></span>
      <span class="rep-last">${u.lastStart?`Last login<br> <b>${cmdDate(u.lastStart)}</b> <span class="t">${esc(bdClock(u.lastStart))}</span>`:`Last seen<br> <b>${cmdDate(u.last)}</b> <span class="t">${esc(bdClock(u.last))}</span>`}</span>
      <svg class="rep-chev" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
    </summary>
    <div class="rep-body">${isOpen?cmdBody(u.user):""}</div></details>`;
}
/* inside a user's card: each session as login -> commands -> logout */
function cmdBody(user){
  const d=cmdUsers[user];
  if(!d)return `<div class="loading-block" role="status"><span class="spin"></span>Loading ${esc(user)}'s sessions…</div>`;
  if(d.error)return errorState("Could not load these sessions",d.error);
  const list=(d.sessions||[]).filter(cmdKeep);
  if(!list.length)return `<p class="rep-note" style="padding:12px 0">No sessions ${esc(CMD_PERIOD[d.hours]||"")}.</p>`;
  return `<div class="rep-head"><span>Sessions, newest first</span></div><ol class="rep-tl cmd-tl">${list.map(cmdSessionItem).join("")}</ol>`;
}
function cmdSessionItem(s){
  const at=s.start||s.events[0]?.ts||s.end||s.last;
  const line=(t,cls,text)=>`<span class="l ${cls}"><time>${t?esc(bdClock(t,true)):"--:--"}</time><span>${text}</span></span>`;
  let log;
  if(s.failed)log=line(s.start,"fail",`✕ Login refused${s.source_ip?" from "+esc(s.source_ip):""}`);
  else{
    const steps=s.events.filter(e=>e.kind==="change"||e.kind==="command").map(e=>{
      const bad=e.result&&!/^succ/i.test(e.result);
      return line(e.ts,e.kind==="change"?"chg":"cmd",`<i>${e.kind==="change"?"change":"view"}</i>${esc(e.command)}${bad?` <em>(${esc(e.result)})</em>`:""}`)}).join("");
    log=(s.start?line(s.start,"in",`▶ Logged in${s.source_ip?" from "+esc(s.source_ip):""}`):line(null,"in","▶ Logged in before this period"))+
      (steps||`<span class="l none"><time></time><span>No commands in this session</span></span>`)+
      (s.status==="closed"?line(s.end,"out",`◀ Logged out · ${cmdDur(s.duration)} on the device`):
       s.status==="active"?line(null,"now","● Still logged in"):line(s.last,"out","◀ No logout recorded (last activity)"));
  }
  return `<li class="st-${esc(s.status)}">
    <div class="rep-when"><b>${cmdDate(at)}</b><span>${esc(bdClock(at))}</span></div>
    <div class="rep-what">
      <p class="cmd-sline"><b>${esc(s.device||s.device_ip)}</b>${s.device?` <span class="m">${esc(s.device_ip)}</span>`:""}
        ${s.failed?"":`<span>${cmdDur(s.duration)}</span>`}
        ${s.changes?`<span class="cmd-c">${cmdPlural(s.changes,"change")}</span>`:""}${s.commands?`<span>${cmdPlural(s.commands,"command")}</span>`:""}</p>
      <pre class="rep-prev cmd-log">${log}</pre></div>
    <div class="rep-act">${cmdPill(s.status)}</div></li>`;
}
/* opening a card loads that user's sessions */
$o("#cmdSessList").addEventListener("toggle",e=>{
  const d=e.target;if(!d.matches||!d.matches("details[data-user]")||!d.open)return;
  const u=d.dataset.user,body=d.querySelector(".rep-body");
  if(cmdUsers[u]){body.innerHTML=cmdBody(u);return}
  body.innerHTML=cmdBody(u);
  cmdFetchUser(u).then(()=>{if(d.open)body.innerHTML=cmdBody(u)});
},true);
function cmdOpenUser(name){
  history.pushState(null,"","#user="+encodeURIComponent(name));
  loadCommands();
}
addEventListener("popstate",()=>{if(PAGE==="radius-commands")loadCommands()});

/* ---- All activity ---- */
function renderCmdEvents(){
  const list=cmdData.events||[],q=$("#cmdQ").value.trim(),k=$("#cmdKind").value;
  $("#cmdCount").textContent=list.length?`${fmtNum(list.length)} event${list.length===1?"":"s"}${list.length>=cmdData.limit?` shown (newest ${fmtNum(cmdData.limit)}; Export CSV has all)`:""}`:"";
  if(!list.length){
    $("#cmdList").innerHTML=`<div class="empty"><b>${q||k?"Nothing matches":"No activity "+esc(CMD_PERIOD[cmdData.hours]||"")}</b>${q||k?"Try another user, device, address or command, or a longer period.":"User actions appear here as soon as a device sends them."}</div>`;return}
  const {rows,bar}=paginate("cmdEvents",list);
  morph($("#cmdList"),`<div class="tbl"><table class="cmd-table"><thead><tr><th>Time</th><th>User</th><th>Device</th><th>Type</th><th>Command / detail</th><th>From</th></tr></thead><tbody>`+
    rows.map(e=>{const [label,cls]=CMD_KIND[e.kind]||[e.kind,""];
      const failed=e.result&&!/^succ/i.test(e.result);
      return `<tr data-key="${e.id}"><td class="when">${fmtWhen(e.ts)}</td><td><button type="button" class="cmd-user" data-user="${esc(e.username)}">${esc(e.username)}</button></td>
        <td>${cmdDevice(e.device,e.device_ip)}</td>
        <td><span class="pill ${cls}">${esc(label)}</span></td>
        <td>${/^log/.test(e.kind)?(e.command?`<span class="d">via ${esc(e.command.toUpperCase())}</span>`:'<span class="none">-</span>'):e.command?`<code class="cmd">${esc(e.command)}</code>`:'<span class="none">-</span>'}${failed?` <span class="sub bad-t">Result: ${esc(e.result)}</span>`:""}</td>
        <td class="m">${esc(e.source_ip||"-")}</td></tr>`}).join("")+`</tbody></table></div>`+bar);
}
$o("#cmdList").addEventListener("click",e=>{const b=e.target.closest(".cmd-user");if(b)cmdOpenUser(b.dataset.user)});

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

PAGES.cmdEvents=PAGES.cmdSources=PAGES.cmdSess=1;
for(const k of ["cmdEvents","cmdSources","cmdSess"]){const v=+localStorage.getItem("dbms_page_size_"+k);SIZES[k]=PAGE_SIZES.includes(v)?v:10}
REDRAW.cmdEvents=renderCmdEvents;REDRAW.cmdSources=renderCmdSources;REDRAW.cmdSess=renderCmdSessions;
let cmdT=0;
$o("#cmdQ").addEventListener("input",()=>{clearTimeout(cmdT);cmdT=setTimeout(()=>{PAGES.cmdEvents=1;loadCommands()},350)});
$o("#cmdSQ").addEventListener("input",()=>{clearTimeout(cmdT);cmdT=setTimeout(()=>{PAGES.cmdSess=1;loadCommands()},350)});
$o("#cmdSFilter").addEventListener("change",()=>{PAGES.cmdSess=1;renderCmdSessions()});
$o("#cmdKind").addEventListener("change",()=>{PAGES.cmdEvents=1;loadCommands()});
$o("#cmdHours").addEventListener("change",()=>{PAGES.cmdEvents=PAGES.cmdSess=1;loadCommands()});
$o("#cmdRefresh").addEventListener("click",()=>loadCommands());
$o("#cmdTabs").addEventListener("click",e=>{const b=e.target.closest("[data-cmd-tab]");if(!b)return;cmdTab=b.dataset.cmdTab;renderCmdView(null)});
$o("#cmdCsv").addEventListener("click",()=>{const p=cmdActQuery();p.set("format","csv");location.href="/api/radius/commands?"+p});
if(PAGE==="radius-commands")setInterval(()=>{if(!document.hidden&&cmdData)loadCommands()},30000);
