/* VAULT - pages/commands.js
   Command History (/radius/commands): what users did on the network devices, read from the devices' syslog by
   the vault-syslog receiver. Search and the type filter run on the server (newest 500 matches are sent);
   Export CSV downloads every match (up to 50,000). Refreshes itself every 30 seconds while the page is open. */
let cmdData=null;
const CMD_PERIOD={24:"in the last 24 hours",168:"in the last 7 days",720:"in the last 30 days"};
const CMD_KIND={change:["Change","k-change"],command:["Command","k-command"],login:["Login","k-login"],logout:["Logout","k-logout"],"login-failed":["Failed login","k-fail"]};
const cmdQuery=()=>{
  const p=new URLSearchParams({hours:$("#cmdHours").value||"24"});
  const q=$("#cmdQ").value.trim(),k=$("#cmdKind").value;
  if(q)p.set("q",q);if(k)p.set("kind",k);
  return p;
};
async function loadCommands(){
  try{
    cmdData=await api("/api/radius/commands?"+cmdQuery());
    renderCmdStatus();renderCmdKpis();renderCmdEvents();renderCmdSources();
  }catch(e){
    $("#cmdList").innerHTML=errorState("Could not load the command history",e);
    ["#cmdKpis","#cmdSources","#cmdStatus"].forEach(s=>{const el=$(s);if(el)el.innerHTML=""});$("#cmdCount").textContent="";
  }
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
  const t=cmdData.totals||{},per=CMD_PERIOD[cmdData.hours]||"";
  const top=(cmdData.top_changers||[])[0];
  radKpis("#cmdKpis",[
    ["Changes",t.changes||0,top?`Most by ${top.username} (${fmtNum(top.n)})`:`Configuration commands ${per}`,t.changes?"warn":""],
    ["Commands",t.commands||0,"Show / display and other view-only commands"],
    ["Logins",t.logins||0,`Successful device logins ${per}`,"g"],
    ["Failed logins",t.failed||0,t.failed?"Reported by the devices":"None reported",t.failed?"bad":""],
    ["Users",t.users||0,`On ${fmtNum(t.devices||0)} device${t.devices===1?"":"s"}`]]);
}
function renderCmdEvents(){
  const list=cmdData.events||[],q=$("#cmdQ").value.trim(),k=$("#cmdKind").value;
  $("#cmdCount").textContent=list.length?`${fmtNum(list.length)} event${list.length===1?"":"s"}${list.length>=cmdData.limit?` shown (newest ${fmtNum(cmdData.limit)}; Export CSV has all)`:""}`:"";
  if(!list.length){
    $("#cmdList").innerHTML=`<div class="empty"><b>${q||k?"Nothing matches":"No activity "+esc(CMD_PERIOD[cmdData.hours]||"")}</b>${q||k?"Try another user, device, address or command, or a longer period.":"User actions appear here as soon as a device sends them."}</div>`;return}
  const {rows,bar}=paginate("cmdEvents",list);
  morph($("#cmdList"),`<div class="tbl"><table class="cmd-table"><thead><tr><th>Time</th><th>User</th><th>Device</th><th>Type</th><th>Command / detail</th><th>From</th></tr></thead><tbody>`+
    rows.map(e=>{const [label,cls]=CMD_KIND[e.kind]||[e.kind,""];
      const failed=e.result&&!/^succ/i.test(e.result);
      return `<tr data-key="${e.id}"><td class="when">${fmtWhen(e.ts)}</td><td><strong>${esc(e.username)}</strong></td>
        <td><span class="dn">${esc(e.device||e.device_ip)}</span>${e.device?`<span class="sub m">${esc(e.device_ip)}</span>`:""}</td>
        <td><span class="pill ${cls}">${esc(label)}</span></td>
        <td>${/^log/.test(e.kind)?(e.command?`<span class="d">via ${esc(e.command.toUpperCase())}</span>`:'<span class="none">-</span>'):e.command?`<code class="cmd">${esc(e.command)}</code>`:'<span class="none">-</span>'}${failed?` <span class="sub bad-t">Result: ${esc(e.result)}</span>`:""}</td>
        <td class="m">${esc(e.source_ip||"-")}</td></tr>`}).join("")+`</tbody></table></div>`+bar);
}
function renderCmdSources(){
  const list=cmdData.sources||[],box=$("#cmdSources");
  if(!list.length){box.innerHTML=`<div class="empty"><b>No device has sent logs yet</b>Devices appear here with their first message.</div>`;return}
  const {rows,bar}=paginate("cmdSources",list);
  box.innerHTML=`<div class="tbl"><table><thead><tr><th>Device</th><th>Last message</th><th>Messages</th><th>User actions</th><th>Status</th></tr></thead><tbody>`+
    rows.map(s=>`<tr><td><span class="dn">${esc(s.device||s.ip)}</span>${s.device?`<span class="sub m">${esc(s.ip)}</span>`:""}</td>
      <td class="when">${fmtWhen(s.last_seen)}</td><td>${fmtNum(s.received)}</td><td>${fmtNum(s.recognized)}</td>
      <td>${s.recognized?'<span class="pill UP">Working</span>':`<span class="pill k-change">No user actions yet</span>`}
        ${!s.recognized&&s.sample?`<details class="cmd-sample"><summary>Last message received</summary><code>${esc(s.sample)}</code></details>`:""}</td></tr>`).join("")+`</tbody></table></div>`+bar;
}
PAGES.cmdEvents=PAGES.cmdSources=1;
for(const k of ["cmdEvents","cmdSources"]){const v=+localStorage.getItem("dbms_page_size_"+k);SIZES[k]=PAGE_SIZES.includes(v)?v:10}
REDRAW.cmdEvents=renderCmdEvents;REDRAW.cmdSources=renderCmdSources;
let cmdT=0;
$o("#cmdQ").addEventListener("input",()=>{clearTimeout(cmdT);cmdT=setTimeout(()=>{PAGES.cmdEvents=1;loadCommands()},350)});
$o("#cmdKind").addEventListener("change",()=>{PAGES.cmdEvents=1;loadCommands()});
$o("#cmdHours").addEventListener("change",()=>{PAGES.cmdEvents=1;loadCommands()});
$o("#cmdRefresh").addEventListener("click",()=>loadCommands());
$o("#cmdCsv").addEventListener("click",()=>{const p=cmdQuery();p.set("format","csv");location.href="/api/radius/commands?"+p});
if(PAGE==="radius-commands")setInterval(()=>{if(!document.hidden&&cmdData)loadCommands()},30000);
