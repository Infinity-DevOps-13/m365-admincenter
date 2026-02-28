// ===== Admin SIM: RBAC + MFA(83) + Device Compliance + Password Policy + Role Assignment =====
// Browser-only. localStorage only. Safe learning project. Never use real passwords.

const STORE = "adminSim.v4";
const SESSION_KEY = "adminSim.session.v1";
const DEVICE_FLAG = "adminSim.device.compliant";

const MFA_NUMBER = "83";                 // always 83 (simulated)
const MAX_ATTEMPTS = 3;                  // lockout after 3 wrong passwords
const LOCKOUT_SECONDS = 60;              // lock for 60s
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;   // auto logout after 5 minutes

// Roles
const ROLES = {
  STUDENT: "Student",
  TEACHER: "Teacher",
  HELPDESK: "Helpdesk",
  ICT_ADMIN: "ICT Admin",
  GLOBAL_ADMIN: "Global Admin"
};
const ROLE_ORDER = [ROLES.STUDENT, ROLES.TEACHER, ROLES.HELPDESK, ROLES.ICT_ADMIN, ROLES.GLOBAL_ADMIN];

// Demo accounts (login usernames). Password = "demo"
const demoAccounts = [
  { username: "student.demo", displayName: "Student Demo", role: ROLES.STUDENT },
  { username: "teacher.demo", displayName: "Teacher Demo", role: ROLES.TEACHER },
  { username: "helpdesk.demo", displayName: "Helpdesk Demo", role: ROLES.HELPDESK },
  { username: "ict.demo", displayName: "ICT Admin Demo", role: ROLES.ICT_ADMIN },
  { username: "global.demo", displayName: "Global Admin Demo", role: ROLES.GLOBAL_ADMIN }
];

// Default state
const defaultState = {
  orgName: "SMK Demo School Tenant",
  users: [
    { id: uid(), name: "Student A", email: "studA@school.edu", role: ROLES.STUDENT, active: true },
    { id: uid(), name: "Teacher B", email: "teachB@school.edu", role: ROLES.TEACHER, active: true },
    { id: uid(), name: "Helpdesk C", email: "helpC@school.edu", role: ROLES.HELPDESK, active: true }
  ],
  policies: {
    mfaRequired: false,
    requireCompliantDevice: false,
    copilotEnabled: false,
    onedriveQuotaGB: 10,
    pwMinLen: 8,
    pwRequireNumber: true,
    pwRequireUpper: true
  },
  audit: [],
  security: {}
};

// Runtime
let state = loadState();
let current = null;
let pendingLogin = null;
let idleTimer = null;

// -------- Login DOM
const loginScreen = document.getElementById("loginScreen");
const appScreen   = document.getElementById("appScreen");
const stepEmail   = document.getElementById("step-email");
const stepPassword= document.getElementById("step-password");
const stepStay    = document.getElementById("step-stay");
const stepMfa     = document.getElementById("step-mfa");
const stepError   = document.getElementById("step-error");
const loginEmail  = document.getElementById("loginEmail");
const loginPassword = document.getElementById("loginPassword");
const showPw      = document.getElementById("showPw");
const whoPill     = document.getElementById("whoPill");
const tenantPill  = document.getElementById("tenantPill");
const lockoutMsg  = document.getElementById("lockoutMsg");
const deviceCompliantFlag = document.getElementById("deviceCompliantFlag");
const btnNextToPassword = document.getElementById("btnNextToPassword");
const btnBackToEmail    = document.getElementById("btnBackToEmail");
const btnSignIn         = document.getElementById("btnSignIn");
const btnCreateAccount  = document.getElementById("btnCreateAccount");
const btnForgotPw       = document.getElementById("btnForgotPw");
const staySignedIn      = document.getElementById("staySignedIn");
const btnNoStay         = document.getElementById("btnNoStay");
const btnYesStay        = document.getElementById("btnYesStay");
const mfaInput          = document.getElementById("mfaInput");
const btnMfaCancel      = document.getElementById("btnMfaCancel");
const btnMfaVerify      = document.getElementById("btnMfaVerify");
const errorText         = document.getElementById("errorText");
const btnBackToStart    = document.getElementById("btnBackToStart");
const btnResetAll       = document.getElementById("btnResetAll");

// -------- App DOM
const orgNameEl   = document.getElementById("orgName");
const whoName     = document.getElementById("whoName");
const whoRole     = document.getElementById("whoRole");
const btnLogout   = document.getElementById("btnLogout");
const nav         = document.getElementById("nav");
const roleCaps    = document.getElementById("roleCaps");
const statUsers   = document.getElementById("statUsers");
const statDevice  = document.getElementById("statDevice");
const statMfa     = document.getElementById("statMfa");
const pMfa        = document.getElementById("pMfa");
const pDevice     = document.getElementById("pDevice");
const pQuota      = document.getElementById("pQuota");
const pCopilot    = document.getElementById("pCopilot");
const pPwSummary  = document.getElementById("pPwSummary");

// Users
const btnShowAddUser = document.getElementById("btnShowAddUser");
const userForm       = document.getElementById("userForm");
const btnAddUser     = document.getElementById("btnAddUser");
const btnCancelAddUser = document.getElementById("btnCancelAddUser");
const newUserName    = document.getElementById("newUserName");
const newUserEmail   = document.getElementById("newUserEmail");
const newUserRole    = document.getElementById("newUserRole");
const usersTbody     = document.getElementById("usersTbody");
const userSearch     = document.getElementById("userSearch");
const userCount      = document.getElementById("userCount");

// Policies
const polMfa            = document.getElementById("polMfa");
const polRequireDevice  = document.getElementById("polRequireDevice");
const polCopilot        = document.getElementById("polCopilot");
const polQuota          = document.getElementById("polQuota");
const polPwMinLen       = document.getElementById("polPwMinLen");
const polPwRequireNumber= document.getElementById("polPwRequireNumber");
const polPwRequireUpper = document.getElementById("polPwRequireUpper");
const btnSavePolicies   = document.getElementById("btnSavePolicies");

// Audit / Export
const auditList   = document.getElementById("auditList");
const btnClearAudit = document.getElementById("btnClearAudit");
const btnExport   = document.getElementById("btnExport");
const importFile  = document.getElementById("importFile");
const btnReset    = document.getElementById("btnReset");

// ===== INIT
initRoleDropdown();
wireLogin();
wireApp();
restoreDeviceCheckbox();
restoreSessionOrShowLogin();

// ===== Helpers
function uid(){ return Math.random().toString(36).slice(2,10); }
function escapeHtml(s){ return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function clone(x){ return JSON.parse(JSON.stringify(x)); }
function now(){ return new Date().toLocaleString(); }
function saveState(){ localStorage.setItem(STORE, JSON.stringify(state)); }
function loadState(){ const raw = localStorage.getItem(STORE); if(!raw) return clone(defaultState); try { return JSON.parse(raw); } catch { return clone(defaultState); } }
function isRoleAtLeast(role){ return ROLE_ORDER.indexOf(current.role) >= ROLE_ORDER.indexOf(role); }
function deviceIsCompliant(){ return localStorage.getItem(DEVICE_FLAG) === "1"; }
function setDeviceCompliant(flag){ localStorage.setItem(DEVICE_FLAG, flag ? "1" : "0"); }

// ===== Login wiring
function restoreDeviceCheckbox(){ deviceCompliantFlag.checked = deviceIsCompliant(); }
function wireLogin(){
  btnResetAll.onclick = resetEverything;
  btnCreateAccount.onclick = ()=> alert("Simulator only: demo accounts are pre-created.");
  btnForgotPw.onclick = ()=> alert("Simulator only: password is demo.");
  deviceCompliantFlag.onchange = ()=> setDeviceCompliant(deviceCompliantFlag.checked);

  btnNextToPassword.onclick = ()=>{
    const id = (loginEmail.value || "").trim().toLowerCase();
    if(!id) return showError("Please enter a demo username (e.g. ict.demo)");
    const acct = demoAccounts.find(a=>a.username.toLowerCase() === id);
    if(!acct) return showError("Demo account not found (try ict.demo or global.demo)");

    if(isLocked(acct.username)){
      const secs = secondsLeft(acct.username);
      return showLockout(`This account is locked. Try again in ${secs}s.`);
    } else hideLockout();

    whoPill.textContent = acct.username;
    tenantPill.textContent = `Tenant: ${state.orgName}`;
    gotoStep("password");
    loginPassword.value = ""; showPw.checked = false; loginPassword.type = "password";
  };

  btnBackToEmail.onclick = ()=> gotoStep("email");
  showPw.onchange = ()=> { loginPassword.type = showPw.checked ? "text" : "password"; };

  btnSignIn.onclick = ()=>{
    const id = whoPill.textContent.trim().toLowerCase();
    const acct = demoAccounts.find(a=>a.username.toLowerCase() === id);
    if(!acct) return showError("Account not found. Go back and try again.");

    if(isLocked(acct.username)){
      const secs = secondsLeft(acct.username);
      return showLockout(`This account is locked. Try again in ${secs}s.`);
    } else hideLockout();

    const pwd = (loginPassword.value || "").trim();
    if(pwd !== "demo"){
      registerFail(acct.username);
      audit(`LOGIN FAIL: ${acct.username} (wrong password)`);
      if(isLocked(acct.username)){
        audit(`LOCKOUT: ${acct.username} for ${LOCKOUT_SECONDS}s`);
        return showLockout(`Too many attempts. Locked for ${LOCKOUT_SECONDS}s.`);
      }
      return showError("Incorrect password (hint: demo).");
    }

    clearFails(acct.username);
    pendingLogin = acct;
    audit(`PASSWORD OK: ${acct.username}`);
    gotoStep("stay");
  };

  btnNoStay.onclick = ()=> afterStay(false);
  btnYesStay.onclick = ()=> afterStay(true);

  // MFA step
  btnMfaCancel.onclick = ()=>{
    audit(`MFA CANCEL: ${pendingLogin ? pendingLogin.username : "unknown"}`);
    pendingLogin = null;
    gotoStep("email");
  };
  btnMfaVerify.onclick = ()=>{
    const v = (mfaInput.value || "").trim();
    if(v !== MFA_NUMBER){
      audit(`MFA FAIL: ${pendingLogin ? pendingLogin.username : "unknown"} (entered=${v})`);
      return showError("Incorrect number. Enter 83.");
    }
    audit(`MFA OK: ${pendingLogin.username} (83)`);
    finalizeLogin();
  };

  btnBackToStart.onclick = ()=> gotoStep("email");
}

function afterStay(remember){
  if(state.policies.requireCompliantDevice && !deviceIsCompliant()){
    audit(`SIGN-IN BLOCK: Non-compliant device (policy)`);
    return showError("Device is not compliant (toggle it on the first login step).");
  }
  if(state.policies.mfaRequired){
    mfaInput.value = "";
    gotoStep("mfa");
    audit(`MFA REQUIRED: ${pendingLogin.username}`);
    return;
  }
  finalizeLogin(remember);
}

function finalizeLogin(remember=false){
  if(!pendingLogin) return showError("Login session expired. Try again.");
  current = { username: pendingLogin.username, displayName: pendingLogin.displayName, role: pendingLogin.role };
  audit(`LOGIN SUCCESS: ${current.username} role=${current.role}`);
  if(remember){ localStorage.setItem(SESSION_KEY, JSON.stringify({ username: current.username })); audit("SESSION: Remembered"); }
  else { localStorage.removeItem(SESSION_KEY); }
  pendingLogin = null;
  showApp();
}

// ===== Security: lockout
function ensureSec(u){ if(!state.security[u]) state.security[u] = { attempts: 0, lockedUntil: 0 }; return state.security[u]; }
function registerFail(u){ const s = ensureSec(u); s.attempts += 1; if(s.attempts >= MAX_ATTEMPTS){ s.lockedUntil = Date.now() + LOCKOUT_SECONDS*1000; s.attempts = 0; } saveState(); }
function clearFails(u){ const s = ensureSec(u); s.attempts = 0; s.lockedUntil = 0; saveState(); }
function isLocked(u){ const s = ensureSec(u); return Date.now() < s.lockedUntil; }
function secondsLeft(u){ const s = ensureSec(u); return Math.max(0, Math.ceil((s.lockedUntil - Date.now())/1000)); }
function showLockout(text){ lockoutMsg.style.display = "block"; lockoutMsg.textContent = text; }
function hideLockout(){ lockoutMsg.style.display = "none"; lockoutMsg.textContent = ""; }

// ===== App wiring
function wireApp(){
  if(nav){
    nav.querySelectorAll(".nav-btn").forEach(btn=>{
      btn.onclick = ()=>{
        nav.querySelectorAll(".nav-btn").forEach(b=>b.classList.remove("active"));
        btn.classList.add("active");
        const view = btn.dataset.view;
        document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
        const target = document.getElementById(`view-${view}`);
        if(target) target.classList.add("active");
        renderAll();
      };
    });
  }
  btnLogout.onclick = ()=>{
    audit(`LOGOUT: ${current ? current.username : "unknown"}`);
    current = null; localStorage.removeItem(SESSION_KEY); showLogin();
  };
  btnShowAddUser.onclick = ()=> userForm.classList.remove("hidden");
  btnCancelAddUser.onclick = ()=> userForm.classList.add("hidden");
  btnAddUser.onclick = addUser;
  userSearch.oninput = renderUsers;
  btnSavePolicies.onclick = savePolicies;
  btnClearAudit.onclick = ()=>{
    if(!isRoleAtLeast(ROLES.ICT_ADMIN)) return alert("Access denied.");
    if(confirm("Clear audit logs?")){ state.audit = []; saveState(); renderAudit(); }
  };
  btnExport.onclick = exportJson;
  importFile.onchange = importJson;
  btnReset.onclick = ()=>{
    if(!isRoleAtLeast(ROLES.ICT_ADMIN)) return alert("Access denied.");
    if(confirm("Reset everything?")){ state = clone(defaultState); saveState(); audit("RESET: Factory defaults"); renderAll(); }
  };
  ["click","mousemove","keydown","touchstart"].forEach(evt=>{
    document.addEventListener(evt, resetIdleTimer, { passive: true });
  });
}
function initRoleDropdown(){
  newUserRole.innerHTML = "";
  Object.values(ROLES).forEach(r=>{
    const opt = document.createElement("option");
    opt.value = r; opt.textContent = r;
    newUserRole.appendChild(opt);
  });
}
function restoreSessionOrShowLogin(){
  const raw = localStorage.getItem(SESSION_KEY);
  if(!raw) return showLogin();
  try{
    const sess = JSON.parse(raw);
    const acct = demoAccounts.find(a=>a.username === sess.username);
    if(!acct) return showLogin();
    current = { username: acct.username, displayName: acct.displayName, role: acct.role };
    audit(`SESSION RESTORE: ${current.username}`);
    showApp();
  }catch{ showLogin(); }
}

// ===== View switching & Idle timer
function showLogin(){ loginScreen.classList.remove("hidden"); appScreen.classList.add("hidden"); loginEmail.value=""; loginPassword.value=""; mfaInput.value=""; hideLockout(); gotoStep("email"); stopIdleTimer(); }
function showApp(){ loginScreen.classList.add("hidden"); appScreen.classList.remove("hidden"); orgNameEl.textContent = state.orgName; whoName.textContent = current.displayName; whoRole.textContent = current.role; renderAll(); startIdleTimer(); }
function gotoStep(name){ [stepEmail, stepPassword, stepStay, stepMfa, stepError].forEach(x=>x.classList.add("hidden")); if(name==="email")stepEmail.classList.remove("hidden"); if(name==="password")stepPassword.classList.remove("hidden"); if(name==="stay")stepStay.classList.remove("hidden"); if(name==="mfa")stepMfa.classList.remove("hidden"); if(name==="error")stepError.classList.remove("hidden"); }
function showError(msg){ errorText.textContent = msg; gotoStep("error"); }
function startIdleTimer(){ stopIdleTimer(); idleTimer = setTimeout(()=>{ if(current){ audit(`AUTO LOGOUT: idle timeout (5 min) user=${current.username}`); current=null; localStorage.removeItem(SESSION_KEY); showLogin(); alert("Logged out due to inactivity (simulated)."); } }, IDLE_TIMEOUT_MS); }
function resetIdleTimer(){ if(!current) return; startIdleTimer(); }
function stopIdleTimer(){ if(idleTimer) clearTimeout(idleTimer); idleTimer = null; }

// ===== Rendering
function renderAll(){ renderDashboard(); renderUsers(); renderPoliciesUI(); renderAudit(); }
function roleCapabilities(role){ if(role===ROLES.STUDENT)return["View own profile (simulated)"]; if(role===ROLES.TEACHER)return["View users (read-only)"]; if(role===ROLES.HELPDESK)return["Reset passwords (simulated)","Disable/enable users","View audit logs"]; if(role===ROLES.ICT_ADMIN)return["Manage users","Edit policies","Export/Import","View audit logs"]; if(role===ROLES.GLOBAL_ADMIN)return["Full tenant control","Change user roles","Edit all policies","View audit logs"]; return["Unknown role"]; }
function renderDashboard(){ if(statUsers)statUsers.textContent=String(state.users.length); if(statDevice)statDevice.textContent=deviceIsCompliant()?"Yes":"No"; if(statMfa)statMfa.textContent=state.policies.mfaRequired?"Yes":"No"; pMfa.textContent=state.policies.mfaRequired?"Yes":"No"; pDevice.textContent=state.policies.requireCompliantDevice?"Yes":"No"; pQuota.textContent=`${state.policies.onedriveQuotaGB} GB`; pCopilot.textContent=state.policies.copilotEnabled?"Yes":"No"; pPwSummary.textContent=`min ${state.policies.pwMinLen}`+(state.policies.pwRequireNumber?", number":"")+(state.policies.pwRequireUpper?", uppercase":""); roleCaps.innerHTML = roleCapabilities(current.role).map(x=>`<li>${escapeHtml(x)}</li>`).join(""); }
function renderPoliciesUI(){ polMfa.checked=!!state.policies.mfaRequired; polRequireDevice.checked=!!state.policies.requireCompliantDevice; polCopilot.checked=!!state.policies.copilotEnabled; polQuota.value=state.policies.onedriveQuotaGB??10; polPwMinLen.value=state.policies.pwMinLen??8; polPwRequireNumber.checked=!!state.policies.pwRequireNumber; polPwRequireUpper.checked=!!state.policies.pwRequireUpper; const editable=isRoleAtLeast(ROLES.ICT_ADMIN); [polMfa,polRequireDevice,polCopilot,polQuota,polPwMinLen,polPwRequireNumber,polPwRequireUpper].forEach(el=>el.disabled=!editable); btnSavePolicies.style.display=editable?"":"none"; }
function renderUsers(){ let list=state.users.slice(); const q=(userSearch.value||"").trim().toLowerCase(); if(q){ list=list.filter(u=>u.name.toLowerCase().includes(q)||u.email.toLowerCase().includes(q)); } userCount.textContent=`${list.length} users`; usersTbody.innerHTML=""; list.forEach(u=>{ const canHelpdesk=isRoleAtLeast(ROLES.HELPDESK); const canAdmin=isRoleAtLeast(ROLES.ICT_ADMIN); const isGA=current.role===ROLES.GLOBAL_ADMIN; const roleCell=isGA?`<select class="small" data-act="setrole" data-id="${u.id}">${Object.values(ROLES).map(r=>`<option value="${r}" ${r===u.role?"selected":""}>${r}</option>`).join("")}</select>`:`<span class="badge">${escapeHtml(u.role)}</span>`; const actions=[]; if(canHelpdesk){ actions.push(`<button class="small" data-act="toggle" data-id="${u.id}">${u.active?"Disable":"Enable"}</button>`); actions.push(`<button class="small" data-act="resetpw" data-id="${u.id}">Reset PW</button>`); } if(canAdmin){ actions.push(`<button class="small danger" data-act="del" data-id="${u.id}">Delete</button>`); } const tr=document.createElement("tr"); tr.innerHTML=`<td>${escapeHtml(u.name)}</td><td>${escapeHtml(u.email)}</td><td>${roleCell}</td><td>${u.active?`<span class="badge" style="color:#22c55e">Active</span>`:`<span class="badge" style="color:#f59e0b">Disabled</span>`}</td><td>${actions.length?actions.join(" "):`<span class="muted">No actions</span>`}</td>`; tr.querySelectorAll("[data-act]").forEach(el=>{ const id=el.dataset.id; const act=el.dataset.act; if(act==="toggle")el.onclick=()=>toggleUser(id); if(act==="resetpw")el.onclick=()=>resetPassword(id); if(act==="del")el.onclick=()=>deleteUser(id); if(act==="setrole")el.onchange=(e)=>setUserRole(id,e.target.value); }); usersTbody.appendChild(tr); }); }
function renderAudit(){ auditList.innerHTML=""; if(!isRoleAtLeast(ROLES.HELPDESK)){ auditList.innerHTML=`<li><b>Access denied</b><br><span class="muted tiny">Audit logs require Helpdesk or higher.</span></li>`; return; } state.audit.slice(0,60).forEach(a=>{ const li=document.createElement("li"); li.innerHTML=`<b>${escapeHtml(a.msg)}</b><br><span class="muted tiny">${escapeHtml(a.time)}</span>`; auditList.appendChild(li); }); }

// ===== Data actions
function addUser(){ if(!isRoleAtLeast(ROLES.ICT_ADMIN)) return alert("Access denied."); const name=newUserName.value.trim(); const email=newUserEmail.value.trim(); const role=newUserRole.value; if(!name||!email) return alert("Please enter name and email."); if(state.users.some(u=>u.email.toLowerCase()===email.toLowerCase())) return alert("Email already exists."); state.users.push({ id:uid(), name, email, role, active:true }); saveState(); audit(`USER CREATE: ${email} (role=${role})`); newUserName.value=""; newUserEmail.value=""; userForm.classList.add("hidden"); renderUsers(); renderDashboard(); }
function toggleUser(id){ if(!isRoleAtLeast(ROLES.HELPDESK)) return alert("Access denied."); const u=state.users.find(x=>x.id===id); if(!u) return; u.active=!u.active; saveState(); audit(`USER ${u.active?"ENABLE":"DISABLE"}: ${u.email}`); renderUsers(); }
function resetPassword(id){ if(!isRoleAtLeast(ROLES.HELPDESK)) return alert("Access denied."); const u=state.users.find(x=>x.id===id); if(!u) return; const npw=prompt(`Enter new password for ${u.email}\n(Policy enforced)`); if(npw===null) return; const result=checkPasswordAgainstPolicy(npw); if(!result.ok) return alert(`Password does not meet policy:\n- ${result.reason}`); audit(`RESET PW (sim): ${u.email} • compliant with policy`); alert("Password reset simulated (policy OK)."); }
function deleteUser(id){ if(!isRoleAtLeast(ROLES.ICT_ADMIN)) return alert("Access denied."); const u=state.users.find(x=>x.id===id); if(!u) return; if(!confirm(`Delete user ${u.email}?`)) return; state.users=state.users.filter(x=>x.id!==id); saveState(); audit(`USER DELETE: ${u.email}`); renderUsers(); renderDashboard(); }
function setUserRole(id,newRole){ if(current.role!==ROLES.GLOBAL_ADMIN) return alert("Only Global Admin can change roles."); const u=state.users.find(x=>x.id===id); if(!u) return; const old=u.role; u.role=newRole; saveState(); audit(`ROLE CHANGE: ${u.email} ${old} → ${newRole}`); if(u.email===current.username){ alert("You changed your own role. RBAC will apply immediately."); } renderUsers(); renderDashboard(); }

// ===== Password policy
function checkPasswordAgainstPolicy(pw){ const p=state.policies; if(pw.length<p.pwMinLen) return {ok:false,reason:`Minimum length ${p.pwMinLen}`}; if(p.pwRequireNumber && !/[0-9]/.test(pw)) return {ok:false,reason:"Must contain a number"}; if(p.pwRequireUpper && !/[A-Z]/.test(pw)) return {ok:false,reason:"Must contain an uppercase letter"}; return {ok:true}; }

// ===== Policies save
function savePolicies(){ if(!isRoleAtLeast(ROLES.ICT_ADMIN)) return alert("Access denied."); state.policies.mfaRequired=!!polMfa.checked; state.policies.requireCompliantDevice=!!polRequireDevice.checked; state.policies.copilotEnabled=!!polCopilot.checked; state.policies.onedriveQuotaGB=Math.max(1, parseInt(polQuota.value||"10",10)); state.policies.pwMinLen=Math.max(4, parseInt(polPwMinLen.value||"8",10)); state.policies.pwRequireNumber=!!polPwRequireNumber.checked; state.policies.pwRequireUpper=!!polPwRequireUpper.checked; saveState(); audit(`POLICY UPDATE: mfa=${state.policies.mfaRequired}, device=${state.policies.requireCompliantDevice}, quota=${state.policies.onedriveQuotaGB}, pw(min=${state.policies.pwMinLen}, num=${state.policies.pwRequireNumber}, upper=${state.policies.pwRequireUpper})`); renderDashboard(); alert("Policies saved (simulated)."); }

// ===== Audit / Export
function audit(message){ state.audit.unshift({ time: now(), msg: message }); if(state.audit.length>300) state.audit.pop(); saveState(); renderAudit(); }
function renderAudit(){ auditList.innerHTML=""; if(!isRoleAtLeast(ROLES.HELPDESK)){ auditList.innerHTML=`<li><b>Access denied</b><br><span class="muted tiny">Audit logs require Helpdesk or higher.</span></li>`; return; } state.audit.slice(0,60).forEach(a=>{ const li=document.createElement("li"); li.innerHTML=`<b>${escapeHtml(a.msg)}</b><br><span class="muted tiny">${escapeHtml(a.time)}</span>`; auditList.appendChild(li); }); }
function exportJson(){ if(!isRoleAtLeast(ROLES.ICT_ADMIN)) return alert("Access denied."); const blob=new Blob([JSON.stringify(state,null,2)],{type:"application/json"}); const a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download="admin-sim-state.json"; a.click(); audit("EXPORT: Downloaded state"); }
async function importJson(e){ if(!isRoleAtLeast(ROLES.ICT_ADMIN)) return alert("Access denied."); const file=e.target.files?.[0]; if(!file) return; const text=await file.text(); try{ const obj=JSON.parse(text); if(!obj.users||!obj.policies||!obj.audit) throw new Error("Invalid format"); state=obj; saveState(); audit("IMPORT: Loaded state"); renderAll(); alert("Import successful."); }catch{ alert("Invalid JSON file."); } }
function resetEverything(){ if(confirm("Reset simulator data?")){ localStorage.removeItem(STORE); localStorage.removeItem(SESSION_KEY); state=clone(defaultState); saveState(); alert("Reset complete."); showLogin(); } }
