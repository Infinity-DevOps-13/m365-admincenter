// ===== Admin SIM: Security Upgrade + MFA (always 83) =====
// Browser-only. localStorage only. Safe learning.
// MFA number matching is fixed to 83 by request (demo-only, not secure).

const STORE = "adminSim.sec.v1";
const SESSION_KEY = "adminSim.session.v1";

const MFA_NUMBER = "83";          // <-- Always 83 (as you requested)
const MAX_ATTEMPTS = 3;           // lockout after 3 fails
const LOCKOUT_SECONDS = 60;       // 1 minute lockout
const IDLE_TIMEOUT_MS = 5 * 60 * 1000; // 5 min idle auto-logout

const ROLES = {
  STUDENT: "Student",
  TEACHER: "Teacher",
  HELPDESK: "Helpdesk",
  ICT_ADMIN: "ICT Admin",
  GLOBAL_ADMIN: "Global Admin"
};

const demoAccounts = [
  { username: "student.demo", displayName: "Student Demo", role: ROLES.STUDENT },
  { username: "teacher.demo", displayName: "Teacher Demo", role: ROLES.TEACHER },
  { username: "helpdesk.demo", displayName: "Helpdesk Demo", role: ROLES.HELPDESK },
  { username: "ict.demo", displayName: "ICT Admin Demo", role: ROLES.ICT_ADMIN },
  { username: "global.demo", displayName: "Global Admin Demo", role: ROLES.GLOBAL_ADMIN }
];

const defaultState = {
  orgName: "SMK Demo School Tenant",
  policies: {
    mfaRequired: false,
    copilotEnabled: false,
    onedriveQuotaGB: 10
  },
  audit: [],
  // security tracking per username
  security: {
    // e.g. "ict.demo": { attempts: 0, lockedUntil: 0 }
  }
};

let state = loadState();
let current = null; // { username, displayName, role }
let pendingLogin = null; // stores user during MFA step
let idleTimer = null;

// ---------- Login DOM ----------
const loginScreen = document.getElementById("loginScreen");
const appScreen = document.getElementById("appScreen");

const stepEmail = document.getElementById("step-email");
const stepPassword = document.getElementById("step-password");
const stepStay = document.getElementById("step-stay");
const stepMfa = document.getElementById("step-mfa");
const stepError = document.getElementById("step-error");

const loginEmail = document.getElementById("loginEmail");
const loginPassword = document.getElementById("loginPassword");
const showPw = document.getElementById("showPw");
const whoPill = document.getElementById("whoPill");
const tenantPill = document.getElementById("tenantPill");
const lockoutMsg = document.getElementById("lockoutMsg");

const btnNextToPassword = document.getElementById("btnNextToPassword");
const btnBackToEmail = document.getElementById("btnBackToEmail");
const btnSignIn = document.getElementById("btnSignIn");
const btnCreateAccount = document.getElementById("btnCreateAccount");
const btnForgotPw = document.getElementById("btnForgotPw");

const staySignedIn = document.getElementById("staySignedIn");
const btnNoStay = document.getElementById("btnNoStay");
const btnYesStay = document.getElementById("btnYesStay");

const mfaNumber = document.getElementById("mfaNumber");
const mfaInput = document.getElementById("mfaInput");
const btnMfaCancel = document.getElementById("btnMfaCancel");
const btnMfaVerify = document.getElementById("btnMfaVerify");

const errorText = document.getElementById("errorText");
const btnBackToStart = document.getElementById("btnBackToStart");

const btnResetAll = document.getElementById("btnResetAll");

// ---------- App DOM ----------
const orgNameEl = document.getElementById("orgName");
const whoName = document.getElementById("whoName");
const whoRole = document.getElementById("whoRole");
const btnLogout = document.getElementById("btnLogout");

const statUsers = document.getElementById("statUsers");
const statGroups = document.getElementById("statGroups");
const statLic = document.getElementById("statLic");
const statSignins = document.getElementById("statSignins");
const pMfa = document.getElementById("pMfa");
const pCopilot = document.getElementById("pCopilot");
const pQuota = document.getElementById("pQuota");
const roleCaps = document.getElementById("roleCaps");

const polMfa = document.getElementById("polMfa");
const polCopilot = document.getElementById("polCopilot");
const polQuota = document.getElementById("polQuota");
const btnSavePolicies = document.getElementById("btnSavePolicies");

const auditList = document.getElementById("auditList");
const btnClearAudit = document.getElementById("btnClearAudit");

const nav = document.getElementById("nav");

// ---------- Start ----------
wireLogin();
wireApp();
restoreSessionOrShowLogin();

// ================== LOGIN FLOW ==================
function wireLogin(){
  btnResetAll.onclick = resetEverything;

  btnCreateAccount.onclick = ()=> alert("Simulator only: demo accounts are pre-created.");
  btnForgotPw.onclick = ()=> alert("Simulator only: password is demo.");

  btnNextToPassword.onclick = ()=>{
    const id = (loginEmail.value || "").trim().toLowerCase();
    if(!id) return showError("Please enter a demo username (example: ict.demo).");

    const acct = demoAccounts.find(a=>a.username.toLowerCase() === id);
    if(!acct) return showError("Demo account not found. Try ict.demo, helpdesk.demo, global.demo, etc.");

    // Lockout check
    if(isLocked(acct.username)){
      const secs = secondsLeft(acct.username);
      return showLockout(`This account is temporarily locked. Try again in ${secs}s.`);
    } else {
      hideLockout();
    }

    whoPill.textContent = acct.username;
    tenantPill.textContent = `Tenant: ${state.orgName}`;

    gotoStep("password");
    loginPassword.value = "";
    loginPassword.type = "password";
    showPw.checked = false;
  };

  btnBackToEmail.onclick = ()=> gotoStep("email");

  showPw.onchange = ()=> {
    loginPassword.type = showPw.checked ? "text" : "password";
  };

  btnSignIn.onclick = ()=>{
    const id = (whoPill.textContent || "").trim().toLowerCase();
    const acct = demoAccounts.find(a=>a.username.toLowerCase() === id);
    if(!acct) return showError("Account not found. Go back and try again.");

    // Lockout check again
    if(isLocked(acct.username)){
      const secs = secondsLeft(acct.username);
      return showLockout(`This account is temporarily locked. Try again in ${secs}s.`);
    } else {
      hideLockout();
    }

    const pwd = (loginPassword.value || "").trim();
    if(pwd !== "demo"){
      registerFail(acct.username);
      audit(`LOGIN FAIL: ${acct.username} (wrong password)`);

      if(isLocked(acct.username)){
        audit(`LOCKOUT: ${acct.username} locked for ${LOCKOUT_SECONDS}s`);
        const secs = secondsLeft(acct.username);
        return showLockout(`Too many attempts. Account locked for ${secs}s.`);
      }
      return showError("Incorrect password. Hint: demo");
    }

    // Correct password -> proceed
    clearFails(acct.username);
    pendingLogin = acct;
    audit(`PASSWORD OK: ${acct.username}`);

    gotoStep("stay");
  };

  btnNoStay.onclick = ()=> afterStay(false);
  btnYesStay.onclick = ()=> afterStay(true);

  // MFA step
  mfaNumber.textContent = MFA_NUMBER; // always 83
  btnMfaCancel.onclick = ()=>{
    audit(`MFA CANCEL: ${pendingLogin ? pendingLogin.username : "unknown"}`);
    pendingLogin = null;
    gotoStep("email");
  };
  btnMfaVerify.onclick = ()=>{
    const val = (mfaInput.value || "").trim();
    if(val !== MFA_NUMBER){
      audit(`MFA FAIL: ${pendingLogin ? pendingLogin.username : "unknown"} (entered=${val})`);
      return showError("Incorrect number. Enter 83.");
    }
    audit(`MFA OK: ${pendingLogin.username} (number match 83)`);
    finalizeLogin();
  };

  btnBackToStart.onclick = ()=> gotoStep("email");
}

function afterStay(remember){
  // If policy requires MFA, show MFA
  if(state.policies.mfaRequired){
    mfaInput.value = "";
    gotoStep("mfa");
    audit(`MFA REQUIRED: ${pendingLogin.username}`);
    return;
  }
  finalizeLogin(remember);
}

function finalizeLogin(remember = false){
  if(!pendingLogin) return showError("Login session expired. Try again.");

  current = {
    username: pendingLogin.username,
    displayName: pendingLogin.displayName,
    role: pendingLogin.role
  };

  audit(`LOGIN SUCCESS: ${current.username} role=${current.role}`);

  if(remember){
    localStorage.setItem(SESSION_KEY, JSON.stringify({ username: current.username }));
    audit(`SESSION: Remembered login (stay signed in)`);
  } else {
    localStorage.removeItem(SESSION_KEY);
  }

  pendingLogin = null;
  showApp();
}

// ================== APP ==================
function wireApp(){
  // nav
  if(nav){
    nav.querySelectorAll(".nav-btn").forEach(btn=>{
      btn.onclick = ()=>{
        nav.querySelectorAll(".nav-btn").forEach(b=>b.classList.remove("active"));
        btn.classList.add("active");
        const view = btn.dataset.view;
        document.querySelectorAll(".view").forEach(v=>v.classList.remove("active"));
        const target = document.getElementById(`view-${view}`);
        if(target) target.classList.add("active");
      };
    });
  }

  if(btnLogout){
    btnLogout.onclick = ()=>{
      audit(`LOGOUT: ${current ? current.username : "unknown"}`);
      current = null;
      localStorage.removeItem(SESSION_KEY);
      showLogin();
    };
  }

  // policies
  if(btnSavePolicies){
    btnSavePolicies.onclick = ()=>{
      // only ICT Admin / Global Admin
      if(!current || (current.role !== ROLES.ICT_ADMIN && current.role !== ROLES.GLOBAL_ADMIN)){
        return alert("Access denied.");
      }
      state.policies.mfaRequired = !!polMfa.checked;
      state.policies.copilotEnabled = !!polCopilot.checked;
      state.policies.onedriveQuotaGB = Math.max(1, parseInt(polQuota.value || "10", 10));
      saveState();
      audit(`POLICY CHANGE: mfa=${state.policies.mfaRequired} copilot=${state.policies.copilotEnabled} quota=${state.policies.onedriveQuotaGB}GB`);
      renderDashboard();
      alert("Policies saved (simulated).");
    };
  }

  if(btnClearAudit){
    btnClearAudit.onclick = ()=>{
      if(!current || (current.role !== ROLES.ICT_ADMIN && current.role !== ROLES.GLOBAL_ADMIN)){
        return alert("Access denied.");
      }
      if(confirm("Clear audit logs?")){
        state.audit = [];
        saveState();
        renderAudit();
      }
    };
  }

  // Idle timeout tracking
  ["click","mousemove","keydown","touchstart"].forEach(evt=>{
    document.addEventListener(evt, resetIdleTimer, { passive: true });
  });
}

// ================== RENDER ==================
function showLogin(){
  loginScreen.classList.remove("hidden");
  appScreen.classList.add("hidden");
  loginEmail.value = "";
  loginPassword.value = "";
  mfaInput.value = "";
  hideLockout();
  gotoStep("email");
  stopIdleTimer();
}

function showApp(){
  loginScreen.classList.add("hidden");
  appScreen.classList.remove("hidden");

  orgNameEl.textContent = state.orgName;
  whoName.textContent = current.displayName;
  whoRole.textContent = current.role;

  renderDashboard();
  renderPoliciesUI();
  renderAudit();

  startIdleTimer();
}

function renderDashboard(){
  // dummy stats (you can wire real ones later)
  if(statUsers) statUsers.textContent = "—";
  if(statGroups) statGroups.textContent = "—";
  if(statLic) statLic.textContent = "—";
  if(statSignins) statSignins.textContent = "—";

  pMfa.textContent = state.policies.mfaRequired ? "Yes" : "No";
  pCopilot.textContent = state.policies.copilotEnabled ? "Yes" : "No";
  pQuota.textContent = `${state.policies.onedriveQuotaGB} GB`;

  if(roleCaps){
    const caps = roleCapabilities(current?.role);
    roleCaps.innerHTML = caps.map(x=>`<li>${escapeHtml(x)}</li>`).join("");
  }
}

function renderPoliciesUI(){
  if(!polMfa) return;
  polMfa.checked = !!state.policies.mfaRequired;
  polCopilot.checked = !!state.policies.copilotEnabled;
  polQuota.value = state.policies.onedriveQuotaGB ?? 10;

  const editable = current && (current.role === ROLES.ICT_ADMIN || current.role === ROLES.GLOBAL_ADMIN);
  polMfa.disabled = !editable;
  polCopilot.disabled = !editable;
  polQuota.disabled = !editable;
  btnSavePolicies.style.display = editable ? "" : "none";
}

function renderAudit(){
  if(!auditList) return;
  auditList.innerHTML = "";
  // show audit only to Helpdesk+
  const canSee = current && (current.role === ROLES.HELPDESK || current.role === ROLES.ICT_ADMIN || current.role === ROLES.GLOBAL_ADMIN);
  if(!canSee){
    auditList.innerHTML = `<li><b>Access denied</b><br><span class="muted tiny">Audit logs require Helpdesk or higher.</span></li>`;
    return;
  }

  state.audit.slice(0,60).forEach(a=>{
    const li = document.createElement("li");
    li.innerHTML = `<b>${escapeHtml(a.msg)}</b><br><span class="muted tiny">${escapeHtml(a.time)}</span>`;
    auditList.appendChild(li);
  });
}

// ================== SECURITY: LOCKOUT ==================
function ensureSec(username){
  if(!state.security[username]){
    state.security[username] = { attempts: 0, lockedUntil: 0 };
  }
  return state.security[username];
}
function registerFail(username){
  const s = ensureSec(username);
  s.attempts += 1;
  if(s.attempts >= MAX_ATTEMPTS){
    s.lockedUntil = Date.now() + LOCKOUT_SECONDS * 1000;
    s.attempts = 0; // reset attempts after lock
  }
  saveState();
}
function clearFails(username){
  const s = ensureSec(username);
  s.attempts = 0;
  s.lockedUntil = 0;
  saveState();
}
function isLocked(username){
  const s = ensureSec(username);
  return Date.now() < s.lockedUntil;
}
function secondsLeft(username){
  const s = ensureSec(username);
  return Math.max(0, Math.ceil((s.lockedUntil - Date.now()) / 1000));
}
function showLockout(text){
  lockoutMsg.style.display = "block";
  lockoutMsg.textContent = text;
}
function hideLockout(){
  lockoutMsg.style.display = "none";
  lockoutMsg.textContent = "";
}

// ================== SESSION + IDLE TIMEOUT ==================
function restoreSessionOrShowLogin(){
  const raw = localStorage.getItem(SESSION_KEY);
  if(!raw){ return showLogin(); }

  try{
    const sess = JSON.parse(raw);
    const acct = demoAccounts.find(a=>a.username === sess.username);
    if(!acct) return showLogin();

    current = { username: acct.username, displayName: acct.displayName, role: acct.role };
    audit(`SESSION RESTORE: ${current.username}`);
    showApp();
  }catch{
    showLogin();
  }
}

function startIdleTimer(){
  stopIdleTimer();
  idleTimer = setTimeout(()=>{
    if(current){
      audit(`AUTO LOGOUT: idle timeout (${IDLE_TIMEOUT_MS/60000} min) user=${current.username}`);
      current = null;
      localStorage.removeItem(SESSION_KEY);
      showLogin();
      alert("Logged out due to inactivity (simulated).");
    }
  }, IDLE_TIMEOUT_MS);
}
function resetIdleTimer(){
  if(!current) return;
  startIdleTimer();
}
function stopIdleTimer(){
  if(idleTimer) clearTimeout(idleTimer);
  idleTimer = null;
}

// ================== AUDIT ==================
function audit(message){
  const time = new Date().toLocaleString();
  state.audit.unshift({ time, msg: message });
  if(state.audit.length > 300) state.audit.pop();
  saveState();
}

// ================== STORAGE ==================
function saveState(){
  localStorage.setItem(STORE, JSON.stringify(state));
}
function loadState(){
  const raw = localStorage.getItem(STORE);
  if(!raw) return JSON.parse(JSON.stringify(defaultState));
  try { return JSON.parse(raw); } catch { return JSON.parse(JSON.stringify(defaultState)); }
}

function resetEverything(){
  if(confirm("Reset simulator data?")){
    localStorage.removeItem(STORE);
    localStorage.removeItem(SESSION_KEY);
    state = JSON.parse(JSON.stringify(defaultState));
    saveState();
    alert("Reset complete.");
    showLogin();
  }
}

// ================== UI STEP SWITCH ==================
function gotoStep(name){
  [stepEmail, stepPassword, stepStay, stepMfa, stepError].forEach(x=>x.classList.add("hidden"));
  if(name === "email") stepEmail.classList.remove("hidden");
  if(name === "password") stepPassword.classList.remove("hidden");
  if(name === "stay") stepStay.classList.remove("hidden");
  if(name === "mfa") stepMfa.classList.remove("hidden");
  if(name === "error") stepError.classList.remove("hidden");
}

function showError(msg){
  errorText.textContent = msg;
  gotoStep("error");
}

// ================== ROLE CAPABILITIES ==================
function roleCapabilities(role){
  if(role === ROLES.STUDENT) return ["View own profile (simulated)"];
  if(role === ROLES.TEACHER) return ["View users (read-only)", "View sign-in logs (if enabled)"];
  if(role === ROLES.HELPDESK) return ["Reset passwords (simulated)", "Disable/enable users", "View audit logs"];
  if(role === ROLES.ICT_ADMIN) return ["Manage users/groups/licenses", "Edit tenant policies", "View audit logs"];
  if(role === ROLES.GLOBAL_ADMIN) return ["All permissions (simulated)", "Full tenant control"];
  return ["Unknown role"];
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
