import { useState, useEffect, useRef, useCallback } from "react";

/* ─── GLOBAL CSS ─── */
const GLOBAL_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --cyan: #00f5ff; --cyan-dim: #00f5ff33; --red: #ff2d55; --gold: #ffd60a;
    --green: #30d158; --purple: #bf5af2; --orange: #ff9f0a;
    --bg: #060a12; --bg2: #0a1020;
    --font-display: 'Orbitron', monospace;
    --font-mono: 'Share Tech Mono', monospace;
    --font-body: 'Rajdhani', sans-serif;
  }
  html, body { background: var(--bg); color: #fff; font-family: var(--font-body); overflow-x: hidden; }
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-thumb { background: var(--cyan-dim); border-radius: 2px; }
  @keyframes scan { 0%{transform:translateY(-100%)} 100%{transform:translateY(100vh)} }
  @keyframes pulse-ring { 0%{transform:scale(1);opacity:0.8} 100%{transform:scale(2.5);opacity:0} }
  @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-8px)} }
  @keyframes spin-slow { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
  @keyframes spin-rev { from{transform:rotate(360deg)} to{transform:rotate(0deg)} }
  @keyframes fadeInUp { from{opacity:0;transform:translateY(20px)} to{opacity:1;transform:translateY(0)} }
  @keyframes slideIn { from{opacity:0;transform:translateX(-12px)} to{opacity:1;transform:translateX(0)} }
  @keyframes threat-in { from{transform:translateX(110%);opacity:0} to{transform:translateX(0);opacity:1} }
  @keyframes flicker { 0%,100%{opacity:1} 92%{opacity:1} 93%{opacity:0.3} 94%{opacity:1} }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
  @keyframes holo { 0%,100%{background-position:0% 50%} 50%{background-position:100% 50%} }
  @keyframes glitch1 { 0%,85%,100%{opacity:0} 86%,99%{opacity:1;transform:translateX(-3px);color:#ff2d55} }
  @keyframes glitch2 { 0%,88%,100%{opacity:0} 89%,98%{opacity:1;transform:translateX(3px);color:#00f5ff} }
  @keyframes redPulse { 0%,100%{box-shadow:0 0 0 0 rgba(255,45,85,0)} 50%{box-shadow:0 0 30px 10px rgba(255,45,85,0.25)} }
  @keyframes matrix { 0%{transform:translateY(-100%);opacity:1} 100%{transform:translateY(100vh);opacity:0.2} }
  @keyframes shake { 0%,100%{transform:translateX(0)} 20%{transform:translateX(-6px)} 40%{transform:translateX(6px)} 60%{transform:translateX(-4px)} 80%{transform:translateX(4px)} }
  @keyframes vignette-pulse { 0%,100%{opacity:0} 50%{opacity:1} }
`;

/* ─── RISK WEIGHTS ─── */
const RISK_WEIGHTS = {
  PHISHING_LINK_CLICK: 25,
  SUSPICIOUS_DOWNLOAD: 30,
  FAKE_LOGIN_ATTEMPT: 35,
  SOCIAL_ENGINEERING: 28,
  MALICIOUS_ATTACHMENT: 40,
  DATA_EXFILTRATION: 45,
  UNAUTHORIZED_ACCESS: 50,
};

const MODES = { PROTECTED: "PROTECTED", ELEVATED: "ELEVATED", QUARANTINE: "QUARANTINE" };
const getMode = s => s > 78 ? MODES.QUARANTINE : s > 42 ? MODES.ELEVATED : MODES.PROTECTED;

/* ─── SECURITY ENGINE ─── */
class SecurityEngine {
  constructor() {
    this.sessionId = (crypto.randomUUID?.() || Math.random().toString(36).slice(2));
    this.startTime = Date.now();
    this.canaryTokens = new Map();
    this.decoyFiles = [];
    this.honeypotTraps = [];
    this.intruderProfile = {};
    this.forensicLog = [];
    this.lockedDown = false;
    this.blockedEmails = [];
    this.blockedDomains = [];
    this._initCanaryTokens();
    this._initHoneypots();
    this._initHeadlessDetection();
  }
  _initCanaryTokens() {
    const tokens = ["PASSWD_DUMP_v2.csv","PrivateKey_RSA4096.pem","BankCredsExport.xlsx","AdminSecrets.env","UserDB_Full_2024.sql"];
    tokens.forEach(name => {
      const id = Math.random().toString(36).slice(2,10).toUpperCase();
      this.canaryTokens.set(id, { name, accessed: false, accessTime: null });
    });
    this.decoyFiles = Array.from(this.canaryTokens.entries()).map(([id, f]) => ({ id, ...f }));
  }
  _initHoneypots() {
    this.honeypotTraps = [
      { selector: "honeypot-btn", label: "Export All User Data", triggered: false },
      { selector: "honeypot-link", label: "Admin Override Panel", triggered: false },
      { selector: "honeypot-field", label: "Debug API Key Field", triggered: false },
    ];
  }
  _initHeadlessDetection() {
    const hints = [];
    if (!navigator.plugins?.length) hints.push("NO_PLUGINS");
    if (navigator.webdriver) hints.push("WEBDRIVER");
    if (!window.chrome && navigator.userAgent.includes("Chrome")) hints.push("FAKE_CHROME");
    if (window.callPhantom || window._phantom) hints.push("PHANTOM");
    this.intruderProfile.headlessHints = hints;
    return hints.length > 0;
  }
  checkEmail(email) {
    const lower = email.toLowerCase().trim();
    const domain = lower.split("@")[1] || "";
    if (this.blockedEmails.includes(lower)) return { blocked: true, reason: "ADDRESS_BLOCKED" };
    if (this.blockedDomains.includes(domain)) return { blocked: true, reason: "DOMAIN_BLOCKED" };
    return { blocked: false };
  }
  blockEmail(email) {
    const lower = email.toLowerCase().trim();
    if (!this.blockedEmails.includes(lower)) {
      this.blockedEmails.push(lower);
      this.forensicLog.push({ event: "EMAIL_BLOCKED", target: lower, time: new Date().toISOString() });
    }
  }
  unblockEmail(email) {
    this.blockedEmails = this.blockedEmails.filter(e => e !== email);
  }
  blockDomain(domain) {
    const d = domain.toLowerCase().replace(/^@/, "");
    if (!this.blockedDomains.includes(d)) {
      this.blockedDomains.push(d);
      this.forensicLog.push({ event: "DOMAIN_BLOCKED", target: d, time: new Date().toISOString() });
    }
  }
  unblockDomain(domain) {
    this.blockedDomains = this.blockedDomains.filter(d => d !== domain);
  }
  triggerCanary(tokenId) {
    const token = this.canaryTokens.get(tokenId);
    if (!token) return null;
    token.accessed = true;
    token.accessTime = new Date().toISOString();
    this.forensicLog.push({ event: "CANARY_TRIGGERED", token: token.name, time: token.accessTime });
    return token;
  }
  triggerHoneypot(selector) {
    const trap = this.honeypotTraps.find(h => h.selector === selector);
    if (!trap) return null;
    trap.triggered = true;
    trap.triggerTime = new Date().toISOString();
    this.forensicLog.push({ event: "HONEYPOT_TRIGGERED", trap: trap.label, time: trap.triggerTime });
    return trap;
  }
  lockSession() {
    this.lockedDown = true;
    this.forensicLog.push({ event: "SESSION_LOCKED", time: new Date().toISOString(), sessionId: this.sessionId });
  }
  buildForensicReport() {
    return {
      sessionId: this.sessionId,
      duration: Math.round((Date.now() - this.startTime) / 1000),
      intruderProfile: this.intruderProfile,
      canaryTriggered: Array.from(this.canaryTokens.values()).filter(t => t.accessed),
      honeypotTriggered: this.honeypotTraps.filter(h => h.triggered),
      forensicLog: this.forensicLog,
      threatLevel: this.forensicLog.length > 3 ? "CRITICAL" : this.forensicLog.length > 1 ? "HIGH" : "MEDIUM",
    };
  }
  addIntruderData(key, val) { this.intruderProfile[key] = val; }
}

const engine = new SecurityEngine();

/* ─── PARTICLE CANVAS ─── */
function ParticleCanvas({ mode }) {
  const ref = useRef(null);
  const col = mode === MODES.QUARANTINE ? "255,45,85" : mode === MODES.ELEVATED ? "255,214,10" : "0,245,255";
  useEffect(() => {
    const c = ref.current; if (!c) return;
    const ctx = c.getContext("2d");
    let W = c.width = window.innerWidth, H = c.height = window.innerHeight;
    const onR = () => { W = c.width = window.innerWidth; H = c.height = window.innerHeight; };
    window.addEventListener("resize", onR);
    const pts = Array.from({ length: 60 }, () => ({ x: Math.random() * W, y: Math.random() * H, vx: (Math.random() - .5) * .45, vy: (Math.random() - .5) * .45, r: Math.random() * 1.5 + .5 }));
    let raf;
    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      pts.forEach(p => {
        p.x += p.vx; p.y += p.vy;
        if (p.x < 0) p.x = W; if (p.x > W) p.x = 0; if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
        ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${col},.5)`; ctx.fill();
      });
      for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) {
        const dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y, d = Math.sqrt(dx * dx + dy * dy);
        if (d < 120) {
          ctx.beginPath(); ctx.moveTo(pts[i].x, pts[i].y); ctx.lineTo(pts[j].x, pts[j].y);
          ctx.strokeStyle = `rgba(${col},${.12 * (1 - d / 120)})`; ctx.lineWidth = .5; ctx.stroke();
        }
      }
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => { cancelAnimationFrame(raf); window.removeEventListener("resize", onR); };
  }, [col]);
  return <canvas ref={ref} style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none" }} />;
}

/* ─── MATRIX RAIN ─── */
function MatrixRain() {
  const ref = useRef(null);
  useEffect(() => {
    const c = ref.current; if (!c) return;
    const ctx = c.getContext("2d");
    let W = c.width = window.innerWidth, H = c.height = window.innerHeight;
    const cols = Math.floor(W / 16);
    const drops = Array(cols).fill(1);
    const chars = "01アイウエオカキクケコ▲◆◈⬡■ABCDEF0123456789";
    let raf;
    const draw = () => {
      ctx.fillStyle = "rgba(6,10,18,0.05)"; ctx.fillRect(0, 0, W, H);
      ctx.fillStyle = "rgba(255,45,85,0.55)"; ctx.font = "13px 'Share Tech Mono'";
      drops.forEach((y, x) => {
        const ch = chars[Math.floor(Math.random() * chars.length)];
        ctx.fillText(ch, x * 16, y * 16);
        if (y * 16 > H && Math.random() > 0.975) drops[x] = 0;
        drops[x]++;
      });
      raf = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(raf);
  }, []);
  return <canvas ref={ref} style={{ position: "fixed", inset: 0, zIndex: 1, pointerEvents: "none", opacity: 0.35 }} />;
}

/* ─── GRID ─── */
function Grid() {
  return <div style={{ position: "fixed", inset: 0, zIndex: 0, pointerEvents: "none", backgroundImage: "linear-gradient(rgba(0,245,255,0.035) 1px,transparent 1px),linear-gradient(90deg,rgba(0,245,255,0.035) 1px,transparent 1px)", backgroundSize: "60px 60px" }} />;
}

/* ─── SCANLINE ─── */
function ScanLine() {
  return <div style={{ position: "fixed", inset: 0, zIndex: 1, pointerEvents: "none", overflow: "hidden" }}>
    <div style={{ position: "absolute", left: 0, right: 0, height: 2, background: "linear-gradient(90deg,transparent,#00f5ff22,transparent)", animation: "scan 7s linear infinite" }} />
    <div style={{ position: "absolute", inset: 0, background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.025) 2px,rgba(0,0,0,0.025) 4px)" }} />
  </div>;
}

/* ─── GLITCH TEXT ─── */
function GlitchText({ text, style = {} }) {
  return <div style={{ position: "relative", display: "inline-block", ...style }}>
    <span style={{ position: "relative", zIndex: 2 }}>{text}</span>
    <span aria-hidden style={{ position: "absolute", top: 0, left: 0, zIndex: 1, animation: "glitch1 5s infinite" }}>{text}</span>
    <span aria-hidden style={{ position: "absolute", top: 0, left: 0, zIndex: 1, animation: "glitch2 5s infinite .15s" }}>{text}</span>
  </div>;
}

/* ─── RING GAUGE ─── */
function Ring({ value, max = 100, color, size = 120, label }) {
  const r = 44, circ = 2 * Math.PI * r, fill = (value / max) * circ;
  return <div style={{ position: "relative", width: size, height: size, flexShrink: 0 }}>
    <svg viewBox="0 0 100 100" style={{ width: "100%", height: "100%", transform: "rotate(-90deg)" }}>
      <circle cx="50" cy="50" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="6" />
      <circle cx="50" cy="50" r={r} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round"
        strokeDasharray={`${fill} ${circ}`}
        style={{ transition: "stroke-dasharray 1s cubic-bezier(.4,0,.2,1),stroke .5s", filter: `drop-shadow(0 0 6px ${color})` }} />
    </svg>
    <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", textAlign: "center" }}>
      <div style={{ fontFamily: "var(--font-display)", fontSize: size * .22, fontWeight: 700, color, lineHeight: 1 }}>{Math.round(value)}</div>
      {label && <div style={{ fontFamily: "var(--font-mono)", fontSize: size * .09, color: "rgba(255,255,255,0.35)", marginTop: 2 }}>{label}</div>}
    </div>
  </div>;
}

/* ─── STATUS BADGE ─── */
function StatusBadge({ mode }) {
  const cfg = {
    [MODES.PROTECTED]: { color: "#30d158", label: "PROTECTED" },
    [MODES.ELEVATED]: { color: "#ffd60a", label: "ELEVATED" },
    [MODES.QUARANTINE]: { color: "#ff2d55", label: "QUARANTINE" },
  }[mode];
  return <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
    <div style={{ position: "relative", width: 10, height: 10 }}>
      <div style={{ width: 10, height: 10, borderRadius: "50%", background: cfg.color, boxShadow: `0 0 8px ${cfg.color}` }} />
      <div style={{ position: "absolute", inset: 0, borderRadius: "50%", border: `1px solid ${cfg.color}`, animation: "pulse-ring 1.4s ease-out infinite" }} />
    </div>
    <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: cfg.color, letterSpacing: "0.25em" }}>{cfg.label}</span>
  </div>;
}

/* ─── CARD ─── */
function Card({ children, style = {}, accent = "var(--cyan)", glow = false }) {
  return <div style={{
    background: "rgba(6,10,18,0.72)", border: `1px solid ${accent}22`,
    borderRadius: 16, backdropFilter: "blur(20px)", WebkitBackdropFilter: "blur(20px)",
    boxShadow: glow ? `0 0 40px ${accent}14,inset 0 1px 0 ${accent}11` : "inset 0 1px 0 rgba(255,255,255,0.04)",
    position: "relative", overflow: "hidden", ...style
  }}>
    <div style={{ position: "absolute", top: 0, left: "20%", right: "20%", height: 1, background: `linear-gradient(90deg,transparent,${accent}55,transparent)` }} />
    {children}
  </div>;
}

/* ─── DNA BARS ─── */
function DNABars({ timings }) {
  if (!timings.length) return <div style={{ textAlign: "center", padding: "28px 0", fontFamily: "var(--font-mono)", fontSize: 11, color: "rgba(255,255,255,0.12)", letterSpacing: "0.2em" }}>AWAITING BEHAVIORAL INPUT...</div>;
  const max = Math.max(...timings, 1);
  return <div style={{ display: "flex", gap: 4, height: 64, alignItems: "flex-end" }}>
    {timings.map((t, i) => {
      const anomaly = t < 50 || t > 600;
      const color = anomaly ? "var(--red)" : t < 100 ? "var(--gold)" : "var(--cyan)";
      return <div key={i} style={{ flex: 1, background: color, borderRadius: "3px 3px 0 0", height: `${Math.max((t / max) * 100, 6)}%`, transition: "height .4s cubic-bezier(.4,0,.2,1),background .3s", boxShadow: `0 0 8px ${color}55`, opacity: .7 + (i / timings.length) * .3 }} />;
    })}
  </div>;
}

/* ─── LOG FEED ─── */
function LogFeed({ logs }) {
  const typeColor = { threat: "var(--red)", warn: "var(--gold)", info: "var(--cyan)", forensic: "var(--purple)" };
  const typeIcon = { threat: "▲", warn: "◆", info: "●", forensic: "⬡" };
  return <div style={{ height: 220, overflowY: "auto", display: "flex", flexDirection: "column", gap: 2 }}>
    {logs.map((log, i) => (
      <div key={i} style={{ display: "flex", gap: 10, alignItems: "flex-start", padding: "6px 10px", borderRadius: 6, background: i === 0 ? `${typeColor[log.type]}08` : "transparent", borderLeft: i === 0 ? `2px solid ${typeColor[log.type]}` : "2px solid transparent", animation: i === 0 ? "slideIn .3s ease-out" : "none" }}>
        <span style={{ color: typeColor[log.type], fontSize: 9, marginTop: 1, flexShrink: 0 }}>{typeIcon[log.type]}</span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.25)", flexShrink: 0 }}>{log.time}</span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: i === 0 ? typeColor[log.type] : "rgba(255,255,255,0.3)", letterSpacing: "0.04em" }}>{log.msg}</span>
      </div>
    ))}
  </div>;
}

/* ─── THREAT POPUP ─── */
function ThreatPopup({ threat, onDismiss }) {
  if (!threat) return null;
  return <div style={{ position: "fixed", top: 80, right: 24, zIndex: 50, animation: "threat-in .4s cubic-bezier(.4,0,.2,1)" }}>
    <Card accent="var(--red)" glow style={{ padding: "16px 20px", maxWidth: 340 }}>
      <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
        <div>
          <div style={{ fontFamily: "var(--font-display)", fontSize: 10, color: "var(--red)", letterSpacing: "0.2em", marginBottom: 6 }}>⚠ THREAT INTERCEPTED</div>
          <div style={{ fontFamily: "var(--font-body)", fontSize: 13, color: "rgba(255,255,255,0.85)", lineHeight: 1.5 }}>{threat.replace(/_/g, " ")}</div>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,45,85,0.5)", marginTop: 6 }}>SESSION: {engine.sessionId.slice(0, 12).toUpperCase()}</div>
        </div>
        <button onClick={onDismiss} style={{ background: "none", border: "none", color: "rgba(255,255,255,0.3)", cursor: "pointer", fontSize: 18, flexShrink: 0 }}>×</button>
      </div>
    </Card>
  </div>;
}

/* ─── FORENSIC REPORT ─── */
function ForensicReport({ report }) {
  if (!report) return null;
  return <Card accent="var(--purple)" glow style={{ padding: "22px 24px", marginBottom: 16 }}>
    <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(191,90,242,0.6)", letterSpacing: "0.25em", marginBottom: 16 }}>⬡ FORENSIC INTELLIGENCE REPORT</div>
    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 14 }}>
      {[["Session ID", report.sessionId?.slice(0, 16).toUpperCase()], ["Duration", `${report.duration}s`], ["Threat Level", report.threatLevel], ["Canaries Hit", report.canaryTriggered?.length || 0], ["Honeypots Triggered", report.honeypotTriggered?.length || 0], ["Forensic Events", report.forensicLog?.length || 0]].map(([k, v]) => (
        <div key={k} style={{ padding: "8px 12px", background: "rgba(191,90,242,0.06)", borderRadius: 8, border: "0.5px solid rgba(191,90,242,0.12)" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(191,90,242,0.45)", marginBottom: 3 }}>{k}</div>
          <div style={{ fontFamily: "var(--font-display)", fontSize: 12, color: "var(--purple)", fontWeight: 700 }}>{v}</div>
        </div>
      ))}
    </div>
    {report.canaryTriggered?.length > 0 && (
      <div style={{ marginBottom: 10 }}>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,45,85,0.45)", marginBottom: 6, letterSpacing: "0.2em" }}>CANARY TOKENS ACCESSED:</div>
        {report.canaryTriggered.map((t, i) => (
          <div key={i} style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--red)", padding: "4px 8px", marginBottom: 3, background: "rgba(255,45,85,0.06)", borderRadius: 4 }}>
            ▲ {t.name} — {t.accessTime?.slice(11, 19)}
          </div>
        ))}
      </div>
    )}
    <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.12)", borderTop: "0.5px solid rgba(255,255,255,0.05)", paddingTop: 10, letterSpacing: "0.1em" }}>
      TTP FINGERPRINT PRESERVED · ADMISSIBLE IN DIGITAL FORENSICS
    </div>
  </Card>;
}

/* ─── EMAIL BLOCK TAB ─── */
function EmailBlockTab({ addLog, handleRisk }) {
  const [emailInput, setEmailInput] = useState("");
  const [blockedEmails, setBlockedEmails] = useState([...engine.blockedEmails]);
  const [blockedDomains, setBlockedDomains] = useState([...engine.blockedDomains]);
  const [testEmail, setTestEmail] = useState("");
  const [testResult, setTestResult] = useState(null);
  const [blockLog, setBlockLog] = useState([]);

  const addBlock = () => {
    const v = emailInput.trim().toLowerCase();
    if (!v) return;
    if (v.startsWith("@")) {
      const domain = v.slice(1);
      if (domain && !engine.blockedDomains.includes(domain)) {
        engine.blockDomain(domain);
        setBlockedDomains([...engine.blockedDomains]);
        addLog(`DOMAIN_BLOCKED · @${domain}`, "warn");
        setBlockLog(p => [{ time: new Date().toLocaleTimeString(), msg: `Domain @${domain} blocked`, type: "warn" }, ...p]);
      }
    } else if (v.includes("@")) {
      if (!engine.blockedEmails.includes(v)) {
        engine.blockEmail(v);
        setBlockedEmails([...engine.blockedEmails]);
        addLog(`EMAIL_BLOCKED · ${v}`, "warn");
        setBlockLog(p => [{ time: new Date().toLocaleTimeString(), msg: `Email ${v} blocked`, type: "warn" }, ...p]);
      }
    }
    setEmailInput("");
  };

  const removeEmail = (e) => {
    engine.unblockEmail(e);
    setBlockedEmails([...engine.blockedEmails]);
    addLog(`EMAIL_UNBLOCKED · ${e}`, "info");
  };

  const removeDomain = (d) => {
    engine.unblockDomain(d);
    setBlockedDomains([...engine.blockedDomains]);
    addLog(`DOMAIN_UNBLOCKED · @${d}`, "info");
  };

  const checkTestEmail = () => {
    if (!testEmail.trim() || !testEmail.includes("@")) return;
    const result = engine.checkEmail(testEmail.trim());
    setTestResult({ email: testEmail.trim(), ...result });
    if (result.blocked) {
      addLog(`EMAIL_ACCESS_DENIED · ${testEmail.trim()}`, "threat");
      handleRisk(0, "UNAUTHORIZED_ACCESS", `EMAIL_BLOCK_TRIGGERED · ${testEmail.trim()}`);
      setBlockLog(p => [{ time: new Date().toLocaleTimeString(), msg: `BLOCKED: ${testEmail.trim()} — ${result.reason}`, type: "threat" }, ...p]);
    } else {
      addLog(`EMAIL_ACCESS_ALLOWED · ${testEmail.trim()}`, "info");
      setBlockLog(p => [{ time: new Date().toLocaleTimeString(), msg: `ALLOWED: ${testEmail.trim()}`, type: "info" }, ...p]);
    }
  };

  const tagStyle = (color) => ({
    display: "inline-flex", alignItems: "center", gap: 6, padding: "5px 12px",
    borderRadius: 20, fontSize: 11, margin: 3, fontFamily: "var(--font-mono)",
    background: `${color}11`, border: `1px solid ${color}44`, color,
  });

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 20, animation: "fadeInUp .4s ease-out" }}>
      <Card accent="var(--red)" glow style={{ padding: "28px" }}>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,45,85,0.5)", letterSpacing: "0.3em", marginBottom: 16 }}>EMAIL BLOCK ENGINE</div>
        <div style={{ fontFamily: "var(--font-body)", fontSize: 13, color: "rgba(255,255,255,0.45)", marginBottom: 20, lineHeight: 1.6 }}>
          Block specific email addresses or entire domains. Use <span style={{ color: "var(--gold)" }}>@domain.com</span> to block an entire domain. Blocked addresses trigger a THREAT alert and are logged forensically.
        </div>

        <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
          <input
            type="text"
            value={emailInput}
            onChange={e => setEmailInput(e.target.value)}
            onKeyDown={e => e.key === "Enter" && addBlock()}
            placeholder="user@example.com or @domain.com"
            style={{ flex: 1, background: "transparent", border: "none", borderBottom: "1px solid rgba(255,45,85,0.4)", color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 12, padding: "10px 0", outline: "none", caretColor: "var(--red)" }}
          />
          <button onClick={addBlock} style={{ padding: "8px 16px", background: "rgba(255,45,85,0.1)", border: "1px solid rgba(255,45,85,0.4)", color: "var(--red)", fontFamily: "var(--font-mono)", fontSize: 10, cursor: "pointer", borderRadius: 8, letterSpacing: "0.1em" }}>
            BLOCK
          </button>
        </div>

        <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,45,85,0.4)", letterSpacing: "0.2em", marginBottom: 10 }}>BLOCKED ADDRESSES</div>
        <div style={{ minHeight: 36, marginBottom: 16, flexWrap: "wrap", display: "flex" }}>
          {blockedEmails.length === 0
            ? <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.15)" }}>No addresses blocked</span>
            : blockedEmails.map(e => (
              <span key={e} style={tagStyle("var(--red)")}>
                {e}
                <button onClick={() => removeEmail(e)} style={{ background: "none", border: "none", color: "rgba(255,45,85,0.5)", cursor: "pointer", fontSize: 14, padding: 0, lineHeight: 1 }}>×</button>
              </span>
            ))}
        </div>

        <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,45,85,0.4)", letterSpacing: "0.2em", marginBottom: 10 }}>BLOCKED DOMAINS</div>
        <div style={{ minHeight: 36, flexWrap: "wrap", display: "flex" }}>
          {blockedDomains.length === 0
            ? <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.15)" }}>No domains blocked</span>
            : blockedDomains.map(d => (
              <span key={d} style={tagStyle("var(--orange)")}>
                @{d}
                <button onClick={() => removeDomain(d)} style={{ background: "none", border: "none", color: "rgba(255,159,10,0.5)", cursor: "pointer", fontSize: 14, padding: 0, lineHeight: 1 }}>×</button>
              </span>
            ))}
        </div>

        <div style={{ borderTop: "0.5px solid rgba(255,255,255,0.06)", marginTop: 20, paddingTop: 20 }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,45,85,0.4)", letterSpacing: "0.2em", marginBottom: 10 }}>TEST EMAIL ACCESS</div>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <input
              type="text"
              value={testEmail}
              onChange={e => setTestEmail(e.target.value)}
              onKeyDown={e => e.key === "Enter" && checkTestEmail()}
              placeholder="test@example.com"
              style={{ flex: 1, background: "transparent", border: "none", borderBottom: "1px solid rgba(255,255,255,0.15)", color: "#fff", fontFamily: "var(--font-mono)", fontSize: 12, padding: "8px 0", outline: "none" }}
            />
            <button onClick={checkTestEmail} style={{ padding: "6px 14px", background: "rgba(0,245,255,0.08)", border: "1px solid rgba(0,245,255,0.3)", color: "var(--cyan)", fontFamily: "var(--font-mono)", fontSize: 10, cursor: "pointer", borderRadius: 8 }}>
              CHECK
            </button>
          </div>
          {testResult && (
            <div style={{ padding: "10px 14px", borderRadius: 8, background: testResult.blocked ? "rgba(255,45,85,0.1)" : "rgba(48,209,88,0.08)", border: `1px solid ${testResult.blocked ? "rgba(255,45,85,0.3)" : "rgba(48,209,88,0.3)"}`, fontFamily: "var(--font-mono)", fontSize: 11 }}>
              <span style={{ color: testResult.blocked ? "var(--red)" : "var(--green)" }}>
                {testResult.blocked ? `⛔ BLOCKED — ${testResult.reason.replace(/_/g, " ")}` : "✓ ALLOWED — not on blocklist"}
              </span>
              <div style={{ fontSize: 9, color: "rgba(255,255,255,0.25)", marginTop: 4 }}>{testResult.email}</div>
            </div>
          )}
        </div>
      </Card>

      <Card accent="var(--red)" style={{ padding: "28px" }}>
        <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,45,85,0.5)", letterSpacing: "0.3em", marginBottom: 16 }}>EMAIL BLOCK LOG</div>
        <div style={{ height: 260, overflowY: "auto", display: "flex", flexDirection: "column", gap: 3 }}>
          {blockLog.length === 0
            ? <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.12)", textAlign: "center", padding: "40px 0" }}>No email block events yet</div>
            : blockLog.map((l, i) => {
              const col = l.type === "threat" ? "var(--red)" : l.type === "warn" ? "var(--gold)" : "var(--cyan)";
              return <div key={i} style={{ display: "flex", gap: 8, padding: "6px 10px", borderRadius: 6, borderLeft: `2px solid ${col}`, background: `${col}08` }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.25)", flexShrink: 0 }}>{l.time}</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: col }}>{l.msg}</span>
              </div>;
            })}
        </div>
        <div style={{ borderTop: "0.5px solid rgba(255,255,255,0.06)", marginTop: 16, paddingTop: 16 }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.2)", lineHeight: 2 }}>
            HOW IT WORKS<br />
            1. Add email or @domain to blocklist<br />
            2. System intercepts login attempts<br />
            3. Blocked attempt → THREAT alert<br />
            4. Event logged with timestamp + session ID<br />
            5. Forensic evidence chain preserved<br />
            6. Optional: auto-quarantine session
          </div>
        </div>
      </Card>
    </div>
  );
}

/* ─── PHONE HANDOFF TAB ─── */
const HANDOFF_CATEGORIES = [
  { id: "messages", label: "Messages & SMS", icon: "💬", risk: "low" },
  { id: "contacts", label: "Contacts", icon: "👤", risk: "medium" },
  { id: "camera", label: "Camera / Photos", icon: "📷", risk: "low" },
  { id: "browser", label: "Web Browser", icon: "🌐", risk: "medium" },
  { id: "email", label: "Email / Inbox", icon: "📧", risk: "high" },
  { id: "payments", label: "Payment Apps", icon: "💳", risk: "high" },
  { id: "settings", label: "Device Settings", icon: "⚙️", risk: "high" },
  { id: "social", label: "Social Media", icon: "📱", risk: "medium" },
  { id: "files", label: "File Manager", icon: "📁", risk: "high" },
  { id: "banking", label: "Banking App", icon: "🏦", risk: "critical" },
  { id: "screenshot", label: "Screenshot Taken", icon: "📸", risk: "high" },
  { id: "calls", label: "Call History", icon: "📞", risk: "medium" },
];

function PhoneHandoffTab({ addLog, handleRisk }) {
  const [handoffActive, setHandoffActive] = useState(false);
  const [handoffStart, setHandoffStart] = useState(null);
  const [events, setEvents] = useState([]);
  const [restrictions, setRestrictions] = useState({ email: true, payments: true, settings: true, files: true, banking: true });
  const [summary, setSummary] = useState(null);

  const riskColor = { low: "var(--green)", medium: "var(--gold)", high: "var(--orange)", critical: "var(--red)" };
  const riskLabel = { low: "LOW RISK", medium: "MEDIUM", high: "HIGH RISK", critical: "CRITICAL" };

  const startHandoff = () => {
    setHandoffActive(true);
    setHandoffStart(new Date().toLocaleTimeString());
    setEvents([]);
    setSummary(null);
    addLog("HANDOFF_SESSION_STARTED · monitoring active", "warn");
  };

  const endHandoff = () => {
    setHandoffActive(false);
    const suspicious = events.filter(e => e.risk === "high" || e.risk === "critical");
    const restricted = events.filter(e => e.wasRestricted);
    const report = {
      total: events.length,
      suspicious: suspicious.length,
      restricted: restricted.length,
      duration: handoffStart,
      events,
    };
    setSummary(report);
    addLog(`HANDOFF_ENDED · ${events.length} events · ${suspicious.length} suspicious`, "info");
    if (suspicious.length > 0) {
      handleRisk(suspicious.length * 12, "UNAUTHORIZED_ACCESS", `HANDOFF_MISUSE_DETECTED · ${suspicious.length} high-risk events`);
    }
  };

  const logEvent = (cat) => {
    if (!handoffActive) return;
    const wasRestricted = restrictions[cat.id];
    const evt = {
      id: Date.now(),
      time: new Date().toLocaleTimeString(),
      label: cat.label,
      risk: cat.risk,
      wasRestricted,
    };
    setEvents(p => [evt, ...p]);
    if (cat.risk === "critical") {
      addLog(`HANDOFF_CRITICAL · ${cat.label} accessed`, "threat");
      handleRisk(0, "UNAUTHORIZED_ACCESS", `HANDOFF_CRITICAL_ACCESS · ${cat.label}`);
    } else if (wasRestricted) {
      addLog(`HANDOFF_RESTRICTED · ${cat.label} — access denied area`, "threat");
      handleRisk(10, "UNAUTHORIZED_ACCESS", `HANDOFF_RESTRICTED_AREA · ${cat.label}`);
    } else if (cat.risk === "high") {
      addLog(`HANDOFF_HIGH_RISK · ${cat.label}`, "warn");
    } else {
      addLog(`HANDOFF_ACCESS · ${cat.label}`, "info");
    }
  };

  const toggleRestriction = (id) => {
    setRestrictions(p => ({ ...p, [id]: !p[id] }));
  };

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 20, animation: "fadeInUp .4s ease-out" }}>
      {/* Left panel */}
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <Card accent="var(--gold)" glow style={{ padding: "24px" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,214,10,0.5)", letterSpacing: "0.3em", marginBottom: 12 }}>PHONE HANDOFF MONITOR</div>
          <div style={{ fontFamily: "var(--font-body)", fontSize: 13, color: "rgba(255,255,255,0.45)", marginBottom: 18, lineHeight: 1.6 }}>
            Hand your phone to someone? Activate Handoff Mode first. Every app they open is recorded. When you get the phone back, review what was accessed and check for misuse.
          </div>
          {!handoffActive ? (
            <button onClick={startHandoff} style={{ width: "100%", padding: "14px 0", background: "rgba(255,214,10,0.08)", border: "1px solid rgba(255,214,10,0.4)", color: "var(--gold)", fontFamily: "var(--font-display)", fontSize: 11, cursor: "pointer", borderRadius: 10, letterSpacing: "0.2em", transition: "all .3s", animation: "float 3s ease-in-out infinite" }}
              onMouseOver={e => { e.target.style.background = "rgba(255,214,10,0.16)"; }}
              onMouseOut={e => { e.target.style.background = "rgba(255,214,10,0.08)"; }}>
              ▶ START HANDOFF SESSION
            </button>
          ) : (
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 14, padding: "10px 14px", background: "rgba(255,214,10,0.08)", borderRadius: 8, border: "1px solid rgba(255,214,10,0.2)" }}>
                <div style={{ width: 8, height: 8, borderRadius: "50%", background: "var(--gold)", animation: "pulse-ring 1.2s ease-out infinite" }} />
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--gold)" }}>ACTIVE · Started {handoffStart} · {events.length} events</span>
              </div>
              <button onClick={endHandoff} style={{ width: "100%", padding: "12px 0", background: "rgba(255,45,85,0.08)", border: "1px solid rgba(255,45,85,0.4)", color: "var(--red)", fontFamily: "var(--font-display)", fontSize: 11, cursor: "pointer", borderRadius: 10, letterSpacing: "0.2em" }}>
                ■ END HANDOFF SESSION
              </button>
            </div>
          )}
        </Card>

        <Card accent="var(--purple)" style={{ padding: "24px" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(191,90,242,0.5)", letterSpacing: "0.3em", marginBottom: 14 }}>RESTRICT DURING HANDOFF</div>
          {["email", "payments", "settings", "files", "banking"].map(id => {
            const cat = HANDOFF_CATEGORIES.find(c => c.id === id);
            return (
              <div key={id} onClick={() => toggleRestriction(id)} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "9px 0", borderBottom: "0.5px solid rgba(255,255,255,0.05)", cursor: "pointer" }}>
                <span style={{ fontFamily: "var(--font-body)", fontSize: 13, color: "rgba(255,255,255,0.6)" }}>{cat?.icon} {cat?.label}</span>
                <div style={{ width: 34, height: 18, borderRadius: 9, background: restrictions[id] ? "rgba(255,45,85,0.3)" : "rgba(255,255,255,0.1)", border: `1px solid ${restrictions[id] ? "rgba(255,45,85,0.5)" : "rgba(255,255,255,0.15)"}`, position: "relative", transition: "all .3s" }}>
                  <div style={{ position: "absolute", top: 2, left: restrictions[id] ? 16 : 2, width: 12, height: 12, borderRadius: "50%", background: restrictions[id] ? "var(--red)" : "rgba(255,255,255,0.3)", transition: "all .3s" }} />
                </div>
              </div>
            );
          })}
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.15)", marginTop: 12 }}>Toggle to enable/disable restrictions</div>
        </Card>

        {summary && (
          <Card accent={summary.suspicious > 0 ? "var(--red)" : "var(--green)"} glow style={{ padding: "20px 22px" }}>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: summary.suspicious > 0 ? "rgba(255,45,85,0.6)" : "rgba(48,209,88,0.6)", letterSpacing: "0.25em", marginBottom: 14 }}>
              {summary.suspicious > 0 ? "⚠ MISUSE DETECTED" : "✓ SESSION CLEAN"}
            </div>
            {[["Total Events", summary.total], ["High-Risk Access", summary.suspicious], ["Restricted Areas Hit", summary.restricted]].map(([k, v]) => (
              <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "7px 0", borderBottom: "0.5px solid rgba(255,255,255,0.05)" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.3)" }}>{k}</span>
                <span style={{ fontFamily: "var(--font-display)", fontSize: 13, color: v > 0 && k !== "Total Events" ? "var(--red)" : "var(--cyan)", fontWeight: 700 }}>{v}</span>
              </div>
            ))}
          </Card>
        )}
      </div>

      {/* Right panel */}
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        <Card accent="var(--gold)" style={{ padding: "24px" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,214,10,0.5)", letterSpacing: "0.3em", marginBottom: 14 }}>
            {handoffActive ? "SIMULATE APP ACCESS" : "APP ACCESS SIMULATOR"}
          </div>
          {!handoffActive && <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.2)", marginBottom: 14 }}>Start a handoff session to simulate app accesses</div>}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8 }}>
            {HANDOFF_CATEGORIES.map(cat => (
              <button key={cat.id} onClick={() => logEvent(cat)} disabled={!handoffActive}
                style={{
                  padding: "10px 12px", background: !handoffActive ? "transparent" : `${riskColor[cat.risk]}0a`,
                  border: `1px solid ${!handoffActive ? "rgba(255,255,255,0.08)" : `${riskColor[cat.risk]}33`}`,
                  color: !handoffActive ? "rgba(255,255,255,0.2)" : riskColor[cat.risk],
                  fontFamily: "var(--font-mono)", fontSize: 10, cursor: handoffActive ? "pointer" : "not-allowed",
                  borderRadius: 8, textAlign: "left", transition: "all .2s",
                }}>
                <div style={{ marginBottom: 3 }}>{cat.icon} {cat.label}</div>
                <div style={{ fontSize: 8, opacity: 0.5 }}>{riskLabel[cat.risk]}{restrictions[cat.id] ? " · RESTRICTED" : ""}</div>
              </button>
            ))}
          </div>
        </Card>

        <Card accent="var(--gold)" style={{ padding: "24px" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,214,10,0.5)", letterSpacing: "0.3em", marginBottom: 14 }}>ACCESS LOG</div>
          <div style={{ height: 240, overflowY: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
            {events.length === 0
              ? <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.12)", textAlign: "center", padding: "40px 0" }}>No access events recorded</div>
              : events.map(evt => {
                const col = evt.wasRestricted || evt.risk === "critical" ? "var(--red)" : evt.risk === "high" ? "var(--orange)" : evt.risk === "medium" ? "var(--gold)" : "var(--green)";
                return (
                  <div key={evt.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 12px", borderRadius: 6, background: `${col}08`, borderLeft: `2px solid ${col}` }}>
                    <div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: col }}>{evt.label}</div>
                      {evt.wasRestricted && <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,45,85,0.5)", marginTop: 2 }}>RESTRICTED AREA</div>}
                    </div>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.2)" }}>{evt.time}</span>
                  </div>
                );
              })}
          </div>
        </Card>
      </div>
    </div>
  );
}

/* ─── SHADOW ENV SCREEN ─── */
function ShadowEnv({ onReset, risk }) {
  const [step, setStep] = useState(0);
  const [showSplit, setShowSplit] = useState(false);
  const [showForensic, setShowForensic] = useState(false);
  const [forensicReport, setForensicReport] = useState(null);
  const [honeypotState, setHoneypotState] = useState({});
  const [canaryState, setCanaryState] = useState({});
  const [ipTrace, setIpTrace] = useState({ stage: 0, ips: [] });
  const [lockPhase, setLockPhase] = useState(0);

  const lines = [
    { t: 0, text: "> BEHAVIORAL_DNA_MISMATCH — confidence 96%", c: "#ff2d55" },
    { t: 500, text: `> SESSION_ANOMALY_SCORE: ${Math.round(risk)}% — threshold exceeded`, c: "#ff2d55" },
    { t: 1000, text: "> INITIATING virtual_instance_fork() — MicroVM spinning up", c: "#ff2d55" },
    { t: 1500, text: "> DECOY_FS MOUNTED: /honeypot/v2/user_documents/", c: "#ffd60a" },
    { t: 2000, text: "> CANARY_TOKEN_INJECTION: 5 files seeded with trackers", c: "#ffd60a" },
    { t: 2500, text: "> VFS_HOOK ACTIVE: intruder routed → fake_root", c: "#ffd60a" },
    { t: 3000, text: "> REAL_ROOT: ENCRYPTED · INVISIBLE · SEALED", c: "#30d158" },
    { t: 3500, text: "> HONEYPOT_TRAPS: 3 psychological triggers armed", c: "#bf5af2" },
    { t: 4000, text: "> IP_TRACE: 185.220.x.x → TOR_EXIT_NODE_12 → resolving...", c: "#00f5ff" },
    { t: 4500, text: "> TTP_FINGERPRINT: APT29 pattern match 84% confidence", c: "#00f5ff" },
    { t: 5000, text: "> CANARY_CALLBACK_LISTENER: active on port 443/8443", c: "#00f5ff" },
    { t: 5500, text: "> FORENSIC_EVIDENCE: timestamped · cryptographically signed", c: "#30d158" },
    { t: 6000, text: "> COUNTER-INTEL PACKAGE: deploying misinformation payload", c: "#bf5af2" },
    { t: 6500, text: "> ALL_SYSTEMS: QUARANTINE COMPLETE · INTRUDER CONTAINED ✓", c: "#30d158" },
  ];

  useEffect(() => {
    lines.forEach(({ t }, i) => setTimeout(() => setStep(i), t));
    setTimeout(() => setShowSplit(true), 7200);
    setTimeout(() => setShowForensic(true), 9000);
    setTimeout(() => setForensicReport(engine.buildForensicReport()), 9200);
    const ips = ["185.220.101.47", "10.0.0.1 (TOR_EXIT)", "45.141.215.x (VPN)", "ORIGIN: resolving...", "ORIGIN: 78.31.x.x (RU)"];
    ips.forEach((ip, i) => setTimeout(() => setIpTrace(p => ({ stage: i, ips: [...p.ips, ip] })), 4000 + i * 900));
    setTimeout(() => setLockPhase(1), 3200);
    setTimeout(() => setLockPhase(2), 8000);
  }, []);

  const triggerCanary = (id) => { engine.triggerCanary(id); setCanaryState(p => ({ ...p, [id]: true })); };
  const triggerHoneypot = (sel) => { engine.triggerHoneypot(sel); setHoneypotState(p => ({ ...p, [sel]: true })); };

  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 200, background: "#000", display: "flex", flexDirection: "column", alignItems: "center", overflowY: "auto", fontFamily: "var(--font-mono)", paddingBottom: 40 }}>
      <Grid /><ParticleCanvas mode={MODES.QUARANTINE} /><MatrixRain />
      <div style={{ position: "fixed", inset: 0, pointerEvents: "none", zIndex: 2, background: "radial-gradient(ellipse at center, transparent 40%, rgba(255,45,85,0.18) 100%)", animation: "vignette-pulse 3s ease-in-out infinite" }} />

      <div style={{ position: "relative", zIndex: 10, width: "90%", maxWidth: 880, paddingTop: 40 }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div style={{ fontFamily: "var(--font-display)", fontSize: 28, fontWeight: 900, color: "var(--red)", letterSpacing: "0.15em", animation: "flicker 3s infinite" }}>◈ QUARANTINE ACTIVE</div>
          <div style={{ fontSize: 11, color: "rgba(255,45,85,0.45)", marginTop: 6, letterSpacing: "0.3em" }}>SHADOW ENVIRONMENT — MIRROR MAZE + COUNTER-INTEL DEPLOYED</div>
          <div style={{ display: "inline-flex", alignItems: "center", gap: 8, marginTop: 12, padding: "6px 16px", background: "rgba(255,45,85,0.08)", borderRadius: 20, border: "0.5px solid rgba(255,45,85,0.2)" }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--red)", animation: "pulse-ring 1s infinite" }} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--red)" }}>SESSION LOCKED · {engine.sessionId.slice(0, 12).toUpperCase()}</span>
          </div>
        </div>

        <Card accent="var(--red)" glow style={{ padding: "24px 28px", marginBottom: 20 }}>
          <div style={{ fontSize: 10, color: "rgba(255,45,85,0.4)", marginBottom: 16, letterSpacing: "0.2em" }}>[COGNISAFE_QUARANTINE_ENGINE v3.1 · SHADOW_MODE]</div>
          {lines.slice(0, step + 1).map((l, i) => (
            <div key={i} style={{ fontSize: 12, color: i === step ? l.c : `${l.c}44`, marginBottom: 5, transition: "color .5s", animation: i === step ? "fadeInUp .3s ease-out" : "none" }}>
              {l.text}{i === step && <span style={{ animation: "blink .8s infinite" }}>_</span>}
            </div>
          ))}
        </Card>

        {showSplit && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 14, marginBottom: 18, animation: "fadeInUp .5s ease-out" }}>
            <Card accent="var(--red)" style={{ padding: "16px 18px" }}>
              <div style={{ fontSize: 10, color: "rgba(255,45,85,0.5)", marginBottom: 10, letterSpacing: "0.2em" }}>👁 ATTACKER VIEW (DECOY)</div>
              <div style={{ fontSize: 11, color: "var(--red)", marginBottom: 3 }}>$ ls /documents</div>
              {engine.decoyFiles.map(f => (
                <div key={f.id} onClick={() => triggerCanary(f.id)} style={{ fontSize: 10, color: canaryState[f.id] ? "#ff9f0a" : "rgba(255,45,85,0.55)", cursor: "pointer", marginBottom: 2, padding: "2px 6px", borderRadius: 3, background: canaryState[f.id] ? "rgba(255,159,10,0.12)" : "transparent", transition: "all .2s", textDecoration: "underline dotted" }}>
                  {canaryState[f.id] ? "🔔 " : ""}{f.name}
                </div>
              ))}
            </Card>
            <Card accent="var(--cyan)" glow style={{ padding: "16px 18px" }}>
              <div style={{ fontSize: 10, color: "rgba(0,245,255,0.5)", marginBottom: 10, letterSpacing: "0.2em" }}>🔒 REAL SYSTEM</div>
              <div style={{ fontSize: 12, color: "var(--green)", marginBottom: 4 }}>✓ /documents ENCRYPTED</div>
              <div style={{ fontSize: 12, color: "var(--green)", marginBottom: 4 }}>✓ /keys SEALED</div>
              <div style={{ fontSize: 12, color: "var(--green)", marginBottom: 4 }}>✓ /db MIRRORED+HIDDEN</div>
              <div style={{ fontSize: 11, color: "var(--green)", marginBottom: 4 }}>✓ DNA_LOCK ENGAGED</div>
              {lockPhase >= 1 && <div style={{ fontSize: 10, color: "var(--gold)", marginTop: 8, animation: "fadeInUp .3s" }}>⬡ SESSION SIGNATURE PRESERVED</div>}
              {lockPhase >= 2 && <div style={{ fontSize: 10, color: "var(--purple)", marginTop: 4, animation: "fadeInUp .3s" }}>⬡ COUNTER-INTEL ACTIVE</div>}
            </Card>
            <Card accent="var(--cyan)" style={{ padding: "16px 18px" }}>
              <div style={{ fontSize: 10, color: "rgba(0,245,255,0.5)", marginBottom: 10, letterSpacing: "0.2em" }}>📡 IP TRACE</div>
              {ipTrace.ips.map((ip, i) => (
                <div key={i} style={{ fontSize: 10, color: i === ipTrace.ips.length - 1 ? "var(--gold)" : "rgba(0,245,255,0.4)", marginBottom: 4, animation: "fadeInUp .3s" }}>
                  {i > 0 ? "→ " : ""}{ip}
                </div>
              ))}
              {ipTrace.stage < 4 && <div style={{ fontSize: 10, color: "rgba(255,255,255,0.2)" }}>Tracing<span style={{ animation: "blink .8s infinite" }}>...</span></div>}
            </Card>
          </div>
        )}

        {showSplit && (
          <Card accent="var(--purple)" style={{ padding: "20px 22px", marginBottom: 18, animation: "fadeInUp .5s ease-out .2s both" }}>
            <div style={{ fontSize: 10, color: "rgba(191,90,242,0.5)", marginBottom: 14, letterSpacing: "0.2em" }}>🪤 PSYCHOLOGICAL HONEYPOT TRAPS</div>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              {engine.honeypotTraps.map(trap => (
                <button key={trap.selector} onClick={() => triggerHoneypot(trap.selector)} style={{ padding: "10px 16px", background: honeypotState[trap.selector] ? "rgba(255,45,85,0.15)" : "rgba(191,90,242,0.06)", border: `1px solid ${honeypotState[trap.selector] ? "var(--red)" : "rgba(191,90,242,0.25)"}`, color: honeypotState[trap.selector] ? "var(--red)" : "rgba(191,90,242,0.8)", fontFamily: "var(--font-mono)", fontSize: 10, cursor: "pointer", borderRadius: 8, transition: "all .2s", animation: honeypotState[trap.selector] ? "shake .4s ease-out" : "none" }}>
                  {honeypotState[trap.selector] ? "⚠ TRIGGERED: " : ""}{trap.label}
                </button>
              ))}
            </div>
          </Card>
        )}

        {showForensic && forensicReport && (
          <div style={{ animation: "fadeInUp .5s ease-out" }}>
            <ForensicReport report={forensicReport} />
          </div>
        )}

        <button onClick={onReset} style={{ width: "100%", padding: "14px 0", background: "transparent", border: "1px solid rgba(255,255,255,0.12)", color: "rgba(255,255,255,0.35)", fontFamily: "var(--font-mono)", fontSize: 11, cursor: "pointer", borderRadius: 10, letterSpacing: "0.3em", transition: "all .3s" }}
          onMouseOver={e => { e.target.style.borderColor = "rgba(255,255,255,0.4)"; e.target.style.color = "#fff"; }}
          onMouseOut={e => { e.target.style.borderColor = "rgba(255,255,255,0.12)"; e.target.style.color = "rgba(255,255,255,0.35)"; }}>
          RESET DEMO SESSION
        </button>
      </div>
    </div>
  );
}

/* ─── CONSENT GATE ─── */
function ConsentGate({ onConsent }) {
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const go = () => {
    setScanning(true); let p = 0;
    const t = setInterval(() => { p += Math.random() * 14; setProgress(Math.min(p, 100)); if (p >= 100) { clearInterval(t); setTimeout(onConsent, 400); } }, 70);
  };
  const perms = [
    ["Keystroke dynamics & typing rhythm", "Level 1 · Micro Behavior"],
    ["Navigation flow & scroll velocity", "Level 2 · Interaction"],
    ["Mouse jitter & click patterns", "Level 2 · Interaction"],
    ["Session time & device fingerprint", "Level 3 · Contextual"],
    ["Email block & access control", "Level 3 · Security"],
    ["Phone handoff audit logging", "Level 3 · Device Guard"],
    ["Behavioral DNA profiling", "Level 4 · Cognitive"],
    ["All data processed locally on device", "Privacy · Edge-Only"],
  ];
  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)", display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
      <Grid /><ParticleCanvas mode={MODES.PROTECTED} /><ScanLine />
      <div style={{ position: "relative", zIndex: 10, width: "90%", maxWidth: 460, animation: "fadeInUp .8s ease-out" }}>
        <div style={{ textAlign: "center", marginBottom: 44 }}>
          <div style={{ position: "relative", width: 100, height: 100, margin: "0 auto 28px" }}>
            <div style={{ position: "absolute", inset: 0, borderRadius: "50%", border: "1px solid rgba(0,245,255,0.15)", animation: "spin-slow 8s linear infinite" }}>
              <div style={{ position: "absolute", top: -3, left: "50%", transform: "translateX(-50%)", width: 6, height: 6, borderRadius: "50%", background: "var(--cyan)", boxShadow: "0 0 12px var(--cyan)" }} />
            </div>
            <div style={{ position: "absolute", inset: 14, borderRadius: "50%", border: "1px solid rgba(0,245,255,0.1)", animation: "spin-rev 5s linear infinite" }}>
              <div style={{ position: "absolute", bottom: -3, left: "50%", transform: "translateX(-50%)", width: 4, height: 4, borderRadius: "50%", background: "var(--cyan)", opacity: .6 }} />
            </div>
            <div style={{ position: "absolute", inset: 28, borderRadius: "50%", background: "radial-gradient(circle,rgba(0,245,255,0.12),transparent)", border: "1px solid rgba(0,245,255,0.3)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <span style={{ fontFamily: "var(--font-display)", fontSize: 16, color: "var(--cyan)" }}>⬡</span>
            </div>
          </div>
          <GlitchText text="COGNISAFE" style={{ fontFamily: "var(--font-display)", fontSize: 30, fontWeight: 900, color: "#fff", letterSpacing: "0.2em" }} />
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(0,245,255,0.45)", marginTop: 8, letterSpacing: "0.35em" }}>COGNITIVE BEHAVIORAL DEFENSE · v3.1</div>
        </div>
        <Card accent="var(--cyan)" glow style={{ padding: "32px 28px" }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.25)", letterSpacing: "0.3em", marginBottom: 20 }}>GUARDIAN ACCESS REQUEST</div>
          {perms.map(([label, tag], i) => (
            <div key={i} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "11px 14px", marginBottom: 8, background: "rgba(0,245,255,0.04)", borderRadius: 8, border: "0.5px solid rgba(0,245,255,0.1)", animation: `fadeInUp .5s ease-out ${i * .1}s both` }}>
              <span style={{ fontFamily: "var(--font-body)", fontSize: 13, color: "rgba(255,255,255,0.7)" }}>{label}</span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(0,245,255,0.5)", letterSpacing: "0.1em" }}>{tag}</span>
            </div>
          ))}
          <div style={{ marginTop: 24 }}>
            {scanning ? (
              <div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--cyan)", marginBottom: 8, letterSpacing: "0.2em" }}>INITIALIZING BEHAVIORAL ENGINE v3.1...</div>
                <div style={{ background: "rgba(255,255,255,0.06)", borderRadius: 4, height: 4, overflow: "hidden" }}>
                  <div style={{ height: "100%", background: "var(--cyan)", borderRadius: 4, width: `${progress}%`, transition: "width .1s", boxShadow: "0 0 12px var(--cyan)" }} />
                </div>
              </div>
            ) : (
              <button onClick={go} style={{ width: "100%", padding: "15px 0", background: "transparent", border: "1px solid var(--cyan)", color: "var(--cyan)", fontFamily: "var(--font-display)", fontSize: 12, fontWeight: 700, letterSpacing: "0.25em", cursor: "pointer", borderRadius: 10, boxShadow: "0 0 20px rgba(0,245,255,0.2)", transition: "all .3s", animation: "float 3s ease-in-out infinite" }}
                onMouseOver={e => { e.target.style.background = "var(--cyan)"; e.target.style.color = "#000"; }}
                onMouseOut={e => { e.target.style.background = "transparent"; e.target.style.color = "var(--cyan)"; }}>
                GRANT GUARDIAN ACCESS
              </button>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}

/* ─── REALISTIC THREAT SIMULATION BAR ─── */
function SimulationBar({ addLog, handleRisk }) {
  const [cooldowns, setCooldowns] = useState({});

  const threats = [
    { id: "phishing", name: "🎣 Phishing Link", desc: "Clicked suspicious 'Verify Account' link", weight: 25, reason: "PHISHING_LINK_CLICK", msg: "PHISHING_LINK_CLICKED · fake-login-page.com" },
    { id: "download", name: "📎 Suspicious Download", desc: "Downloaded invoice.zip from unknown sender", weight: 30, reason: "SUSPICIOUS_DOWNLOAD", msg: "SUSPICIOUS_FILE_DOWNLOADED · invoice.zip" },
    { id: "fake_login", name: "🔐 Fake Login", desc: "Entered credentials on fake banking portal", weight: 35, reason: "FAKE_LOGIN_ATTEMPT", msg: "FAKE_LOGIN_PAGE_CREDENTIALS_ENTERED" },
    { id: "social", name: "📞 Social Engineering", desc: "Shared OTP with 'tech support'", weight: 28, reason: "SOCIAL_ENGINEERING", msg: "SOCIAL_ENGINEERING_OTP_SHARED" },
    { id: "attachment", name: "📧 Malicious Attachment", desc: "Opened attached 'invoice.exe'", weight: 40, reason: "MALICIOUS_ATTACHMENT", msg: "MALICIOUS_ATTACHMENT_OPENED · invoice.exe" },
    { id: "data_exfil", name: "📤 Data Exfiltration", desc: "Attempted to upload sensitive files", weight: 45, reason: "DATA_EXFILTRATION", msg: "DATA_EXFILTRATION_ATTEMPT_DETECTED" },
    { id: "unauth", name: "🚪 Unauthorized Access", desc: "Accessed admin panel without permission", weight: 50, reason: "UNAUTHORIZED_ACCESS", msg: "UNAUTHORIZED_ADMIN_ACCESS_ATTEMPT" },
  ];

  const triggerThreat = (threat) => {
    if (cooldowns[threat.id]) return;
    setCooldowns(prev => ({ ...prev, [threat.id]: true }));
    setTimeout(() => setCooldowns(prev => ({ ...prev, [threat.id]: false }), 1000));
    addLog(threat.msg, "threat");
    handleRisk(threat.weight, threat.reason, threat.msg);
  };

  return (
    <div style={{
      position: "fixed", bottom: 0, left: 0, right: 0, zIndex: 100,
      background: "rgba(6,10,18,0.95)", backdropFilter: "blur(20px)",
      borderTop: "1px solid rgba(255,45,85,0.5)",
      padding: "12px 20px",
      boxShadow: "0 -4px 30px rgba(0,0,0,0.5)"
    }}>
      <div style={{ textAlign: "center", marginBottom: 10 }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--red)", letterSpacing: "0.15em" }}>⚠ REAL-TIME THREAT SIMULATION — Click any threat to increase risk ⚠</span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 10, justifyContent: "center" }}>
        {threats.map(threat => (
          <button
            key={threat.id}
            onClick={() => triggerThreat(threat)}
            disabled={cooldowns[threat.id]}
            style={{
              padding: "8px 16px",
              background: cooldowns[threat.id] ? "rgba(255,255,255,0.05)" : "rgba(255,45,85,0.15)",
              border: `1px solid ${cooldowns[threat.id] ? "rgba(255,255,255,0.1)" : "rgba(255,45,85,0.5)"}`,
              color: cooldowns[threat.id] ? "rgba(255,255,255,0.2)" : "var(--red)",
              fontFamily: "var(--font-mono)", fontSize: 10, fontWeight: 500,
              cursor: cooldowns[threat.id] ? "not-allowed" : "pointer",
              borderRadius: 30, transition: "all 0.2s", display: "flex", alignItems: "center", gap: 8
            }}
            onMouseOver={e => { if (!cooldowns[threat.id]) e.target.style.background = "rgba(255,45,85,0.3)"; }}
            onMouseOut={e => { if (!cooldowns[threat.id]) e.target.style.background = "rgba(255,45,85,0.15)"; }}
          >
            <span>{threat.name}</span>
            <span style={{ fontSize: 9, opacity: 0.7 }}>+{threat.weight}</span>
          </button>
        ))}
      </div>
      <div style={{ textAlign: "center", marginTop: 8, fontSize: 8, fontFamily: "var(--font-mono)", color: "rgba(255,255,255,0.25)" }}>
        ⚡ Only manual button clicks increase risk — normal mouse movement and typing are SAFE ⚡<br />
        Risk decays over time — reach 78% to trigger quarantine shadow environment
      </div>
    </div>
  );
}

/* ─── DASHBOARD (AUTOMATIC DETECTION DISABLED) ─── */
function Dashboard() {
  const [risk, setRisk] = useState(0);
  const [mode, setMode] = useState(MODES.PROTECTED);
  const [logs, setLogs] = useState([
    { time: new Date().toLocaleTimeString(), msg: "COGNISAFE_v3.1_ENGINE_ONLINE", type: "info" },
    { time: new Date().toLocaleTimeString(), msg: "BEHAVIORAL_DNA_MONITOR_ACTIVE", type: "info" },
    { time: new Date().toLocaleTimeString(), msg: "CANARY_TOKENS_SEEDED · 5_FILES", type: "info" },
    { time: new Date().toLocaleTimeString(), msg: "HONEYPOT_TRAPS_ARMED · 3_TRIGGERS", type: "info" },
    { time: new Date().toLocaleTimeString(), msg: "EMAIL_BLOCK_ENGINE_READY", type: "info" },
    { time: new Date().toLocaleTimeString(), msg: "PHONE_HANDOFF_MONITOR_READY", type: "info" },
    { time: new Date().toLocaleTimeString(), msg: "ALL_SENSOR_LEVELS_NOMINAL", type: "info" },
    { time: new Date().toLocaleTimeString(), msg: "⚠ THREAT SIMULATION MODE — Click threats below to test ⚠", type: "warn" },
  ]);
  const [dnaTimings, setDnaTimings] = useState([]);
  const [threatCount, setThreatCount] = useState(0);
  const [resilience, setResilience] = useState(42);
  const [showQ, setShowQ] = useState(false);
  const [tab, setTab] = useState("overview");
  const [popup, setPopup] = useState(null);
  const [clicks, setClicks] = useState(0);
  const [mouseEvents, setMouseEvents] = useState(0);
  const [tabSwitches, setTabSwitches] = useState(0);
  const [clipboardEvents, setClipboardEvents] = useState(0);
  const lastKey = useRef(0);
  const riskRef = useRef(0);

  const addLog = useCallback((msg, type = "info") => {
    setLogs(p => [{ time: new Date().toLocaleTimeString(), msg, type }, ...p.slice(0, 49)]);
  }, []);

  const handleRisk = useCallback((delta, reason, msg) => {
    setRisk(p => {
      const weight = RISK_WEIGHTS[reason] ?? delta;
      const next = Math.min(100, p + weight);
      riskRef.current = next;
      const m = getMode(next);
      setMode(m);
      if (msg) addLog(msg, next > 70 ? "threat" : next > 40 ? "warn" : "info");
      engine.addIntruderData("lastReason", reason);
      engine.addIntruderData("peakRisk", Math.max(engine.intruderProfile.peakRisk || 0, next));
      if (m === MODES.QUARANTINE && !showQ) {
        setThreatCount(pp => pp + 1);
        setResilience(pp => Math.min(pp + 8, 100));
        engine.lockSession();
        setTimeout(() => setShowQ(true), 1200);
      }
      return next;
    });
  }, [addLog, showQ]);

  const decayRisk = useCallback(() => {
    setRisk(p => { const next = Math.max(0, p - 0.3); riskRef.current = next; setMode(getMode(next)); return next; });
  }, []);

  useEffect(() => {
    const t = setInterval(decayRisk, 2000);
    return () => clearInterval(t);
  }, [decayRisk]);

  // KEYBOARD DNA - ONLY RECORDS, NO RISK ADDED
  const handleKeyDown = useCallback((e) => {
    const now = performance.now();
    if (lastKey.current !== 0) {
      const f = now - lastKey.current;
      setDnaTimings(p => [...p.slice(-24), f]);
      // NO RISK ADDED from typing
    }
    lastKey.current = now;
  }, []);

  // ALL AUTOMATIC DETECTION IS DISABLED - ONLY MANUAL BUTTONS ADD RISK
  useEffect(() => {
    // Off-hours detection DISABLED
    // Headless detection DISABLED
    // Click burst detection DISABLED
    // Scroll anomaly DISABLED
    // Mouse anomaly DISABLED
    // Tab switch detection DISABLED
    // Clipboard detection DISABLED
    
    // Only tracking for display purposes (no risk added)
    const onClick = () => setClicks(p => p + 1);
    const onMouseMove = () => setMouseEvents(p => p + 1);
    const onVisibility = () => { if (document.hidden) setTabSwitches(p => p + 1); };
    const onPaste = (e) => {
      const d = e.clipboardData?.getData("text") || "";
      setClipboardEvents(p => p + 1);
      addLog("CLIPBOARD_EVENT · len=" + d.length, "info");
    };

    window.addEventListener("click", onClick);
    window.addEventListener("mousemove", onMouseMove);
    document.addEventListener("visibilitychange", onVisibility);
    window.addEventListener("paste", onPaste);
    
    return () => {
      window.removeEventListener("click", onClick);
      window.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("visibilitychange", onVisibility);
      window.removeEventListener("paste", onPaste);
    };
  }, [addLog]);

  useEffect(() => {
    if (risk > 50 && risk < 78) setPopup("ELEVATED_RISK_DETECTED_MONITORING_ENHANCED");
    else if (risk >= 78) setPopup("CRITICAL_THREAT_SHADOW_QUARANTINE_INITIATED");
    else setPopup(null);
  }, [risk]);

  const tc = mode === MODES.QUARANTINE ? "var(--red)" : mode === MODES.ELEVATED ? "var(--gold)" : "var(--cyan)";
  const TABS = [
    ["overview", "OVERVIEW"], ["dna", "DNA SENSOR"], ["email", "EMAIL BLOCK"],
    ["handoff", "PHONE HANDOFF"], ["intel", "THREAT INTEL"], ["shadow", "SHADOW ENV"], ["coach", "CYBER COACH"]
  ];
  return (
    <div style={{ minHeight: "100vh", background: "var(--bg)", position: "relative", paddingBottom: 140 }}>
      <Grid /><ParticleCanvas mode={mode} /><ScanLine />
      {mode === MODES.QUARANTINE && <div style={{ position: "fixed", inset: 0, zIndex: 1, pointerEvents: "none", background: "radial-gradient(ellipse,transparent 40%,rgba(255,45,85,0.12) 100%)", animation: "redPulse 2s ease-in-out infinite" }} />}
      {showQ && <ShadowEnv risk={risk} onReset={() => { setShowQ(false); setRisk(0); setMode(MODES.PROTECTED); addLog("DEMO_SESSION_RESET · CLEAN_STATE_RESTORED", "info"); }} />}
      <ThreatPopup threat={popup} onDismiss={() => setPopup(null)} />

      <header style={{ position: "sticky", top: 0, zIndex: 40, background: "rgba(6,10,18,0.88)", backdropFilter: "blur(20px)", borderBottom: `1px solid ${tc}22`, padding: "0 28px", height: 62, display: "flex", alignItems: "center", justifyContent: "space-between", transition: "border-color .5s" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <GlitchText text="COGNISAFE" style={{ fontFamily: "var(--font-display)", fontSize: 18, fontWeight: 900, color: "#fff", letterSpacing: "0.15em" }} />
          <div style={{ width: 1, height: 24, background: "rgba(255,255,255,0.08)" }} />
          <StatusBadge mode={mode} />
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 20 }}>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.2)" }}>{new Date().toLocaleTimeString()} · v3.1</div>
          <Ring value={risk} color={tc} size={46} label="RISK" />
        </div>
      </header>

      <div style={{ position: "sticky", top: 62, zIndex: 39, background: "rgba(6,10,18,0.82)", backdropFilter: "blur(20px)", borderBottom: "1px solid rgba(255,255,255,0.05)", display: "flex", padding: "0 28px", gap: 4, overflowX: "auto" }}>
        {TABS.map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)} style={{ padding: "12px 16px", background: "none", border: "none", borderBottom: tab === id ? `2px solid ${tc}` : "2px solid transparent", color: tab === id ? tc : "rgba(255,255,255,0.28)", fontFamily: "var(--font-display)", fontSize: 9, cursor: "pointer", letterSpacing: "0.15em", transition: "all .25s", fontWeight: 700, whiteSpace: "nowrap" }}>
            {label}
          </button>
        ))}
      </div>

      <main style={{ padding: "28px", maxWidth: 1200, margin: "0 auto", position: "relative", zIndex: 10 }}>

        {/* ── OVERVIEW ── */}
        {tab === "overview" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))", gap: 20, animation: "fadeInUp .4s ease-out" }}>
            <Card accent={tc} glow style={{ padding: "36px 28px", display: "flex", flexDirection: "column", alignItems: "center", gap: 24 }}>
              <Ring value={risk} color={tc} size={160} label="RISK SCORE" />
              <div style={{ width: "100%", display: "flex", flexDirection: "column", gap: 8 }}>
                {[["DNA Vectors", dnaTimings.length], ["Threats Blocked", threatCount], ["Session Events", clicks], ["Mouse Events", mouseEvents], ["Tab Switches", tabSwitches], ["Clipboard Events", clipboardEvents]].map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "8px 0", borderBottom: "0.5px solid rgba(255,255,255,0.05)" }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.3)" }}>{k}</span>
                    <span style={{ fontFamily: "var(--font-display)", fontSize: 13, color: tc, fontWeight: 700 }}>{v}</span>
                  </div>
                ))}
              </div>
            </Card>
            <Card accent="var(--cyan)" style={{ padding: "28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.22)", letterSpacing: "0.3em", marginBottom: 22 }}>SENSOR_MATRIX · v3.1</div>
              {[
                { id: "L1", label: "Micro Behavior", sub: "Keystroke DNA · Mouse Jitter · Click Pattern", c: "var(--cyan)" },
                { id: "L2", label: "Interaction Flow", sub: "Click Burst · Scroll Velocity · Clipboard", c: "var(--cyan)" },
                { id: "L3", label: "Contextual DNA", sub: "Time · Device · Tab Visibility", c: "var(--cyan)" },
                { id: "EM", label: "Email Guard", sub: "Address Blocklist · Domain Filter", c: "var(--red)" },
                { id: "PH", label: "Phone Handoff", sub: "Access Audit · Misuse Detection", c: "var(--gold)" },
                { id: "SHD", label: "Shadow Engine", sub: "Mirror Maze · Canary · Counter-Intel", c: "var(--red)" },
                { id: "FRN", label: "Forensic Layer", sub: "Evidence Signing · TTP Fingerprinting", c: "var(--gold)" },
              ].map((s, i) => (
                <div key={s.id} style={{ display: "flex", alignItems: "center", gap: 14, padding: "11px 0", borderBottom: "0.5px solid rgba(255,255,255,0.04)", animation: `fadeInUp .4s ease-out ${i * .08}s both` }}>
                  <div style={{ position: "relative", flexShrink: 0 }}>
                    <div style={{ width: 8, height: 8, borderRadius: "50%", background: s.c, boxShadow: `0 0 8px ${s.c}` }} />
                    <div style={{ position: "absolute", inset: 0, borderRadius: "50%", border: `1px solid ${s.c}`, animation: "pulse-ring 2s ease-out infinite" }} />
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontFamily: "var(--font-body)", fontSize: 13, fontWeight: 600, color: "rgba(255,255,255,0.8)" }}>{s.label}</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.22)" }}>{s.sub}</div>
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "var(--green)", padding: "3px 8px", background: "rgba(48,209,88,0.1)", borderRadius: 4 }}>ACTIVE</div>
                </div>
              ))}
            </Card>
            <Card accent="var(--cyan)" style={{ padding: "28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.22)", letterSpacing: "0.3em", marginBottom: 16 }}>LIVE_TELEMETRY</div>
              <LogFeed logs={logs} />
            </Card>
            <Card accent="var(--cyan)" style={{ padding: "28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.22)", letterSpacing: "0.3em", marginBottom: 18 }}>DEVICE_FINGERPRINT · L3</div>
              {[["Platform", navigator.platform], ["Language", navigator.language], ["Screen", `${screen.width}×${screen.height}`], ["Color Depth", `${screen.colorDepth}-bit`], ["Login Hour", `${new Date().getHours()}:00 hrs`], ["Timezone", Intl.DateTimeFormat().resolvedOptions().timeZone], ["CPU Cores", navigator.hardwareConcurrency || "N/A"], ["Webdriver", navigator.webdriver ? "DETECTED ⚠" : "Clean"], ["Plugins", navigator.plugins?.length || 0]].map(([k, v], i) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "7px 0", borderBottom: "0.5px solid rgba(255,255,255,0.04)", animation: `fadeInUp .4s ease-out ${i * .05}s both` }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.28)" }}>{k}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: String(v).includes("DETECTED") ? "var(--red)" : "rgba(0,245,255,0.7)" }}>{v}</span>
                </div>
              ))}
            </Card>
          </div>
        )}

        {/* ── DNA SENSOR ── */}
        {tab === "dna" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 20, animation: "fadeInUp .4s ease-out" }}>
            <Card accent="var(--cyan)" glow style={{ padding: "32px 28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.22)", letterSpacing: "0.3em", marginBottom: 24 }}>BEHAVIORAL DNA INPUT · LEVEL 1</div>
              <div style={{ position: "relative", marginBottom: 32 }}>
                <input type="text" onKeyDown={handleKeyDown} placeholder="Type to generate behavioral signature (no risk added)..."
                  style={{ width: "100%", background: "transparent", border: "none", borderBottom: `1px solid ${tc}44`, color: tc, fontFamily: "var(--font-mono)", fontSize: 14, padding: "14px 0", outline: "none", boxSizing: "border-box", letterSpacing: "0.05em", caretColor: tc, transition: "border-color .5s" }} />
                <div style={{ position: "absolute", bottom: 0, left: 0, right: 0, height: 1, background: `linear-gradient(90deg,transparent,${tc},transparent)`, animation: "holo 3s ease infinite", backgroundSize: "200% 200%" }} />
              </div>
              <div style={{ marginBottom: 12, fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.18)" }}>FLIGHT TIME VECTORS — {dnaTimings.length} samples</div>
              <DNABars timings={dnaTimings} />
              <div style={{ marginTop: 20, display: "flex", justifyContent: "space-between" }}>
                {[["< 50ms · FAST", "var(--gold)"], ["50–400ms · NORMAL", "var(--cyan)"], ["> 400ms · SLOW", "var(--red)"]].map(([l, c]) => (
                  <div key={l} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                    <div style={{ width: 8, height: 8, background: c, borderRadius: 2 }} />
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.28)" }}>{l}</span>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 12, fontSize: 9, fontFamily: "var(--font-mono)", color: "rgba(255,255,255,0.2)", textAlign: "center" }}>
                ℹ️ Typing is monitored but does NOT add risk. Only manual threat buttons increase risk.
              </div>
            </Card>
            <Card accent="var(--cyan)" style={{ padding: "32px 28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.22)", letterSpacing: "0.3em", marginBottom: 24 }}>DNA PROFILE ANALYSIS</div>
              <div style={{ display: "flex", justifyContent: "space-around", marginBottom: 32 }}>
                <Ring value={dnaTimings.length > 5 ? 87 : dnaTimings.length * 17} color="var(--cyan)" size={100} label="CONFIDENCE" />
                <Ring value={risk} color={tc} size={100} label="RISK" />
                <Ring value={resilience} color="var(--purple)" size={100} label="RESILIENCE" />
              </div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.2)", lineHeight: 1.9, borderTop: "0.5px solid rgba(255,255,255,0.05)", paddingTop: 20 }}>
                {dnaTimings.length < 5 ? `◌ Calibrating... ${dnaTimings.length}/5 vectors needed` : `◈ Profile ACTIVE — ${dnaTimings.length} vectors mapped`}<br />
                {dnaTimings.length > 0 && `→ Avg flight time: ${Math.round(dnaTimings.reduce((a, b) => a + b, 0) / dnaTimings.length)}ms`}<br />
                → Edge processing: ENABLED (stays local)<br />
                → DNA never leaves this device<br />
                → LSTM model: quantized on-device
              </div>
            </Card>
          </div>
        )}

        {/* ── EMAIL BLOCK ── */}
        {tab === "email" && <EmailBlockTab addLog={addLog} handleRisk={handleRisk} />}

        {/* ── PHONE HANDOFF ── */}
        {tab === "handoff" && <PhoneHandoffTab addLog={addLog} handleRisk={handleRisk} />}

        {/* ── THREAT INTEL ── */}
        {tab === "intel" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 20, animation: "fadeInUp .4s ease-out" }}>
            <Card accent="var(--red)" style={{ padding: "28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,45,85,0.5)", letterSpacing: "0.3em", marginBottom: 20 }}>THREAT_VECTORS · 7 SIMULATED</div>
              {[
                { icon: "🎣", label: "Phishing Link", desc: "Fake login page credential harvesting", level: "MEDIUM", c: "var(--gold)" },
                { icon: "📎", label: "Suspicious Download", desc: "Malicious file download from unknown source", level: "HIGH", c: "var(--orange)" },
                { icon: "🔐", label: "Fake Login", desc: "Credential theft via spoofed portal", level: "HIGH", c: "var(--orange)" },
                { icon: "📞", label: "Social Engineering", desc: "OTP/credential sharing with impersonator", level: "HIGH", c: "var(--orange)" },
                { icon: "📧", label: "Malicious Attachment", desc: "Executable disguised as document", level: "CRITICAL", c: "var(--red)" },
                { icon: "📤", label: "Data Exfiltration", desc: "Unauthorized file upload/transfer", level: "CRITICAL", c: "var(--red)" },
                { icon: "🚪", label: "Unauthorized Access", desc: "Privilege escalation attempt", level: "CRITICAL", c: "var(--red)" },
              ].map(({ icon, label, desc, level, c }, i) => (
                <div key={i} style={{ display: "flex", gap: 12, padding: "10px 0", borderBottom: "0.5px solid rgba(255,255,255,0.04)", animation: `fadeInUp .4s ease-out ${i * .06}s both` }}>
                  <span style={{ color: c, fontSize: 16, flexShrink: 0 }}>{icon}</span>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontFamily: "var(--font-body)", fontSize: 12, fontWeight: 600, color: "rgba(255,255,255,0.8)" }}>{label}</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.22)" }}>{desc}</div>
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 8, color: c, padding: "3px 7px", background: `${c}11`, borderRadius: 4, alignSelf: "center", whiteSpace: "nowrap" }}>{level}</div>
                </div>
              ))}
            </Card>
            <Card accent="var(--cyan)" style={{ padding: "28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.22)", letterSpacing: "0.3em", marginBottom: 16 }}>LIVE SECURITY FEED</div>
              <LogFeed logs={logs} />
            </Card>
          </div>
        )}

        {/* ── SHADOW ENV TAB ── */}
        {tab === "shadow" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 20, animation: "fadeInUp .4s ease-out" }}>
            <Card accent="var(--red)" glow style={{ padding: "28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,45,85,0.5)", letterSpacing: "0.3em", marginBottom: 20 }}>🪤 CANARY TOKEN VAULT</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.18)", marginBottom: 14 }}>5 decoy files seeded. Click any to simulate intruder access:</div>
              {engine.decoyFiles.map((f, i) => (
                <div key={f.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "11px 14px", marginBottom: 8, background: f.accessed ? "rgba(255,45,85,0.1)" : "rgba(255,255,255,0.03)", borderRadius: 8, border: `0.5px solid ${f.accessed ? "rgba(255,45,85,0.3)" : "rgba(255,255,255,0.08)"}`, cursor: "pointer", transition: "all .2s", animation: `fadeInUp .4s ease-out ${i * .07}s both` }}
                  onClick={() => { engine.triggerCanary(f.id); addLog(`CANARY_TRIGGERED · ${f.name}`, "threat"); setThreatCount(p => p + 1); handleRisk(25, "UNAUTHORIZED_ACCESS", `CANARY_ACCESS_ATTEMPT · ${f.name}`); }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: f.accessed ? "var(--red)" : "rgba(255,255,255,0.5)" }}>{f.accessed ? "🔔 " : ""}{f.name}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: f.accessed ? "var(--red)" : "rgba(255,255,255,0.2)", padding: "3px 8px", background: f.accessed ? "rgba(255,45,85,0.1)" : "transparent", borderRadius: 4 }}>{f.accessed ? "TRIGGERED" : "ARMED"}</span>
                </div>
              ))}
            </Card>
            <Card accent="var(--purple)" style={{ padding: "28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(191,90,242,0.5)", letterSpacing: "0.3em", marginBottom: 20 }}>🪤 HONEYPOT TRAPS</div>
              {engine.honeypotTraps.map((trap, i) => (
                <div key={trap.selector} style={{ padding: "14px", marginBottom: 10, background: "rgba(191,90,242,0.04)", borderRadius: 10, border: `0.5px solid ${trap.triggered ? "rgba(255,45,85,0.3)" : "rgba(191,90,242,0.12)"}`, cursor: "pointer", transition: "all .2s", animation: `fadeInUp .4s ease-out ${i * .08}s both` }}
                  onClick={() => { engine.triggerHoneypot(trap.selector); addLog(`HONEYPOT_TRIGGERED · ${trap.label}`, "threat"); setThreatCount(p => p + 1); handleRisk(30, "UNAUTHORIZED_ACCESS", `HONEYPOT_TRAP_TRIGGERED · ${trap.label}`); }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <span style={{ fontFamily: "var(--font-body)", fontSize: 13, fontWeight: 600, color: trap.triggered ? "var(--red)" : "rgba(191,90,242,0.8)" }}>{trap.label}</span>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: trap.triggered ? "var(--red)" : "rgba(191,90,242,0.4)" }}>{trap.triggered ? "⚠ TRIGGERED" : "ARMED"}</span>
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.2)" }}>
                    {trap.triggered ? `Triggered at ${trap.triggerTime?.slice(11, 19)}` : "Click to simulate intruder interaction"}
                  </div>
                </div>
              ))}
            </Card>
            <Card accent="var(--gold)" style={{ padding: "28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,214,10,0.5)", letterSpacing: "0.3em", marginBottom: 20 }}>📋 FORENSIC LOG</div>
              <div style={{ height: 280, overflowY: "auto", display: "flex", flexDirection: "column", gap: 4 }}>
                {engine.forensicLog.length === 0
                  ? <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.12)", textAlign: "center", padding: "40px 0" }}>No forensic events yet.<br />Trigger canaries or honeypots above.</div>
                  : engine.forensicLog.map((e, i) => (
                    <div key={i} style={{ padding: "8px 12px", background: "rgba(255,214,10,0.05)", borderRadius: 6, border: "0.5px solid rgba(255,214,10,0.1)", animation: "fadeInUp .3s ease-out" }}>
                      <div style={{ fontFamily: "var(--font-display)", fontSize: 10, color: "var(--gold)", fontWeight: 700, marginBottom: 3 }}>{e.event}</div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.3)" }}>
                        {e.token || e.trap || e.target || ""} · {e.time?.slice(11, 19) || e.time}
                      </div>
                    </div>
                  ))}
              </div>
            </Card>
          </div>
        )}

        {/* ── CYBER COACH ── */}
        {tab === "coach" && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))", gap: 20, animation: "fadeInUp .4s ease-out" }}>
            <Card accent="var(--cyan)" glow style={{ padding: "32px 28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.22)", letterSpacing: "0.3em", marginBottom: 20 }}>CYBER_RESILIENCE_SCORE</div>
              <div style={{ display: "flex", alignItems: "center", gap: 24, marginBottom: 28 }}>
                <Ring value={resilience} color="var(--cyan)" size={120} label="RESILIENCE" />
                <div>
                  <div style={{ fontFamily: "var(--font-display)", fontSize: 28, fontWeight: 900, color: "var(--cyan)" }}>{resilience}</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.3)" }}>/ 100 points</div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--green)", marginTop: 6 }}>{threatCount} threats blocked</div>
                </div>
              </div>
              {[
                { title: "Phishing Awareness", desc: "Always verify sender email addresses. Hover over links before clicking. Legitimate companies never ask for credentials via email.", pts: 20 },
                { title: "Social Engineering", desc: "Never share OTPs, passwords, or sensitive info over phone/email. Verify caller identity through official channels.", pts: 25 },
                { title: "Safe Downloads", desc: "Only download files from trusted sources. Be wary of unexpected attachments, even from known senders.", pts: 20 },
                { title: "Email Security", desc: "Block suspicious domains. Use email blocklist to prevent contact from known threat actors.", pts: 20 },
                { title: "Phone Handoff Safety", desc: "Always activate Handoff Mode before giving your phone to someone. Review access logs afterward.", pts: 20 },
                { title: "Shadow Env Defense", desc: "Canary tokens in decoy files silently report intruder actions. Honeypot traps capture forensic evidence.", pts: 30 },
              ].map((l, i) => (
                <div key={i} style={{ padding: "14px", marginBottom: 10, background: "rgba(0,245,255,0.04)", borderRadius: 10, border: "0.5px solid rgba(0,245,255,0.1)", animation: `fadeInUp .4s ease-out ${i * .1}s both` }}>
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 6 }}>
                    <div style={{ fontFamily: "var(--font-body)", fontSize: 13, fontWeight: 600, color: "rgba(255,255,255,0.8)" }}>{l.title}</div>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--cyan)" }}>+{l.pts} pts</div>
                  </div>
                  <div style={{ fontFamily: "var(--font-body)", fontSize: 12, color: "rgba(255,255,255,0.38)", lineHeight: 1.6 }}>{l.desc}</div>
                </div>
              ))}
            </Card>
            <Card accent="var(--cyan)" style={{ padding: "32px 28px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.22)", letterSpacing: "0.3em", marginBottom: 20 }}>TECH_STACK · v3.1</div>
              {[
                ["DNA Engine", "LSTM Networks", "Time-series keystroke analysis (monitoring only)"],
                ["Email Guard", "Block Engine", "Address + domain filtering"],
                ["Handoff Monitor", "Access Auditor", "Per-app access logging"],
                ["Isolation", "MicroVM Container", "Instant threat quarantine fork"],
                ["Privacy", "Federated Learning", "Data never leaves the device"],
                ["Deception", "VFS + Canary Tokens", "Attacker redirection & trace"],
                ["Honeypot", "Psych UI Traps", "Intruder interaction forensics"],
                ["Counter-Intel", "Misinfo Payload", "Disinformation on intruder"],
                ["Forensics", "Crypto Signing", "Admissible digital evidence"],
              ].map(([layer, tech, detail], i) => (
                <div key={i} style={{ display: "grid", gridTemplateColumns: "0.8fr 1fr 1.2fr", gap: 8, padding: "9px 0", borderBottom: "0.5px solid rgba(255,255,255,0.04)", animation: `fadeInUp .4s ease-out ${i * .05}s both` }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "rgba(255,255,255,0.28)" }}>{layer}</span>
                  <span style={{ fontFamily: "var(--font-display)", fontSize: 10, color: "var(--cyan)", fontWeight: 700 }}>{tech}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 9, color: "rgba(255,255,255,0.22)" }}>{detail}</span>
                </div>
              ))}
            </Card>
          </div>
        )}
      </main>

      {/* REALISTIC THREAT SIMULATION BAR */}
      <SimulationBar addLog={addLog} handleRisk={handleRisk} />
    </div>
  );
}

/* ─── ROOT ─── */
export default function Root() {
  const [consented, setConsented] = useState(false);

  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = GLOBAL_CSS;
    document.head.appendChild(style);
    return () => document.head.removeChild(style);
  }, []);

  if (!consented) return <ConsentGate onConsent={() => setConsented(true)} />;
  return <Dashboard />;
}