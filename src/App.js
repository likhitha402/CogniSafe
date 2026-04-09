import { useState, useEffect, useRef } from "react";

// 🔥 CHANGE THIS IF USING DIFFERENT DEVICE
const BACKEND_URL = "http://localhost:5000/analyze";

export default function App() {

  const [page, setPage] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [balance, setBalance] = useState(25000);
  const [amt, setAmt] = useState("");
  const [note, setNote] = useState("");

  const [risk, setRisk] = useState(0);
  const [action, setAction] = useState("ALLOW");
  const [alertMsg, setAlertMsg] = useState("");
  const [showOTP, setShowOTP] = useState(false);

  const keystrokes = useRef([]);
  const mouseData = useRef([]);
  const lastActivity = useRef(Date.now());

  // -------- API CALL --------
  const sendToBackend = async (event = "pulse") => {
    try {
      const res = await fetch(BACKEND_URL, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          event,
          keystrokes: keystrokes.current,
          mouse: mouseData.current,
          idle: Date.now() - lastActivity.current,
          note
        })
      });

      const data = await res.json();

      setRisk(data.risk);
      setAction(data.action);

      if (data.action === "BLOCK") {
        setAlertMsg("🚫 Blocked by CogniSafe");
        setShowOTP(true);
      }

      if (data.action === "LOCK") {
        setAlertMsg("🔒 Account Locked");
        setPage("login");
      }

      keystrokes.current = [];
      mouseData.current = [];

    } catch (err) {
      console.log("Backend not reachable");
    }
  };

  // -------- BEHAVIOR TRACKING --------
  useEffect(() => {

    const key = () => {
      keystrokes.current.push({ t: Date.now() });
      lastActivity.current = Date.now();
    };

    const mouse = (e) => {
      mouseData.current.push({
        x: e.clientX,
        y: e.clientY,
        t: Date.now()
      });
      lastActivity.current = Date.now();
    };

    document.addEventListener("keydown", key);
    document.addEventListener("mousemove", mouse);

    const interval = setInterval(() => {
      sendToBackend();
    }, 2000);

    return () => {
      document.removeEventListener("keydown", key);
      document.removeEventListener("mousemove", mouse);
      clearInterval(interval);
    };

  }, []);

  // -------- LOGIN --------
  const login = () => {
    sendToBackend("login_attempt");

    if (email && password.length >= 5) {
      setPage("dashboard");
      setAlertMsg("✅ Login success");
    } else {
      setAlertMsg("❌ Invalid credentials");
    }
  };

  // -------- TRANSFER --------
  const transfer = () => {
    sendToBackend("transfer");

    const amount = parseFloat(amt);

    if (amount > 5000) {
      setAlertMsg("⚠️ Suspicious transfer");
      setShowOTP(true);
      return;
    }

    setBalance(balance - amount);
    setAlertMsg("💸 Transfer successful");
  };

  return (
    <div style={{ padding: 40 }}>
      <h1>🛡️ CogniSafe System</h1>

      <h3>Risk: {risk} | Action: {action}</h3>

      {alertMsg && <p>{alertMsg}</p>}

      {page === "login" && (
        <>
          <input placeholder="Email"
            onChange={(e) => setEmail(e.target.value)} /><br />

          <input type="password"
            placeholder="Password"
            onChange={(e) => setPassword(e.target.value)} /><br />

          <button onClick={login}>Login</button>
        </>
      )}

      {page === "dashboard" && (
        <>
          <h3>Balance: ₹{balance}</h3>

          <input placeholder="Amount"
            onChange={(e) => setAmt(e.target.value)} /><br />

          <input placeholder="Note"
            onChange={(e) => setNote(e.target.value)} /><br />

          <button onClick={transfer}>Transfer</button>
        </>
      )}

      {showOTP && <h3>🔐 OTP Verification Required</h3>}
    </div>
  );
}