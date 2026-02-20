import { useEffect, useMemo, useState } from "react";
import { Link, Navigate, Route, Routes, useLocation, useNavigate, useParams } from "react-router-dom";
import { apiRequest } from "./api";
import { decryptPayload, encryptBytes, utf8Bytes } from "./crypto";

const MAX_FILE_BYTES = 12 * 1024 * 1024;
const THEME_STORAGE_KEY = "secureshield_theme";

function getInitialTheme() {
  const saved = window.localStorage.getItem(THEME_STORAGE_KEY);
  if (saved === "light" || saved === "dark") {
    return saved;
  }
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function App() {
  const [auth, setAuth] = useState({ loading: true, user: null });
  const [theme, setTheme] = useState(getInitialTheme);
  const location = useLocation();

  useEffect(() => {
    apiRequest("/api/auth/me")
      .then((body) => setAuth({ loading: false, user: body.authenticated ? body.user : null }))
      .catch(() => setAuth({ loading: false, user: null }));
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  const authValue = useMemo(() => ({ auth, setAuth }), [auth]);

  if (auth.loading) {
    return (
      <div className="shell">
        <div className="app-frame">
          <p className="eyebrow">SecureShield</p>
          <h1>Preparing workspace...</h1>
        </div>
      </div>
    );
  }

  return (
    <div className="shell">
      <div className="bg bg-a" />
      <div className="bg bg-b" />
      <div className="app-frame">
        <ThemeToggle theme={theme} setTheme={setTheme} />
        {location.pathname !== "/" && <TopNav authValue={authValue} />}
        <Routes>
          <Route path="/" element={<Splash />} />
          <Route path="/app" element={<RequireAuth authValue={authValue}><Dashboard user={auth.user} /></RequireAuth>} />
          <Route path="/login" element={<Login authValue={authValue} />} />
          <Route path="/signup" element={<Signup authValue={authValue} />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/secret/:secretId" element={<Reveal />} />
          <Route path="*" element={<Navigate to={auth.user ? "/app" : "/login"} replace />} />
        </Routes>
      </div>
    </div>
  );
}

function ThemeToggle({ theme, setTheme }) {
  const isDark = theme === "dark";
  return (
    <div className="theme-wrap">
      <span className="theme-label" aria-hidden="true">Sun</span>
      <button
        type="button"
        className={`theme-toggle ${isDark ? "active" : ""}`}
        onClick={() => setTheme(isDark ? "light" : "dark")}
        aria-label={`Switch to ${isDark ? "light" : "dark"} theme`}
      >
        <span className="theme-knob" />
      </button>
      <span className="theme-label" aria-hidden="true">Moon</span>
    </div>
  );
}

function TopNav({ authValue }) {
  const navigate = useNavigate();
  const user = authValue.auth.user;

  async function logout() {
    await apiRequest("/api/auth/logout", { method: "POST", body: "{}" });
    authValue.setAuth({ loading: false, user: null });
    navigate("/login");
  }

  return (
    <header className="topbar">
      <div>
        <p className="eyebrow">Secure sharing platform</p>
        <h2 className="brand">SecureShield</h2>
      </div>
      <nav className="nav">
        <Link to="/app">Dashboard</Link>
        <Link to="/secret/demo">Reveal</Link>
        {!user && <Link to="/login">Login</Link>}
        {!user && <Link to="/signup">Signup</Link>}
        {user && <button type="button" onClick={logout}>Logout</button>}
      </nav>
    </header>
  );
}

function RequireAuth({ authValue, children }) {
  if (!authValue.auth.user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

function Splash() {
  const navigate = useNavigate();

  useEffect(() => {
    const timer = setTimeout(() => navigate("/login", { replace: true }), 1900);
    return () => clearTimeout(timer);
  }, [navigate]);

  return (
    <section className="splash">
      <div className="logo">SS</div>
      <h1>SecureShield</h1>
      <p className="muted">One-time encrypted sharing for sensitive data.</p>
      <div className="progress">
        <div className="progress-fill" />
      </div>
      <p className="tiny">Redirecting to login...</p>
    </section>
  );
}

function StatusMessage({ status, error }) {
  if (!status && !error) {
    return null;
  }
  return (
    <div className={`status-box ${error ? "error" : "ok"}`}>
      {error || status}
    </div>
  );
}

function AuthLayout({ title, subtitle, children, footer }) {
  return (
    <section className="auth-layout">
      <aside className="auth-side">
        <p className="eyebrow">Protected workflow</p>
        <h2>Secure data exchange for daily operations</h2>
        <ul>
          <li>Client-side encryption before upload</li>
          <li>Access code + key-fragment protection</li>
          <li>Expiry and revoke controls</li>
        </ul>
      </aside>
      <section className="auth-card">
        <h1>{title}</h1>
        <p className="muted">{subtitle}</p>
        {children}
        {footer ? <div className="auth-footer">{footer}</div> : null}
      </section>
    </section>
  );
}

function Login({ authValue }) {
  const navigate = useNavigate();
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [form, setForm] = useState({ email: "", password: "" });

  async function onSubmit(event) {
    event.preventDefault();
    setStatus("Signing in...");
    setError("");
    try {
      const body = await apiRequest("/api/auth/login", { method: "POST", body: JSON.stringify(form) });
      authValue.setAuth({ loading: false, user: body.user });
      navigate("/app");
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  return (
    <AuthLayout
      title="Welcome back"
      subtitle="Login to manage secure shares."
      footer={<Link to="/forgot-password">Forgot password?</Link>}
    >
      <form onSubmit={onSubmit}>
        <label>Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
        <label>Password<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
        <button type="submit">Login</button>
      </form>
      <StatusMessage status={status} error={error} />
    </AuthLayout>
  );
}

function Signup({ authValue }) {
  const navigate = useNavigate();
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [form, setForm] = useState({ name: "", email: "", password: "" });

  async function onSubmit(event) {
    event.preventDefault();
    setStatus("Creating account...");
    setError("");
    try {
      const body = await apiRequest("/api/auth/signup", { method: "POST", body: JSON.stringify(form) });
      authValue.setAuth({ loading: false, user: body.user });
      navigate("/app");
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  return (
    <AuthLayout title="Create account" subtitle="Start secure sharing in under a minute.">
      <form onSubmit={onSubmit}>
        <label>Name<input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
        <label>Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
        <label>Password<input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
        <button type="submit">Create account</button>
      </form>
      <StatusMessage status={status} error={error} />
    </AuthLayout>
  );
}

function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  async function onSubmit(event) {
    event.preventDefault();
    setStatus("Sending code...");
    setError("");
    try {
      const body = await apiRequest("/api/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) });
      setStatus(body.reset_code ? `${body.message} Code: ${body.reset_code}` : body.message);
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  return (
    <AuthLayout
      title="Forgot password"
      subtitle="We will send a 6-digit reset code."
      footer={<Link to="/reset-password">Already have a code?</Link>}
    >
      <form onSubmit={onSubmit}>
        <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <button type="submit">Send reset code</button>
      </form>
      <StatusMessage status={status} error={error} />
    </AuthLayout>
  );
}

function ResetPassword() {
  const [form, setForm] = useState({ email: "", code: "", new_password: "" });
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  async function onSubmit(event) {
    event.preventDefault();
    setStatus("Resetting...");
    setError("");
    try {
      const body = await apiRequest("/api/auth/reset-password", { method: "POST", body: JSON.stringify(form) });
      setStatus(body.message);
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  return (
    <AuthLayout
      title="Reset password"
      subtitle="Use your reset code and set a new password."
      footer={<Link to="/login">Back to login</Link>}
    >
      <form onSubmit={onSubmit}>
        <label>Email<input type="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
        <label>6-digit code<input value={form.code} onChange={(e) => setForm({ ...form, code: e.target.value })} /></label>
        <label>New password<input type="password" value={form.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} /></label>
        <button type="submit">Reset password</button>
      </form>
      <StatusMessage status={status} error={error} />
    </AuthLayout>
  );
}

function Dashboard({ user }) {
  const [contentKind, setContentKind] = useState("text");
  const [secretText, setSecretText] = useState("");
  const [file, setFile] = useState(null);
  const [expiresMinutes, setExpiresMinutes] = useState(60);
  const [maxViews, setMaxViews] = useState(1);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState({ url: "", code: "" });
  const [shares, setShares] = useState([]);
  const [loadingShares, setLoadingShares] = useState(true);

  async function loadShares() {
    setLoadingShares(true);
    try {
      const body = await apiRequest("/api/secrets");
      setShares(body.items || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingShares(false);
    }
  }

  useEffect(() => {
    loadShares();
  }, []);

  async function buildPayloadInfo() {
    if (contentKind === "text") {
      const value = secretText.trim();
      if (!value) {
        throw new Error("Secret text is required.");
      }
      const encrypted = await encryptBytes(utf8Bytes(value));
      return {
        encrypted,
        meta: { content_kind: "text", mime_type: "text/plain", filename: "", file_size: 0 }
      };
    }

    if (!file) {
      throw new Error("Select an image or video file.");
    }
    if (!(file.type.startsWith("image/") || file.type.startsWith("video/"))) {
      throw new Error("Only image and video files are supported.");
    }
    if (file.size > MAX_FILE_BYTES) {
      throw new Error("File too large. Maximum is 12 MB.");
    }

    const encrypted = await encryptBytes(new Uint8Array(await file.arrayBuffer()));
    return {
      encrypted,
      meta: {
        content_kind: "file",
        mime_type: file.type,
        filename: file.name,
        file_size: file.size
      }
    };
  }

  async function onSubmit(event) {
    event.preventDefault();
    setStatus("Encrypting and creating share...");
    setError("");
    setResult({ url: "", code: "" });
    try {
      const payloadInfo = await buildPayloadInfo();
      const body = await apiRequest("/api/secrets", {
        method: "POST",
        body: JSON.stringify({
          ciphertext: payloadInfo.encrypted.payload,
          expires_minutes: Number(expiresMinutes),
          max_views: Number(maxViews),
          content_kind: payloadInfo.meta.content_kind,
          mime_type: payloadInfo.meta.mime_type,
          filename: payloadInfo.meta.filename,
          file_size: payloadInfo.meta.file_size
        })
      });
      const shareUrl = `${window.location.origin}/secret/${body.secret_id}#k=${payloadInfo.encrypted.decryptionKey}`;
      setResult({ url: shareUrl, code: body.access_code });
      setStatus("Secure share generated.");
      setSecretText("");
      setFile(null);
      await loadShares();
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  async function revokeShare(revokeUrl) {
    setStatus("Revoking share...");
    setError("");
    try {
      await apiRequest(revokeUrl, { method: "DELETE" });
      setStatus("Share revoked.");
      await loadShares();
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  async function copyValue(value, label) {
    await navigator.clipboard.writeText(value);
    setStatus(`${label} copied to clipboard.`);
  }

  return (
    <section className="dashboard">
      <section className="hero">
        <p className="eyebrow">Hello {user?.name || "User"}</p>
        <h1>Secure transfers for daily operational secrets</h1>
        <p className="muted">Create encrypted shares, track live status, and revoke access instantly.</p>
      </section>

      <section className="dashboard-grid">
        <article className="card">
          <h3>Create secure share</h3>
          <form onSubmit={onSubmit}>
            <label>
              Content type
              <select value={contentKind} onChange={(e) => setContentKind(e.target.value)}>
                <option value="text">Text / Credentials</option>
                <option value="file">Photo / Video</option>
              </select>
            </label>

            {contentKind === "text" ? (
              <label>
                Secret text
                <textarea value={secretText} placeholder="Paste secure content..." onChange={(e) => setSecretText(e.target.value)} />
              </label>
            ) : (
              <label>
                Upload file
                <input type="file" accept="image/*,video/*" onChange={(e) => setFile(e.target.files?.[0] || null)} />
              </label>
            )}

            <div className="row">
              <label>
                Expiry
                <select value={expiresMinutes} onChange={(e) => setExpiresMinutes(Number(e.target.value))}>
                  <option value={30}>30 min</option>
                  <option value={60}>1 hour</option>
                  <option value={240}>4 hours</option>
                  <option value={1440}>1 day</option>
                  <option value={10080}>7 days</option>
                </select>
              </label>
              <label>
                Max views
                <select value={maxViews} onChange={(e) => setMaxViews(Number(e.target.value))}>
                  <option value={1}>1</option>
                  <option value={2}>2</option>
                  <option value={3}>3</option>
                </select>
              </label>
            </div>

            <button type="submit">Generate secure link</button>
          </form>
          <StatusMessage status={status} error={error} />
        </article>

        <aside className="card">
          <h3>Share output</h3>
          {!result.url ? (
            <p className="muted">Generate a share to view link and access code.</p>
          ) : (
            <div className="output">
              <label>
                Secure URL
                <textarea readOnly value={result.url} />
              </label>
              <div className="actions">
                <button type="button" onClick={() => copyValue(result.url, "Link")}>Copy link</button>
              </div>
              <label>
                Access code
                <input readOnly value={result.code} />
              </label>
              <div className="actions">
                <button type="button" onClick={() => copyValue(result.code, "Code")}>Copy code</button>
              </div>
            </div>
          )}
        </aside>
      </section>

      <section className="card">
        <h3>My active shares</h3>
        {loadingShares ? <p className="muted">Loading shares...</p> : null}
        {!loadingShares && shares.length === 0 ? <p className="muted">No active shares.</p> : null}
        {!loadingShares && shares.length > 0 ? (
          <div className="shares-list">
            {shares.map((item) => (
              <article className="share-item" key={item.secret_id}>
                <div>
                  <p className="mono">#{item.secret_id}</p>
                  <p>{item.content_kind === "file" ? `File: ${item.filename || "untitled"}` : "Text secret"}</p>
                  <p>Expires: {new Date(item.expires_at).toLocaleString()}</p>
                  <p>Views left: {item.remaining_views}</p>
                </div>
                <div className="actions">
                  <button type="button" onClick={() => copyValue(`${window.location.origin}/secret/${item.secret_id}`, "Secret page URL")}>Copy page URL</button>
                  <button type="button" onClick={() => revokeShare(item.revoke_url)}>Revoke</button>
                </div>
              </article>
            ))}
          </div>
        ) : null}
      </section>
    </section>
  );
}

function Reveal() {
  const { secretId } = useParams();
  const [code, setCode] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [text, setText] = useState("");
  const [fileInfo, setFileInfo] = useState({ url: "", mime: "", filename: "" });

  function parseHashKey() {
    const hash = window.location.hash.replace(/^#/, "");
    const params = new URLSearchParams(hash);
    return params.get("k") || "";
  }

  function resetFile() {
    if (fileInfo.url) {
      URL.revokeObjectURL(fileInfo.url);
    }
    setFileInfo({ url: "", mime: "", filename: "" });
  }

  async function onUnlock() {
    setStatus("Unlocking...");
    setError("");
    setText("");
    resetFile();
    try {
      const keyText = parseHashKey();
      if (!keyText) {
        throw new Error("Missing decryption key in URL fragment.");
      }
      if (!/^\d{6}$/.test(code.trim())) {
        throw new Error("Enter a valid 6-digit access code.");
      }
      const body = await apiRequest(`/api/secrets/${encodeURIComponent(secretId)}?code=${encodeURIComponent(code.trim())}`);
      const bytes = await decryptPayload(body.ciphertext, keyText);
      if (body.content_kind === "file") {
        const blob = new Blob([bytes], { type: body.mime_type || "application/octet-stream" });
        setFileInfo({
          url: URL.createObjectURL(blob),
          mime: body.mime_type || "",
          filename: body.filename || "secure-file"
        });
      } else {
        setText(new TextDecoder().decode(bytes));
      }
      window.history.replaceState({}, document.title, window.location.pathname);
      setStatus("Content unlocked.");
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  return (
    <section className="card reveal">
      <p className="eyebrow">Receiver access</p>
      <h1>Reveal shared secret</h1>
      <p className="muted">Enter the access code sent by the owner.</p>
      <label>
        Access code
        <input value={code} onChange={(e) => setCode(e.target.value)} maxLength={6} inputMode="numeric" placeholder="6-digit code" />
      </label>
      <div className="actions">
        <button type="button" onClick={onUnlock}>Unlock</button>
      </div>
      <StatusMessage status={status} error={error} />

      {text ? (
        <div className="card subcard">
          <h3>Decrypted text</h3>
          <textarea readOnly value={text} />
        </div>
      ) : null}

      {fileInfo.url ? (
        <div className="card subcard">
          <h3>Decrypted file</h3>
          {fileInfo.mime.startsWith("image/") ? <img className="media-preview" src={fileInfo.url} alt="preview" /> : null}
          {fileInfo.mime.startsWith("video/") ? <video className="media-preview" src={fileInfo.url} controls /> : null}
          <a className="file-link" href={fileInfo.url} download={fileInfo.filename}>Download file</a>
        </div>
      ) : null}
    </section>
  );
}

export default App;
