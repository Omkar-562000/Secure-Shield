import { useEffect, useMemo, useState } from "react";
import { Link, Navigate, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { apiRequest } from "./api";
import { decryptPayload, encryptBytes, utf8Bytes } from "./crypto";

const MAX_FILE_BYTES = 12 * 1024 * 1024;

function App() {
  const [auth, setAuth] = useState({ loading: true, user: null });

  useEffect(() => {
    apiRequest("/api/auth/me")
      .then((body) => setAuth({ loading: false, user: body.authenticated ? body.user : null }))
      .catch(() => setAuth({ loading: false, user: null }));
  }, []);

  const authValue = useMemo(() => ({ auth, setAuth }), [auth]);

  if (auth.loading) {
    return <div className="shell"><div className="container">Loading...</div></div>;
  }

  return (
    <div className="shell">
      <div className="container">
        <TopNav authValue={authValue} />
        <Routes>
          <Route path="/" element={<RequireAuth authValue={authValue}><Dashboard /></RequireAuth>} />
          <Route path="/login" element={<Login authValue={authValue} />} />
          <Route path="/signup" element={<Signup authValue={authValue} />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/secret/:secretId" element={<Reveal />} />
          <Route path="*" element={<Navigate to={auth.user ? "/" : "/login"} replace />} />
        </Routes>
      </div>
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
    <div className="nav">
      {user && <Link to="/">Create Share</Link>}
      <Link to="/secret/demo">Reveal</Link>
      {!user && <Link to="/login">Login</Link>}
      {!user && <Link to="/signup">Signup</Link>}
      {user && <button type="button" onClick={logout}>Logout</button>}
    </div>
  );
}

function RequireAuth({ authValue, children }) {
  if (!authValue.auth.user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

function Login({ authValue }) {
  const navigate = useNavigate();
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [form, setForm] = useState({ email: "", password: "" });

  async function onSubmit(event) {
    event.preventDefault();
    setStatus("Logging in...");
    setError("");
    try {
      const body = await apiRequest("/api/auth/login", { method: "POST", body: JSON.stringify(form) });
      authValue.setAuth({ loading: false, user: body.user });
      navigate("/");
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  return (
    <section>
      <h1>Login</h1>
      <form onSubmit={onSubmit}>
        <input placeholder="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <input type="password" placeholder="Password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <button type="submit">Login</button>
      </form>
      <p className="status ok">{status}</p>
      <p className="status error">{error}</p>
      <Link to="/forgot-password">Forgot password?</Link>
    </section>
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
      navigate("/");
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  return (
    <section>
      <h1>Signup</h1>
      <form onSubmit={onSubmit}>
        <input placeholder="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <input placeholder="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <input type="password" placeholder="Password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        <button type="submit">Create account</button>
      </form>
      <p className="status ok">{status}</p>
      <p className="status error">{error}</p>
    </section>
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
    <section>
      <h1>Forgot Password</h1>
      <form onSubmit={onSubmit}>
        <input placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
        <button type="submit">Send reset code</button>
      </form>
      <p className="status ok">{status}</p>
      <p className="status error">{error}</p>
      <Link to="/reset-password">Have code? Reset now</Link>
    </section>
  );
}

function ResetPassword() {
  const [form, setForm] = useState({ email: "", code: "", new_password: "" });
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  async function onSubmit(event) {
    event.preventDefault();
    setStatus("Resetting password...");
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
    <section>
      <h1>Reset Password</h1>
      <form onSubmit={onSubmit}>
        <input placeholder="Email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
        <input placeholder="6-digit code" value={form.code} onChange={(e) => setForm({ ...form, code: e.target.value })} />
        <input type="password" placeholder="New password" value={form.new_password} onChange={(e) => setForm({ ...form, new_password: e.target.value })} />
        <button type="submit">Reset password</button>
      </form>
      <p className="status ok">{status}</p>
      <p className="status error">{error}</p>
      <Link to="/login">Back to login</Link>
    </section>
  );
}

function Dashboard() {
  const [contentKind, setContentKind] = useState("text");
  const [secretText, setSecretText] = useState("");
  const [file, setFile] = useState(null);
  const [expiresMinutes, setExpiresMinutes] = useState(60);
  const [maxViews, setMaxViews] = useState(1);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [result, setResult] = useState({ url: "", code: "" });

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
    setStatus("Encrypting and uploading...");
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
      setStatus("Secure link and code generated.");
      setSecretText("");
      setFile(null);
    } catch (err) {
      setError(err.message);
      setStatus("");
    }
  }

  return (
    <section>
      <h1>Create Secure Share</h1>
      <form onSubmit={onSubmit}>
        <select value={contentKind} onChange={(e) => setContentKind(e.target.value)}>
          <option value="text">Text / Credentials</option>
          <option value="file">Photo / Video</option>
        </select>
        {contentKind === "text" ? (
          <textarea placeholder="Secret text..." value={secretText} onChange={(e) => setSecretText(e.target.value)} />
        ) : (
          <input type="file" accept="image/*,video/*" onChange={(e) => setFile(e.target.files?.[0] || null)} />
        )}
        <div className="row">
          <select value={expiresMinutes} onChange={(e) => setExpiresMinutes(Number(e.target.value))}>
            <option value={30}>30 minutes</option>
            <option value={60}>1 hour</option>
            <option value={240}>4 hours</option>
            <option value={1440}>1 day</option>
            <option value={10080}>7 days</option>
          </select>
          <select value={maxViews} onChange={(e) => setMaxViews(Number(e.target.value))}>
            <option value={1}>1 view</option>
            <option value={2}>2 views</option>
            <option value={3}>3 views</option>
          </select>
        </div>
        <button type="submit">Create Secure Link</button>
      </form>
      <p className="status ok">{status}</p>
      <p className="status error">{error}</p>

      {result.url && (
        <div className="panel">
          <p>Share URL</p>
          <textarea readOnly value={result.url} />
          <p>6-digit access code</p>
          <input readOnly value={result.code} />
        </div>
      )}
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
    <section>
      <h1>Reveal Secret</h1>
      <input
        value={code}
        onChange={(e) => setCode(e.target.value)}
        maxLength={6}
        inputMode="numeric"
        placeholder="6-digit access code"
      />
      <div className="actions">
        <button type="button" onClick={onUnlock}>Unlock Content</button>
      </div>
      <p className="status ok">{status}</p>
      <p className="status error">{error}</p>

      {text && (
        <div className="panel">
          <p>Decrypted text</p>
          <textarea readOnly value={text} />
        </div>
      )}

      {fileInfo.url && (
        <div className="panel">
          <p>Decrypted file</p>
          {fileInfo.mime.startsWith("image/") && <img className="media-preview" src={fileInfo.url} alt="preview" />}
          {fileInfo.mime.startsWith("video/") && <video className="media-preview" src={fileInfo.url} controls />}
          <a href={fileInfo.url} download={fileInfo.filename}>Download file</a>
        </div>
      )}
    </section>
  );
}

export default App;
