const statusEl = document.getElementById("reveal-status");
const accessCodeInput = document.getElementById("access-code");
const unlockButton = document.getElementById("unlock-btn");
const secretWrap = document.getElementById("secret-output-wrap");
const textResult = document.getElementById("text-result");
const fileResult = document.getElementById("file-result");
const secretOutput = document.getElementById("secret-output");
const copySecretButton = document.getElementById("copy-secret-btn");
const imagePreview = document.getElementById("image-preview");
const videoPreview = document.getElementById("video-preview");
const downloadFileButton = document.getElementById("download-file-btn");
const clearContentButton = document.getElementById("clear-content-btn");
const secretId = secretWrap?.dataset?.secretId || "";

let objectUrl = null;

function setStatus(message, level = "") {
    statusEl.textContent = message;
    statusEl.className = `status ${level}`.trim();
}

function fromBase64Url(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function parseHashKey() {
    const hash = window.location.hash.replace(/^#/, "");
    const params = new URLSearchParams(hash);
    return params.get("k") || "";
}

async function decryptPayload(payload, keyText) {
    const parts = payload.split(".");
    if (parts.length !== 2) {
        throw new Error("Invalid encrypted payload.");
    }

    const iv = fromBase64Url(parts[0]);
    const cipherBytes = fromBase64Url(parts[1]);
    const keyBytes = fromBase64Url(keyText);
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        cipherBytes
    );
    return new Uint8Array(decrypted);
}

function resetMediaPreview() {
    if (objectUrl) {
        URL.revokeObjectURL(objectUrl);
        objectUrl = null;
    }
    imagePreview.src = "";
    videoPreview.src = "";
    downloadFileButton.href = "#";
    imagePreview.classList.add("hidden");
    videoPreview.classList.add("hidden");
    textResult.classList.add("hidden");
    fileResult.classList.add("hidden");
}

function showTextContent(bytes) {
    const text = new TextDecoder().decode(bytes);
    secretOutput.textContent = text;
    textResult.classList.remove("hidden");
}

function showFileContent(bytes, mimeType, filename) {
    const blob = new Blob([bytes], { type: mimeType || "application/octet-stream" });
    objectUrl = URL.createObjectURL(blob);

    if (mimeType.startsWith("image/")) {
        imagePreview.src = objectUrl;
        imagePreview.classList.remove("hidden");
    } else if (mimeType.startsWith("video/")) {
        videoPreview.src = objectUrl;
        videoPreview.classList.remove("hidden");
    }

    downloadFileButton.href = objectUrl;
    downloadFileButton.download = filename || "secure-file";
    fileResult.classList.remove("hidden");
}

async function unlockContent() {
    resetMediaPreview();
    setStatus("");

    const code = accessCodeInput.value.trim();
    const keyText = parseHashKey();
    if (!secretId) {
        setStatus("Invalid share URL.", "error");
        return;
    }
    if (!keyText) {
        setStatus("Missing decryption key in URL fragment.", "error");
        return;
    }
    if (!/^\d{6}$/.test(code)) {
        setStatus("Enter a valid 6-digit access code.", "error");
        return;
    }

    unlockButton.disabled = true;
    unlockButton.textContent = "Unlocking...";

    try {
        const response = await fetch(`/api/secrets/${encodeURIComponent(secretId)}?code=${encodeURIComponent(code)}`);
        const body = await response.json();
        if (!response.ok) {
            throw new Error(body.error || "Could not unlock content.");
        }

        const rawBytes = await decryptPayload(body.ciphertext, keyText);
        if (body.content_kind === "file") {
            showFileContent(rawBytes, body.mime_type || "", body.filename || "");
        } else {
            showTextContent(rawBytes);
        }

        secretWrap.classList.remove("hidden");
        setStatus("Content unlocked successfully.", "ok");
        window.history.replaceState({}, document.title, window.location.pathname);
    } catch (error) {
        setStatus(error.message || "Unable to decrypt content.", "error");
    } finally {
        unlockButton.disabled = false;
        unlockButton.textContent = "Unlock Content";
    }
}

async function copySecret() {
    if (!secretOutput.textContent) {
        return;
    }
    await navigator.clipboard.writeText(secretOutput.textContent);
    setStatus("Text copied to clipboard.", "ok");
}

function clearFromScreen() {
    secretOutput.textContent = "";
    accessCodeInput.value = "";
    resetMediaPreview();
    secretWrap.classList.add("hidden");
    setStatus("Cleared from screen.", "ok");
}

unlockButton.addEventListener("click", unlockContent);
copySecretButton.addEventListener("click", copySecret);
clearContentButton.addEventListener("click", clearFromScreen);
