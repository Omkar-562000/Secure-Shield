const form = document.getElementById("create-secret-form");
const contentKindSelect = document.getElementById("content-kind");
const textWrap = document.getElementById("text-wrap");
const fileWrap = document.getElementById("file-wrap");
const secretInput = document.getElementById("secret-text");
const fileInput = document.getElementById("secret-file");
const dropZone = document.getElementById("drop-zone");
const fileMeta = document.getElementById("file-meta");
const expiresSelect = document.getElementById("expires-minutes");
const maxViewsSelect = document.getElementById("max-views");
const createButton = document.getElementById("create-btn");
const statusEl = document.getElementById("status");
const resultPanel = document.getElementById("result-panel");
const shareUrlEl = document.getElementById("share-url");
const shareCodeEl = document.getElementById("share-code");
const copyLinkButton = document.getElementById("copy-link-btn");
const copyCodeButton = document.getElementById("copy-code-btn");

const MAX_FILE_BYTES = 12 * 1024 * 1024;
let selectedFile = null;

function setStatus(message, level = "") {
    statusEl.textContent = message;
    statusEl.className = `status ${level}`.trim();
}

function toBase64Url(bytes) {
    const chunkSize = 0x8000;
    let binary = "";
    for (let i = 0; i < bytes.length; i += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function utf8Bytes(text) {
    return new TextEncoder().encode(text);
}

async function encryptBytes(rawBytes) {
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        rawBytes
    );

    const cipherBytes = new Uint8Array(encrypted);
    return {
        payload: `${toBase64Url(iv)}.${toBase64Url(cipherBytes)}`,
        decryptionKey: toBase64Url(keyBytes)
    };
}

function resetFileSelection() {
    selectedFile = null;
    fileInput.value = "";
    fileMeta.textContent = "";
}

function showSelectedFile(file) {
    if (!file) {
        resetFileSelection();
        return;
    }
    selectedFile = file;
    fileMeta.textContent = `Selected: ${file.name} (${Math.ceil(file.size / 1024)} KB)`;
}

function switchMode() {
    const mode = contentKindSelect.value;
    const isText = mode === "text";
    textWrap.classList.toggle("hidden", !isText);
    fileWrap.classList.toggle("hidden", isText);
    if (isText) {
        resetFileSelection();
    }
}

fileInput.addEventListener("change", () => {
    showSelectedFile(fileInput.files?.[0] || null);
});

dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropZone.classList.add("drop-zone-active");
});

dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("drop-zone-active");
});

dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.classList.remove("drop-zone-active");
    const file = event.dataTransfer?.files?.[0] || null;
    showSelectedFile(file);
});

contentKindSelect.addEventListener("change", switchMode);

async function getEncryptedPayload() {
    const contentKind = contentKindSelect.value;
    if (contentKind === "text") {
        const secretValue = secretInput.value.trim();
        if (!secretValue) {
            throw new Error("Secret text is required.");
        }
        const encrypted = await encryptBytes(utf8Bytes(secretValue));
        return {
            encrypted,
            meta: {
                content_kind: "text",
                mime_type: "text/plain",
                filename: "",
                file_size: 0
            }
        };
    }

    if (!selectedFile) {
        throw new Error("Select an image or video file.");
    }
    if (!(selectedFile.type.startsWith("image/") || selectedFile.type.startsWith("video/"))) {
        throw new Error("Only image and video files are supported.");
    }
    if (selectedFile.size > MAX_FILE_BYTES) {
        throw new Error("File too large. Maximum is 12 MB.");
    }

    const rawBytes = new Uint8Array(await selectedFile.arrayBuffer());
    const encrypted = await encryptBytes(rawBytes);
    return {
        encrypted,
        meta: {
            content_kind: "file",
            mime_type: selectedFile.type,
            filename: selectedFile.name,
            file_size: selectedFile.size
        }
    };
}

async function createSecret(event) {
    event.preventDefault();
    setStatus("");
    resultPanel.classList.add("hidden");

    createButton.disabled = true;
    createButton.textContent = "Encrypting...";

    try {
        const payloadInfo = await getEncryptedPayload();
        createButton.textContent = "Uploading...";

        const response = await fetch("/api/secrets", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                ciphertext: payloadInfo.encrypted.payload,
                expires_minutes: Number(expiresSelect.value),
                max_views: Number(maxViewsSelect.value),
                content_kind: payloadInfo.meta.content_kind,
                mime_type: payloadInfo.meta.mime_type,
                filename: payloadInfo.meta.filename,
                file_size: payloadInfo.meta.file_size
            })
        });

        const body = await response.json();
        if (!response.ok) {
            if (response.status === 401) {
                window.location.href = "/login";
                return;
            }
            throw new Error(body.error || "Failed to create share.");
        }

        const shareUrl = `${window.location.origin}/secret/${body.secret_id}#k=${payloadInfo.encrypted.decryptionKey}`;
        shareUrlEl.value = shareUrl;
        shareCodeEl.value = body.access_code;
        resultPanel.classList.remove("hidden");
        setStatus("Secure link and code generated.", "ok");
        secretInput.value = "";
        resetFileSelection();
    } catch (error) {
        setStatus(error.message || "Could not create secure share.", "error");
    } finally {
        createButton.disabled = false;
        createButton.textContent = "Create Secure Link";
    }
}

async function copyTextFrom(inputEl, label) {
    if (!inputEl.value) {
        return;
    }
    await navigator.clipboard.writeText(inputEl.value);
    setStatus(`${label} copied to clipboard.`, "ok");
}

form.addEventListener("submit", createSecret);
copyLinkButton.addEventListener("click", () => copyTextFrom(shareUrlEl, "Link"));
copyCodeButton.addEventListener("click", () => copyTextFrom(shareCodeEl, "Code"));
switchMode();
