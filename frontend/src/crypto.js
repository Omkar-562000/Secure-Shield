function toBase64Url(bytes) {
  const chunkSize = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

export async function encryptBytes(rawBytes) {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["encrypt"]);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, cryptoKey, rawBytes);
  return {
    payload: `${toBase64Url(iv)}.${toBase64Url(new Uint8Array(encrypted))}`,
    decryptionKey: toBase64Url(keyBytes)
  };
}

export async function decryptPayload(payload, keyText) {
  const parts = payload.split(".");
  if (parts.length !== 2) {
    throw new Error("Invalid encrypted payload.");
  }
  const iv = fromBase64Url(parts[0]);
  const cipherBytes = fromBase64Url(parts[1]);
  const keyBytes = fromBase64Url(keyText);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, cipherBytes);
  return new Uint8Array(decrypted);
}

export function utf8Bytes(text) {
  return new TextEncoder().encode(text);
}
