import { signSync } from 'http-message-signatures';
import _sodium from 'libsodium-wrappers'
import jwk from '../../tests/rfc9421-keys/ed25519.json' assert { type: 'json' }

// THIS SHOULD BE DETERMINISTIC AND BASED ON THE KEY MATERIAL
const KEY_ID = 'test-key-ed25519';
const IDENTIFIERS = ['@authority'];
const MAX_AGE_IN_MS = 1000 * 60 * 60; // 1 hour

class Ed25519Signer {
  public alg = 'ed25519';

  constructor(public keyid: string, private privateKey: Uint8Array<ArrayBuffer>) {
  }

  signSync(data: string): Uint8Array {
    const sodium = _sodium;
    const message = sodium.from_string(data);
    const signedMessage = sodium.crypto_sign(message, this.privateKey);
    return signedMessage.slice(0, sodium.crypto_sign_BYTES);
  }
}

chrome.webRequest.onBeforeSendHeaders.addListener(
  function (details) {
    const sodium = _sodium

    // Base64URL decode helper
    const base64urlDecode = (str) =>
      sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING);

    // Decode keys
    const privateKey = base64urlDecode(jwk.d); // 32 bytes
    const publicKey = base64urlDecode(jwk.x);  // 32 bytes

    // Build the full 64-byte secret key: privateKey || publicKey
    const fullSecretKey = new Uint8Array(64);
    fullSecretKey.set(privateKey);
    fullSecretKey.set(publicKey, 32);

    // eslint-disable-next-line @typescript-eslint/no-non-null-asserted-optional-chain
    const request = new Request(details.url, { method: details.method, headers: details.requestHeaders?.map(h => [h.name, h.value!])! });
    const withSignature = signSync(request, {
      components: IDENTIFIERS,
      signer: new Ed25519Signer(KEY_ID, fullSecretKey),
      created: new Date(Date.now()), // TODO: use details.timestamp
      nonce: Math.floor(Math.random() * 1_000_000).toFixed(0),
      expires: new Date(Date.now() + MAX_AGE_IN_MS),
    });

    details.requestHeaders?.push({
      name: 'Signature',
      value: withSignature.signatureHeader,
    });
    details.requestHeaders?.push({
      name: 'Signature-Input',
      value: withSignature.inputHeader,
    });

    return { requestHeaders: details.requestHeaders };
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);

chrome.runtime.onStartup.addListener(() => {
  console.log(`onStartup()`);
});