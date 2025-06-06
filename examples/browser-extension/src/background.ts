import {
  Algorithm,
  signatureHeadersSync,
  helpers,
  jwkToKeyID,
} from 'web-bot-auth';
import _sodium from 'libsodium-wrappers';
import jwk from '../../rfc9421-keys/ed25519.json' assert { type: 'json' };

const MAX_AGE_IN_MS = 1000 * 60 * 60; // 1 hour

class Ed25519Signer {
  public alg: Algorithm = 'ed25519';
  public keyid: string;
  private privateKey: Uint8Array;

  constructor(jwk: JsonWebKey, keyid: string) {
    const sodium = _sodium;
    const base64urlDecode = (str: string) =>
      sodium.from_base64(str, sodium.base64_variants.URLSAFE_NO_PADDING);

    if (!jwk.d || !jwk.x) {
      throw new Error("Invalid JWK: missing 'd' or 'x' properties.");
    }

    const privateKey = base64urlDecode(jwk.d);
    const publicKey = base64urlDecode(jwk.x);
    const fullSecretKey = new Uint8Array(64);
    fullSecretKey.set(privateKey);
    fullSecretKey.set(publicKey, 32);

    this.privateKey = fullSecretKey;
    this.keyid = keyid;
  }

  signSync(data: string): Uint8Array {
    const sodium = _sodium;
    const message = sodium.from_string(data);
    const signedMessage = sodium.crypto_sign(message, this.privateKey);
    return signedMessage.slice(0, sodium.crypto_sign_BYTES);
  }
}

const EXCLUDED_RESOURCE_TYPES = [
  'stylesheet',
  'script',
  'image',
  'font',
  'object',
  'media',
];

async function initialize() {
  await _sodium.ready;
  const keyId = await jwkToKeyID(
    jwk,
    helpers.WEBCRYPTO_SHA256,
    helpers.BASE64URL_DECODE
  );
  const signer = new Ed25519Signer(jwk, keyId);

  chrome.webRequest.onBeforeSendHeaders.addListener(
    (details) => {
      if (EXCLUDED_RESOURCE_TYPES.includes(details.type)) {
        return { requestHeaders: details.requestHeaders };
      }
      const request = new Request(details.url, {
        method: details.method,
        headers:
          details.requestHeaders?.map((h) => [h.name, h.value ?? '']) ?? [],
      });
      const now = new Date();
      const headers = signatureHeadersSync(request, signer, {
        created: now,
        expires: new Date(now.getTime() + MAX_AGE_IN_MS),
      });

      if (details.requestHeaders) {
        details.requestHeaders.push({
          name: 'Signature',
          value: headers['Signature'],
        });
        details.requestHeaders.push({
          name: 'Signature-Input',
          value: headers['Signature-Input'],
        });
      }

      return { requestHeaders: details.requestHeaders };
    },
    { urls: ['<all_urls>'] },
    ['blocking', 'requestHeaders']
  );

  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (details.responseHeaders) {
        const acah = details.responseHeaders.find(
          (h) => h.name.toLowerCase() === 'access-control-allow-headers'
        );
        if (acah && acah.value) {
          acah.value = `${acah.value}, Signature, Signature-Input`;
        } else {
          details.responseHeaders.push({
            name: 'Access-Control-Allow-Headers',
            value: 'Signature, Signature-Input',
          });
        }
        return { responseHeaders: details.responseHeaders };
      }
    },
    { urls: ['<all_urls>'] },
    ['blocking', 'responseHeaders', 'extraHeaders']
  );

  chrome.runtime.onStartup.addListener(() => {
    console.log(`onStartup()`);
  });

  console.log('Extension initialized.');
}

initialize().catch(console.error);
