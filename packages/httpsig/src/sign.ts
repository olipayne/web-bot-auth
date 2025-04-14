import {
  Component,
  Parameters,
  RequestLike,
  ResponseLike,
  SignOptions,
  SignSyncOptions,
} from './types';
import { buildSignatureInputString, buildSignedData } from './build';
import { encode as base64Encode } from './base64';

const defaultRequestComponents: Component[] = ['@method', '@path', '@query', '@authority', 'content-type', 'digest'];
const defaultResponseComponents: Component[] = ['@status', 'content-type', 'digest'];

export async function sign<T extends RequestLike | ResponseLike>(message: T, opts: SignOptions): Promise<T> {
  const { signer, components: _components, key: _key, ...params } = opts;

  const components = _components ?? ('status' in message ? defaultResponseComponents : defaultRequestComponents);
  const key = _key ?? 'sig1';

  const signParams: Parameters = {
    created: new Date(),
    keyid: signer.keyid,
    alg: signer.alg,
    ...(params as Parameters),
  };

  const signatureInputString = buildSignatureInputString(components, signParams);
  const dataToSign = buildSignedData(message, components, signatureInputString);

  const signature = await signer.sign(dataToSign);
  const sigBase64 = base64Encode(signature);

  if (typeof message.headers.set === 'function') {
    message.headers.set('Signature', `${key}=:${sigBase64}:`);
    message.headers.set('Signature-Input', `${key}=${signatureInputString}`);
  } else {
    message.headers['Signature'] = `${key}=:${sigBase64}:`;
    message.headers['Signature-Input'] = `${key}=${signatureInputString}`;
  }

  return message;
}

export function signatureHeadersSync<T extends RequestLike | ResponseLike>(message: T, opts: SignSyncOptions) {
  const { signer, components: _components, key: _key, ...params } = opts;

  const components = _components ?? ('status' in message ? defaultResponseComponents : defaultRequestComponents);
  const key = _key ?? 'sig1';

  const signParams: Parameters = {
    created: new Date(),
    keyid: signer.keyid,
    alg: signer.alg,
    ...(params as Parameters),
  };

  const signatureInputString = buildSignatureInputString(components, signParams);
  const dataToSign = buildSignedData(message, components, signatureInputString);

  const signature = signer.signSync(dataToSign);
  const sigBase64 = base64Encode(signature);

  return { 'Signature': `${key}=:${sigBase64}:`, 'Signature-Input': `${key}=${signatureInputString}` };
}
