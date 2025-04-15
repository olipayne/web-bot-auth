import * as httpsig from 'http-message-sig';
export { HTTP_MESSAGE_SIGNATURES_DIRECTORY, Algorithm, MediaType, SignatureHeaders } from 'http-message-sig';
export { jwkThumbprint as jwkToKeyID } from 'jsonwebkey-thumbprint';

export const HTTP_MESSAGE_SIGNAGURE_TAG = 'web-bot-auth'
export const REQUEST_COMPONENTS: httpsig.Component[] = ['@authority'];

export interface SignatureParams {
    created: Date,
    expires: Date,
    nonce?: string
}

export interface VerificationParams {
    keyid: string,
    created: Date,
    expires: Date,
    tag: typeof HTTP_MESSAGE_SIGNAGURE_TAG,
    nonce?: string,
}

export function signatureHeaders<T extends httpsig.RequestLike | httpsig.ResponseLike>(message: T, signer: httpsig.Signer, params: SignatureParams): Promise<httpsig.SignatureHeaders> {
    if (params.created.getTime() > params.expires.getTime()) {
        throw new Error('created should happen before expires')
    }
    let nonce = params.nonce
    if (!nonce) {
        nonce = Math.floor(Math.random() * 4_294_967_295).toFixed(0)
    } else {
        try {
            parseInt(nonce)
        } catch {
            throw new Error('nonce is not a valid uint32')
        }
    }
    return httpsig.signatureHeaders(message, { signer, components: REQUEST_COMPONENTS, created: params.created, expires: params.expires, nonce, keyid: signer.keyid, tag: HTTP_MESSAGE_SIGNAGURE_TAG })
}

export function signatureHeadersSync<T extends httpsig.RequestLike | httpsig.ResponseLike>(message: T, signer: httpsig.SignerSync, params: SignatureParams): httpsig.SignatureHeaders {
    if (params.created.getTime() > params.expires.getTime()) {
        throw new Error('created should happen before expires')
    }
    let nonce = params.nonce
    if (!nonce) {
        nonce = Math.floor(Math.random() * 4_294_967_295).toFixed(0)
    } else {
        try {
            parseInt(nonce)
        } catch {
            throw new Error('nonce is not a valid uint32')
        }
    }
    return httpsig.signatureHeadersSync(message, { signer, components: REQUEST_COMPONENTS, created: params.created, expires: params.expires, nonce, keyid: signer.keyid, tag: HTTP_MESSAGE_SIGNAGURE_TAG })
}

export type Verify<T> = (data: string, signature: Uint8Array, params: VerificationParams) => T | Promise<T>

export function verify<T>(message: httpsig.RequestLike | httpsig.ResponseLike, verifier: Verify<T>): Promise<T> {
    const v = (data: string, signature: Uint8Array, params: httpsig.Parameters): T | Promise<T> => {
        if (params.tag !== HTTP_MESSAGE_SIGNAGURE_TAG) {
            throw new Error(`tag must be '${HTTP_MESSAGE_SIGNAGURE_TAG}'`)
        }
        if (params.created.getTime() > Date.now()) {
            throw new Error('created in the future')
        }
        if (params.expires.getTime() < Date.now()) {
            throw new Error('signature has expired')
        }
        if (params.keyid === undefined) {
            throw new Error('keyid MUST be defined')
        }
        const vparams: VerificationParams = {
            keyid: params.keyid,
            created: params.created,
            expires: params.expires,
            tag: params.tag,
            nonce: params.nonce,
        }
        return verifier(data, signature, vparams)
    }
    return httpsig.verify(message, v)
}

export interface Directory extends httpsig.Directory {
    purpose: string;
}

export const helpers = {
    WEBCRYPTO_SHA256: (b: BufferSource) => crypto.subtle.digest('SHA-256', b),
    BASE64URL_DECODE: (u: ArrayBuffer) => b64ToB64URL(b64ToB64NoPadding(u8ToB64(new Uint8Array(u))))
}

// Helper functions
const u8ToB64 = (u: Uint8Array) =>
    btoa(String.fromCharCode(...u))

const b64ToB64URL = (s: string) =>
    s.replace(/\+/g, '-').replace(/\//g, '_')

const b64ToB64NoPadding = (s: string) =>
    s.replace(/=/g, '')