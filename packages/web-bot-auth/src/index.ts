import { Component, Directory as HTTPMessageSignaturesDirectory, RequestLike, ResponseLike, SignatureHeaders, Signer, SignerSync, signatureHeaders as httpsigSignatureHeaders, signatureHeadersSync as httpsigSignatureHeadersSync } from 'httpsig';
// export { HTTP_MESSAGE_SIGNATURES_DIRECTORY, MediaType } from 'httpsig';
export { jwkThumbprint as jwkToKeyID } from 'jsonwebkey-thumbprint';

export const REQUEST_COMPONENTS: Component[] = ['@authority'];

export function signatureHeaders<T extends RequestLike | ResponseLike>(message: T, signer: Signer): Promise<SignatureHeaders> {
    return httpsigSignatureHeaders(message, { signer, components: REQUEST_COMPONENTS })
}

export function signatureHeadersSync<T extends RequestLike | ResponseLike>(message: T, signer: SignerSync): SignatureHeaders {
    return httpsigSignatureHeadersSync(message, { signer, components: REQUEST_COMPONENTS })
}

export interface Directory extends HTTPMessageSignaturesDirectory {
    purpose: string;
}