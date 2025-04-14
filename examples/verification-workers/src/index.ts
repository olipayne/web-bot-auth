import { verify, Parameters } from 'http-message-signatures';
import { invalidHTML, neutralHTML, validHTML } from './html';

type Directory = {
	keys: {
		alg: string;
		key: string;
		"not-before"?: number;
		"not-after"?: number;
	}[];
	purpose?: string;
}

const getDirectory = (): Directory => ({
	keys: [{
		// keyid = NFcWBst6DXG-N35nHdzMrioWntdzNZghQSkjHNMMSjw=
		alg: 'ed25519',
		key: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`,
		"not-before": new Date('2025-04-01').getTime()
	}],
	purpose: "rag"
})

const pemToBytes = (pem: string): Uint8Array => {
	const b64Tou8 = (b: string) =>
		Uint8Array.from(atob(b), c => c.charCodeAt(0))

	const b64 = pem
		.replace(/-----BEGIN .* KEY-----/, '')
		.replace(/-----END .* KEY-----/, '')
		.replace(/\s/g, '')
	return b64Tou8(b64)
}

const keyToKeyID = async (key: CryptoKey): Promise<string> => {
	const u8ToB64 = (u: Uint8Array) =>
		btoa(String.fromCharCode(...u))
	const b64ToB64URL = (s: string) =>
		s.replace(/\+/g, '-').replace(/\//g, '_')

	const bytes = await crypto.subtle.exportKey("spki", key) as ArrayBuffer;
	const digest = await crypto.subtle.digest('sha-256', bytes)
	return b64ToB64URL(u8ToB64(new Uint8Array(digest)))
}

async function verifyEd25519(data: string, signature: Uint8Array, params: Parameters) {
	// note that here we use getDirectory, but this is as simple as a fetch
	const publicPEM = getDirectory().keys[0].key

	// const key = await crypto.subtle.importKey(
	// 	"spki",
	// 	pemToBytes(publicPEM),
	// 	{ name: "Ed25519" },
	// 	true,
	// 	["verify"]
	// );

	const key = await crypto.subtle.importKey(
		'jwk',
		{
			"kty": "OKP",
			"crv": "Ed25519",
			// "d": "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",
			"x": "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
		},
		{ name: "Ed25519" },
		true,
		["verify"]
	);

	const encodedData = new TextEncoder().encode(data);

	const isValid = await crypto.subtle.verify(
		{ name: "Ed25519" },
		key,
		signature,
		encodedData
	)

	if (!isValid) {
		throw new Error('invalid signature')
	}
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url)

		if (url.pathname.startsWith('/debug')) {
			return new Response([...request.headers].map(([key, value]) => `${key}: ${value}`).join('\n'));
		}

		if (url.pathname.startsWith('/.well-known/http-message-signatures-directory')) {
			return new Response(JSON.stringify(getDirectory()), { headers: { 'content-type': 'application/http-message-signatures-directory' } })
		}

		if (request.headers.get('Signature') === null) {
			return new Response(neutralHTML, { headers: { 'content-type': 'text/html' } })
		}

		try {
			await verify(request, verifyEd25519)
		} catch (e) {
			console.error(e);
			return new Response(invalidHTML, { headers: { 'content-type': 'text/html' } })
		}
		return new Response(validHTML, { headers: { 'content-type': 'text/html' } })
	},
} satisfies ExportedHandler<Env>;
