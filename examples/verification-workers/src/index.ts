import {
	Directory,
	VerificationParams,
	helpers,
	jwkToKeyID,
	verify,
} from "web-bot-auth";
import { invalidHTML, neutralHTML, validHTML } from "./html";
import jwk from "../../rfc9421-keys/ed25519.json" assert { type: "json" };

const getDirectory = async (): Promise<Directory> => {
	const key = {
		kid: await jwkToKeyID(
			jwk,
			helpers.WEBCRYPTO_SHA256,
			helpers.BASE64URL_DECODE
		),
		kty: jwk.kty,
		crv: jwk.crv,
		x: jwk.x,
		nbf: new Date("2025-04-01").getTime(),
	};
	return {
		keys: [key],
		purpose: "rag",
	};
};

async function verifyEd25519(
	data: string,
	signature: Uint8Array,
	params: VerificationParams
) {
	// note that here we use getDirectory, but this is as simple as a fetch
	const directory = await getDirectory();

	const key = await crypto.subtle.importKey(
		"jwk",
		directory.keys[0],
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
	);

	if (!isValid) {
		throw new Error("invalid signature");
	}
}

export default {
	async fetch(request, env, ctx): Promise<Response> {
		const url = new URL(request.url);

		if (url.pathname.startsWith("/debug")) {
			return new Response(
				[...request.headers]
					.map(([key, value]) => `${key}: ${value}`)
					.join("\n")
			);
		}

		if (
			url.pathname.startsWith("/.well-known/http-message-signatures-directory")
		) {
			return new Response(JSON.stringify(await getDirectory()), {
				headers: {
					"content-type": "application/http-message-signatures-directory",
				},
			});
		}

		if (request.headers.get("Signature") === null) {
			return new Response(neutralHTML, {
				headers: { "content-type": "text/html" },
			});
		}

		try {
			await verify(request, verifyEd25519);
		} catch (e) {
			console.error(e);
			return new Response(invalidHTML, {
				headers: { "content-type": "text/html" },
			});
		}
		return new Response(validHTML, {
			headers: { "content-type": "text/html" },
		});
	},
} satisfies ExportedHandler<Env>;
