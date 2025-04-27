// test/index.spec.ts
import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src/index";

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

const sampleURL = "https://example.com";

describe("/ endpoint", () => {
	it("responds with HTTP 200", async () => {
		const request = new IncomingRequest(sampleURL);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);
		expect(response.status).toEqual(200);
	});
});

describe("/debug endpoint", () => {
	it("responds with request headers", async () => {
		const headers = { test: "this is a test header" };
		const request = new Request(`${sampleURL}/debug`, { headers });
		const response = await SELF.fetch(request);
		const headersString = Object.entries(headers)
			.map(([k, v]) => `${k}: ${v}`)
			.join("\n");
		expect(await response.text()).toMatch(headersString);
	});
});
