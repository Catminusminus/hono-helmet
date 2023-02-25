import { honoHelmet } from "./index";
import { Context } from "hono";

test("default configuration", () => {
	const defaultHeaders = new Map([
		[
			"Content-Security-Policy",
			"default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests",
		],
		["Cross-Origin-Embedder-Policy", "require-corp"],
		["Cross-Origin-Opener-Policy", "same-origin"],
		["Cross-Origin-Resource-Policy", "same-origin"],
		["Referrer-Policy", "no-referrer"],
		["Strict-Transport-Security", "max-age=15552000; includeSubDomains"],
		["X-Content-Type-Options", "nosniff"],
		["Origin-Agent-Cluster", "?1"],
		["X-DNS-Prefetch-Control", "off"],
		["X-Download-Options", "noopen"],
		["X-Frame-Options", "SAMEORIGIN"],
		["X-Permitted-Cross-Domain-Policies", "none"],
		["X-XSS-Protection", "0"],
	]);

	const mock = {
		res: {
			headers: new Map<string, string>(),
		},
	};
	const helmet = honoHelmet();
	helmet(mock as unknown as Context, async () => {}).then(() => {
		expect(mock.res.headers).toEqual(defaultHeaders);
	});
});

test("default configuration without csp", () => {
	const defaultHeadersWithoutCsp = new Map([
		["Cross-Origin-Embedder-Policy", "require-corp"],
		["Cross-Origin-Opener-Policy", "same-origin"],
		["Cross-Origin-Resource-Policy", "same-origin"],
		["Referrer-Policy", "no-referrer"],
		["Strict-Transport-Security", "max-age=15552000; includeSubDomains"],
		["X-Content-Type-Options", "nosniff"],
		["Origin-Agent-Cluster", "?1"],
		["X-DNS-Prefetch-Control", "off"],
		["X-Download-Options", "noopen"],
		["X-Frame-Options", "SAMEORIGIN"],
		["X-Permitted-Cross-Domain-Policies", "none"],
		["X-XSS-Protection", "0"],
	]);

	const mock = {
		res: {
			headers: new Map<string, string>(),
		},
	};
	const helmet = honoHelmet({ contentSecurityPolicy: false });
	helmet(mock as unknown as Context, async () => {}).then(() => {
		expect(mock.res.headers).toEqual(defaultHeadersWithoutCsp);
	});
});

test("X-Permitted-Cross-Domain-Policies: all", () => {
	const defaultHeaders = new Map([
		[
			"Content-Security-Policy",
			"default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests",
		],
		["Cross-Origin-Embedder-Policy", "require-corp"],
		["Cross-Origin-Opener-Policy", "same-origin"],
		["Cross-Origin-Resource-Policy", "same-origin"],
		["Referrer-Policy", "no-referrer"],
		["Strict-Transport-Security", "max-age=15552000; includeSubDomains"],
		["X-Content-Type-Options", "nosniff"],
		["Origin-Agent-Cluster", "?1"],
		["X-DNS-Prefetch-Control", "off"],
		["X-Download-Options", "noopen"],
		["X-Frame-Options", "SAMEORIGIN"],
		["X-Permitted-Cross-Domain-Policies", "all"],
		["X-XSS-Protection", "0"],
	]);

	const mock = {
		res: {
			headers: new Map<string, string>(),
		},
	};
	const helmet = honoHelmet({
		permittedCrossDomainPolicies: {
			permittedPolicies: "all",
		},
	});
	helmet(mock as unknown as Context, async () => {}).then(() => {
		expect(mock.res.headers).toEqual(defaultHeaders);
	});
});
