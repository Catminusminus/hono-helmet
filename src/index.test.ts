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

describe("default configuration without", () => {
	let defaultHeaders: Map<string, string>;
	let mock: { res: { headers: Map<string, string> } };
	beforeEach(() => {
		defaultHeaders = new Map([
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
		mock = {
			res: {
				headers: new Map<string, string>(),
			},
		};
	});
	test("csp", () => {
		defaultHeaders.delete("Content-Security-Policy");
		const helmet = honoHelmet({ contentSecurityPolicy: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("coep", () => {
		defaultHeaders.delete("Cross-Origin-Embedder-Policy");
		const helmet = honoHelmet({ crossOriginEmbedderPolicy: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("coop", () => {
		defaultHeaders.delete("Cross-Origin-Opener-Policy");
		const helmet = honoHelmet({ crossOriginOpenerPolicy: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("corp", () => {
		defaultHeaders.delete("Cross-Origin-Resource-Policy");
		const helmet = honoHelmet({ crossOriginResourcePolicy: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("rp", () => {
		defaultHeaders.delete("Referrer-Policy");
		const helmet = honoHelmet({ referrerPolicy: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("hsts", () => {
		defaultHeaders.delete("Strict-Transport-Security");
		const helmet = honoHelmet({ hsts: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("xcto", () => {
		defaultHeaders.delete("X-Content-Type-Options");
		const helmet = honoHelmet({ noSniff: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("oac", () => {
		defaultHeaders.delete("Origin-Agent-Cluster");
		const helmet = honoHelmet({ originAgentCluster: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("dns-prefetch", () => {
		defaultHeaders.delete("X-DNS-Prefetch-Control");
		const helmet = honoHelmet({ dnsPrefetchControl: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("xdo", () => {
		defaultHeaders.delete("X-Download-Options");
		const helmet = honoHelmet({ ieNoOpen: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("xfo", () => {
		defaultHeaders.delete("X-Frame-Options");
		const helmet = honoHelmet({ frameguard: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("xpcdp", () => {
		defaultHeaders.delete("X-Permitted-Cross-Domain-Policies");
		const helmet = honoHelmet({ permittedCrossDomainPolicies: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("xss-protection", () => {
		defaultHeaders.delete("X-XSS-Protection");
		const helmet = honoHelmet({ xssFilter: false });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("multiple headers", () => {
		defaultHeaders.delete("X-Permitted-Cross-Domain-Policies");
		defaultHeaders.delete("X-XSS-Protection");
		const helmet = honoHelmet({
			permittedCrossDomainPolicies: false,
			xssFilter: false,
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
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

describe("CSP Directives", () => {
	let defaultHeaders: Map<string, string>;
	let mock: {
		res: { headers: Map<string, string>; value: string };
		req: string;
	};
	beforeEach(() => {
		defaultHeaders = new Map([
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
		mock = {
			res: {
				headers: new Map<string, string>(),
				value: "hash",
			},
			req: "something",
		};
	});
	test("use defaults: true", () => {
		const helmet = honoHelmet({ contentSecurityPolicy: { useDefaults: true } });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("use defaults: true with default-src", () => {
		defaultHeaders.set(
			"Content-Security-Policy",
			"default-src 'none';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests",
		);
		const helmet = honoHelmet({
			contentSecurityPolicy: {
				useDefaults: true,
				directives: {
					defaultSrc: ["'none'"],
				},
			},
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("use defaults: false", () => {
		defaultHeaders.set("Content-Security-Policy", "default-src 'none'");
		const helmet = honoHelmet({
			contentSecurityPolicy: {
				useDefaults: false,
				directives: {
					defaultSrc: ["'none'"],
				},
			},
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("use defaults: false, multiple default-src value", () => {
		defaultHeaders.set("Content-Security-Policy", "default-src 'self' 'none'");
		const helmet = honoHelmet({
			contentSecurityPolicy: {
				useDefaults: false,
				directives: {
					defaultSrc: ["'self'", "'none'"],
				},
			},
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("use defaults: false, functional default-src value", () => {
		defaultHeaders.set("Content-Security-Policy", "default-src 'something'");
		const helmet = honoHelmet({
			contentSecurityPolicy: {
				useDefaults: false,
				directives: {
					defaultSrc: [(req, res) => `'${req}'`],
				},
			},
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("Referrer-Policy", () => {
	let defaultHeaders: Map<string, string>;
	let mock: {
		res: { headers: Map<string, string> };
	};
	beforeEach(() => {
		defaultHeaders = new Map([
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
		mock = {
			res: {
				headers: new Map<string, string>(),
			},
		};
	});
	test("default", () => {
		const helmet = honoHelmet({ referrerPolicy: true });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("no-referrer-when-downgrade", () => {
		defaultHeaders.set("Referrer-Policy", "no-referrer-when-downgrade");
		const helmet = honoHelmet({
			referrerPolicy: { policy: "no-referrer-when-downgrade" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("multiple values", () => {
		defaultHeaders.set("Referrer-Policy", "origin,no-referrer-when-downgrade");
		const helmet = honoHelmet({
			referrerPolicy: { policy: ["origin", "no-referrer-when-downgrade"] },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});
