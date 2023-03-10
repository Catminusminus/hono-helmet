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

describe("Cross-Origin-Embedder-Policy", () => {
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
		const helmet = honoHelmet({
			crossOriginEmbedderPolicy: { policy: "require-corp" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("credentialless", () => {
		defaultHeaders.set("Cross-Origin-Embedder-Policy", "credentialless");
		const helmet = honoHelmet({
			crossOriginEmbedderPolicy: { policy: "credentialless" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("unsafe-none", () => {
		defaultHeaders.set("Cross-Origin-Embedder-Policy", "unsafe-none");
		const helmet = honoHelmet({
			crossOriginEmbedderPolicy: { policy: "unsafe-none" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("Cross-Origin-Opener-Policy", () => {
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
		defaultHeaders.set("Cross-Origin-Opener-Policy", "same-origin");
		const helmet = honoHelmet({
			crossOriginOpenerPolicy: { policy: "same-origin" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("same-origin-allow-popups", () => {
		defaultHeaders.set(
			"Cross-Origin-Opener-Policy",
			"same-origin-allow-popups",
		);
		const helmet = honoHelmet({
			crossOriginOpenerPolicy: { policy: "same-origin-allow-popups" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("unsafe-none", () => {
		defaultHeaders.set("Cross-Origin-Opener-Policy", "unsafe-none");
		const helmet = honoHelmet({
			crossOriginOpenerPolicy: { policy: "unsafe-none" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("Cross-Origin-Resource-Policy", () => {
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
		defaultHeaders.set("Cross-Origin-Resource-Policy", "same-origin");
		const helmet = honoHelmet({
			crossOriginResourcePolicy: { policy: "same-origin" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("cross-origin", () => {
		defaultHeaders.set("Cross-Origin-Resource-Policy", "cross-origin");
		const helmet = honoHelmet({
			crossOriginResourcePolicy: { policy: "cross-origin" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("same-site", () => {
		defaultHeaders.set("Cross-Origin-Resource-Policy", "same-site");
		const helmet = honoHelmet({
			crossOriginResourcePolicy: { policy: "same-site" },
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
	test("default policy", () => {
		const helmet = honoHelmet({ referrerPolicy: { policy: "no-referrer" } });
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
	test("origin", () => {
		defaultHeaders.set("Referrer-Policy", "origin");
		const helmet = honoHelmet({
			referrerPolicy: { policy: "origin" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("origin-when-cross-origin", () => {
		defaultHeaders.set("Referrer-Policy", "origin-when-cross-origin");
		const helmet = honoHelmet({
			referrerPolicy: { policy: "origin-when-cross-origin" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("same-origin", () => {
		defaultHeaders.set("Referrer-Policy", "same-origin");
		const helmet = honoHelmet({
			referrerPolicy: { policy: "same-origin" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("strict-origin", () => {
		defaultHeaders.set("Referrer-Policy", "strict-origin");
		const helmet = honoHelmet({
			referrerPolicy: { policy: "strict-origin" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("strict-origin-when-cross-origin", () => {
		defaultHeaders.set("Referrer-Policy", "strict-origin-when-cross-origin");
		const helmet = honoHelmet({
			referrerPolicy: { policy: "strict-origin-when-cross-origin" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("unsafe-url", () => {
		defaultHeaders.set("Referrer-Policy", "unsafe-url");
		const helmet = honoHelmet({
			referrerPolicy: { policy: "unsafe-url" },
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

describe("Strict-Transport-Security", () => {
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
		const helmet = honoHelmet({ hsts: true });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("modify maxage to 10", () => {
		defaultHeaders.set(
			"Strict-Transport-Security",
			"max-age=10; includeSubDomains",
		);
		const helmet = honoHelmet({
			hsts: { maxAge: 10 },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("disable includeSubDomains", () => {
		defaultHeaders.set("Strict-Transport-Security", "max-age=15552000");
		const helmet = honoHelmet({
			hsts: { includeSubDomains: false },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("Enable preload", () => {
		defaultHeaders.set(
			"Strict-Transport-Security",
			"max-age=15552000; includeSubDomains; preload",
		);
		const helmet = honoHelmet({
			hsts: { preload: true },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("Disable includeSubDomains and enable preload", () => {
		defaultHeaders.set(
			"Strict-Transport-Security",
			"max-age=15552000; preload",
		);
		const helmet = honoHelmet({
			hsts: { preload: true, includeSubDomains: false },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("Origin-Agent-Cluster", () => {
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
		const helmet = honoHelmet({ originAgentCluster: true });
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("off", () => {
		defaultHeaders.set("Origin-Agent-Cluster", "?0");
		const helmet = honoHelmet({
			originAgentCluster: "?0",
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("on", () => {
		const helmet = honoHelmet({
			originAgentCluster: "?1",
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("X-DNS-Prefetch-Control", () => {
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
		const helmet = honoHelmet({
			dnsPrefetchControl: true,
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("on", () => {
		defaultHeaders.set("X-DNS-Prefetch-Control", "on");
		const helmet = honoHelmet({
			dnsPrefetchControl: { allow: true },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("off", () => {
		const helmet = honoHelmet({
			dnsPrefetchControl: { allow: false },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("X-Download-Options", () => {
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
		const helmet = honoHelmet({
			ieNoOpen: true,
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("X-Frame-Options", () => {
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
		const helmet = honoHelmet({
			frameguard: true,
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("sameorigin", () => {
		const helmet = honoHelmet({
			frameguard: { action: "sameorigin" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("deny", () => {
		defaultHeaders.set("X-Frame-Options", "DENY");
		const helmet = honoHelmet({
			frameguard: { action: "deny" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("X-Permitted-Cross-Domain-Policies", () => {
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
		const helmet = honoHelmet({
			permittedCrossDomainPolicies: true,
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("none", () => {
		const helmet = honoHelmet({
			permittedCrossDomainPolicies: { permittedPolicies: "none" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("all", () => {
		defaultHeaders.set("X-Permitted-Cross-Domain-Policies", "all");
		const helmet = honoHelmet({
			permittedCrossDomainPolicies: { permittedPolicies: "all" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("master-only", () => {
		defaultHeaders.set("X-Permitted-Cross-Domain-Policies", "master-only");
		const helmet = honoHelmet({
			permittedCrossDomainPolicies: { permittedPolicies: "master-only" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("by-content-type", () => {
		defaultHeaders.set("X-Permitted-Cross-Domain-Policies", "by-content-type");
		const helmet = honoHelmet({
			permittedCrossDomainPolicies: { permittedPolicies: "by-content-type" },
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("X-XSS-Protection", () => {
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
		const helmet = honoHelmet({
			xssFilter: true,
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});

describe("Reporting", () => {
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
	test("Reporting Endpoints", () => {
		defaultHeaders.set(
			"Content-Security-Policy",
			"default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests;report-to endpoint-1",
		);
		defaultHeaders.set(
			"Reporting-Endpoints",
			'endpoint-1="https://example.com/reports"',
		);
		const helmet = honoHelmet({
			contentSecurityPolicy: {
				directives: {
					reportTo: "endpoint-1",
				},
			},
			reportingEndpoints: {
				"endpoint-1": "https://example.com/reports",
			},
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
	test("Report To", () => {
		defaultHeaders.set(
			"Content-Security-Policy",
			"default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests;report-to csp-endpoint",
		);
		defaultHeaders.set(
			"Report-To",
			'{"group":"csp-endpoint","max_age":10886400,"endpoints":[{"url":"https://example.com/csp-reports"}]}',
		);
		const helmet = honoHelmet({
			contentSecurityPolicy: {
				directives: {
					reportTo: "csp-endpoint",
				},
			},
			reportTo: [
				{
					group: "csp-endpoint",
					max_age: 10886400,
					endpoints: [{ url: "https://example.com/csp-reports" }],
				},
			],
		});
		helmet(mock as unknown as Context, async () => {}).then(() => {
			expect(mock.res.headers).toEqual(defaultHeaders);
		});
	});
});
