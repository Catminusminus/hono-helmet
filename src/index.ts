import type { Context, MiddlewareHandler, Env } from "hono";

interface Directives {
	defaultSrc?: string[];
	baseUri?: string[];
	fontSrc?: string[];
	fontActions?: string[];
	frameAncestors?: string[];
	imgSrc?: string[];
	objectSrc?: string[];
	scriptSrc?: string[];
	scriptSrcElem?: string[];
	scriptSrcAttr?: string[];
	styleSrc?: string[];
	styleSrcElem?: string[];
	styleSrcAttr?: string[];
	workerSrc?: string[];
	sandbox?: string[];
	upgradeInsecureRequests?: string[];
	childSrc?: string[];
	connectSrc?: string[];
	manifestSrc?: string[];
	mediaSrc?: string[];
	prefetchSrc?: string[];
	formAction?: string[];
	navigateto?: string[];
	requireTrustedTypesFor?: string[];
	trustedTypes?: string[];
}

interface ContentSecurityPolicyOptions {
	useDefaults?: boolean;
	directives?: Directives;
	reportOnly?: boolean;
}
interface CrossOriginEmbedderPolicyOptions {
	policy: "unsafe-none" | "require-corp" | "credentialless";
}
interface CrossOriginOpenerPolicyOptions {
	policy: "unsafe-none" | "same-origin-allow-popups" | "same-origin";
}
interface CrossOriginResourcePolicyOptions {
	policy: "same-site" | "same-origin" | "cross-origin";
}
type ReferrerPolicy = "ReferrerPolicy" | "no-referrer-when-downgrade";
interface ReferrerPolicyOptions {
	policy: ReferrerPolicy | [ReferrerPolicy, ...ReferrerPolicy[]];
}
interface HstsOptions {
	maxAge?: number;
	includeSubDomains?: boolean;
	preload?: boolean;
}
type OriginAgentClusterOptions = "?1" | "?0";
interface DnsPrefetchControlOptions {
	allow: boolean;
}
interface FrameguardOptions {
	action: "deny" | "sameorigin";
}
interface PermittedCrossDomainPoliciesOptions {
	permittedPolicies: "none" | "master-only" | "by-content-type" | "all";
}

interface HonoHelmetOptions {
	contentSecurityPolicy?: ContentSecurityPolicyOptions | boolean;
	crossOriginEmbedderPolicy?: CrossOriginEmbedderPolicyOptions | boolean;
	crossOriginOpenerPolicy?: CrossOriginOpenerPolicyOptions | boolean;
	crossOriginResourcePolicy?: CrossOriginResourcePolicyOptions | boolean;
	referrerPolicy?: ReferrerPolicyOptions | boolean;
	hsts?: HstsOptions | boolean;
	noSniff?: boolean;
	originAgentCluster?: OriginAgentClusterOptions | boolean;
	dnsPrefetchControl?: DnsPrefetchControlOptions | boolean;
	ieNoOpen?: boolean;
	frameguard?: FrameguardOptions | boolean;
	permittedCrossDomainPolicies?: PermittedCrossDomainPoliciesOptions | boolean;
	hidePoweredBy?: boolean;
	xssFilter?: boolean;
}

class ContentSecurityPolicyDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set(
			"Content-Security-Policy",
			"default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests",
		);
	}
}

class ContentSecurityPolicyHandler {
	value: string;
	header: string;
	constructor(options: ContentSecurityPolicyOptions) {
		throw new Error("Not implemented yet");
		const { useDefaults, directives, reportOnly } = options;
		this.value = "";
		this.header =
			reportOnly === undefined || reportOnly === false
				? "Content-Security-Policy"
				: "Content-Security-Policy-Report-Only";
	}
	apply(c: Context): void {
		c.res.headers.set(this.header, this.value);
	}
}

class CrossOriginEmbedderPolicyDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set("Cross-Origin-Embedder-Policy", "require-corp");
	}
}

class CrossOriginEmbedderPolicyHandler {
	value: "unsafe-none" | "require-corp" | "credentialless";
	constructor(options: CrossOriginEmbedderPolicyOptions) {
		this.value = options.policy;
	}
	apply(c: Context): void {
		c.res.headers.set("Cross-Origin-Embedder-Policy", this.value);
	}
}

class CrossOriginOpenerPolicyDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set("Cross-Origin-Opener-Policy", "same-origin");
	}
}

class CrossOriginOpenerPolicyHandler {
	value: "unsafe-none" | "same-origin-allow-popups" | "same-origin";
	constructor(options: CrossOriginOpenerPolicyOptions) {
		this.value = options.policy;
	}
	apply(c: Context): void {
		c.res.headers.set("Cross-Origin-Opener-Policy", this.value);
	}
}

class CrossOriginResourcePolicyDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set("Cross-Origin-Resource-Policy", "same-origin");
	}
}

class CrossOriginResourcePolicyHandler {
	value: "same-site" | "same-origin" | "cross-origin";
	constructor(options: CrossOriginResourcePolicyOptions) {
		this.value = options.policy;
	}
	apply(c: Context): void {
		c.res.headers.set("Cross-Origin-Resource-Policy", this.value);
	}
}

class ReferrerPolicyDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set("Referrer-Policy", "no-referrer");
	}
}

class ReferrerPolicyHandler {
	value: string;
	constructor(options: ReferrerPolicyOptions) {
		if (typeof options.policy === "string") {
			this.value = options.policy;
		} else {
			this.value = options.policy.join();
		}
	}
	apply(c: Context): void {
		c.res.headers.set("Referrer-Policy", this.value);
	}
}

class HstsDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set(
			"Strict-Transport-Security",
			"max-age=15552000; includeSubDomains",
		);
	}
}

class HstsHandler {
	value: string;
	constructor(options: HstsOptions) {
		const optionsAll: Required<HstsOptions> = {
			maxAge: options.maxAge === undefined ? 15552000 : options.maxAge,
			includeSubDomains:
				options.includeSubDomains === undefined
					? true
					: options.includeSubDomains,
			preload: options.preload === undefined ? false : options.preload,
		};
		this.value = `max-age=${optionsAll.maxAge}${
			optionsAll.includeSubDomains ? "; includeSubDomains" : ""
		}${optionsAll.preload ? "; preload" : ""}`;
	}
	apply(c: Context): void {
		c.res.headers.set("Strict-Transport-Security", this.value);
	}
}

class NoSniffHandler {
	apply(c: Context): void {
		c.res.headers.set("X-Content-Type-Options", "nosniff");
	}
}

class OriginAgentClusterDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set("Origin-Agent-Cluster", "?1");
	}
}

class OriginAgentClusterHandler {
	options: OriginAgentClusterOptions;
	constructor(options: OriginAgentClusterOptions) {
		this.options = options;
	}
	apply(c: Context): void {
		c.res.headers.set("Origin-Agent-Cluster", this.options);
	}
}

class DnsPrefetchControlDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set("X-DNS-Prefetch-Control", "off");
	}
}

class DnsPrefetchControlHandler {
	value: "off" | "on";
	constructor(options: DnsPrefetchControlOptions) {
		if (options.allow) {
			this.value = "on";
		} else {
			this.value = "off";
		}
	}
	apply(c: Context): void {
		c.res.headers.set("X-DNS-Prefetch-Control", this.value);
	}
}

class IeNoOpenHandler {
	apply(c: Context): void {
		c.res.headers.set("X-Download-Options", "noopen");
	}
}

class FrameguardDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set("X-Frame-Options", "SAMEORIGIN");
	}
}

class FrameguardHandler {
	value: "DENY" | "SAMEORIGIN";
	constructor(options: FrameguardOptions) {
		if (options.action === "deny") {
			this.value = "DENY";
		} else {
			this.value = "SAMEORIGIN";
		}
	}
	apply(c: Context): void {
		c.res.headers.set("X-Frame-Options", this.value);
	}
}

class PermittedCrossDomainPoliciesDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set("X-Permitted-Cross-Domain-Policies", "none");
	}
}

class PermittedCrossDomainPoliciesHandler {
	options: PermittedCrossDomainPoliciesOptions;
	constructor(options: PermittedCrossDomainPoliciesOptions) {
		this.options = options;
	}
	apply(c: Context): void {
		c.res.headers.set(
			"X-Permitted-Cross-Domain-Policies",
			this.options.permittedPolicies,
		);
	}
}

class HidePoweredByHandler {
	apply(c: Context): void {
		c.res.headers.delete("X-Powered-By");
	}
}

class XssFilterHandler {
	apply(c: Context): void {
		c.res.headers.set("X-XSS-Protection", "0");
	}
}

type Handler =
	| ContentSecurityPolicyDefaultHandler
	| ContentSecurityPolicyHandler
	| CrossOriginEmbedderPolicyDefaultHandler
	| CrossOriginEmbedderPolicyHandler
	| CrossOriginOpenerPolicyDefaultHandler
	| CrossOriginOpenerPolicyHandler
	| CrossOriginResourcePolicyDefaultHandler
	| CrossOriginResourcePolicyHandler
	| ReferrerPolicyDefaultHandler
	| ReferrerPolicyHandler
	| HstsDefaultHandler
	| HstsHandler
	| NoSniffHandler
	| OriginAgentClusterDefaultHandler
	| OriginAgentClusterHandler
	| DnsPrefetchControlDefaultHandler
	| DnsPrefetchControlHandler
	| IeNoOpenHandler
	| FrameguardDefaultHandler
	| FrameguardHandler
	| PermittedCrossDomainPoliciesDefaultHandler
	| PermittedCrossDomainPoliciesHandler
	| HidePoweredByHandler
	| XssFilterHandler;

export const honoHelmet = <E extends Env, P extends string>(
	options?: HonoHelmetOptions,
): MiddlewareHandler<E, P> => {
	const handlers: Handler[] = [];
	if (options === undefined) {
		handlers.push(new ContentSecurityPolicyDefaultHandler());
		handlers.push(new CrossOriginEmbedderPolicyDefaultHandler());
		handlers.push(new CrossOriginOpenerPolicyDefaultHandler());
		handlers.push(new CrossOriginResourcePolicyDefaultHandler());
		handlers.push(new ReferrerPolicyDefaultHandler());
		handlers.push(new HstsDefaultHandler());
		handlers.push(new NoSniffHandler());
		handlers.push(new OriginAgentClusterDefaultHandler());
		handlers.push(new DnsPrefetchControlDefaultHandler());
		handlers.push(new IeNoOpenHandler());
		handlers.push(new FrameguardDefaultHandler());
		handlers.push(new PermittedCrossDomainPoliciesDefaultHandler());
		handlers.push(new HidePoweredByHandler());
		handlers.push(new XssFilterHandler());
	} else {
		const {
			contentSecurityPolicy,
			crossOriginEmbedderPolicy,
			crossOriginOpenerPolicy,
			crossOriginResourcePolicy,
			referrerPolicy,
			hsts,
			noSniff,
			originAgentCluster,
			dnsPrefetchControl,
			ieNoOpen,
			frameguard,
			permittedCrossDomainPolicies,
			hidePoweredBy,
			xssFilter,
		} = options;
		if (contentSecurityPolicy === undefined || contentSecurityPolicy === true) {
			handlers.push(new ContentSecurityPolicyDefaultHandler());
		} else if (contentSecurityPolicy !== false) {
			handlers.push(new ContentSecurityPolicyHandler(contentSecurityPolicy));
		}
		if (
			crossOriginEmbedderPolicy === undefined ||
			crossOriginEmbedderPolicy === true
		) {
			handlers.push(new CrossOriginEmbedderPolicyDefaultHandler());
		} else if (crossOriginEmbedderPolicy !== false) {
			handlers.push(
				new CrossOriginEmbedderPolicyHandler(crossOriginEmbedderPolicy),
			);
		}
		if (
			crossOriginOpenerPolicy === undefined ||
			crossOriginOpenerPolicy === true
		) {
			handlers.push(new CrossOriginOpenerPolicyDefaultHandler());
		} else if (crossOriginOpenerPolicy !== false) {
			handlers.push(
				new CrossOriginOpenerPolicyHandler(crossOriginOpenerPolicy),
			);
		}
		if (
			crossOriginResourcePolicy === undefined ||
			crossOriginResourcePolicy === true
		) {
			handlers.push(new CrossOriginResourcePolicyDefaultHandler());
		} else if (crossOriginResourcePolicy !== false) {
			handlers.push(
				new CrossOriginResourcePolicyHandler(crossOriginResourcePolicy),
			);
		}
		if (referrerPolicy === undefined || referrerPolicy === true) {
			handlers.push(new ReferrerPolicyDefaultHandler());
		} else if (referrerPolicy !== false) {
			handlers.push(new ReferrerPolicyHandler(referrerPolicy));
		}
		if (hsts === undefined || hsts === true) {
			handlers.push(new HstsDefaultHandler());
		} else if (hsts !== false) {
			handlers.push(new HstsHandler(hsts));
		}
		if (noSniff === undefined || noSniff === true) {
			handlers.push(new NoSniffHandler());
		}
		if (originAgentCluster === undefined || originAgentCluster === true) {
			handlers.push(new OriginAgentClusterDefaultHandler());
		} else if (originAgentCluster !== false) {
			handlers.push(new OriginAgentClusterHandler(originAgentCluster));
		}
		if (dnsPrefetchControl === undefined || dnsPrefetchControl === true) {
			handlers.push(new DnsPrefetchControlDefaultHandler());
		} else if (dnsPrefetchControl !== false) {
			handlers.push(new DnsPrefetchControlHandler(dnsPrefetchControl));
		}
		if (ieNoOpen === undefined || ieNoOpen === true) {
			handlers.push(new IeNoOpenHandler());
		}
		if (frameguard === undefined || frameguard === true) {
			handlers.push(new FrameguardDefaultHandler());
		} else if (frameguard !== false) {
			handlers.push(new FrameguardHandler(frameguard));
		}
		if (
			permittedCrossDomainPolicies === undefined ||
			permittedCrossDomainPolicies === true
		) {
			handlers.push(new PermittedCrossDomainPoliciesDefaultHandler());
		} else if (permittedCrossDomainPolicies !== false) {
			handlers.push(
				new PermittedCrossDomainPoliciesHandler(permittedCrossDomainPolicies),
			);
		}
		if (hidePoweredBy === undefined || hidePoweredBy === true) {
			handlers.push(new HidePoweredByHandler());
		}
		if (xssFilter === undefined || xssFilter === true) {
			handlers.push(new XssFilterHandler());
		}
	}
	return async (c, next) => {
		await next();
		handlers.forEach((handler) => handler.apply(c));
	};
};
