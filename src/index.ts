import type { Context, MiddlewareHandler, Env } from "hono";

type Sandbox =
	| "allow-downloads"
	| "allow-downloads-without-user-activation"
	| "allow-forms"
	| "allow-modals"
	| "allow-orientation-lock"
	| "allow-pointer-lock"
	| "allow-popups"
	| "allow-popups-to-escape-sandbox"
	| "allow-presentation"
	| "allow-same-origin"
	| "allow-scripts"
	| "allow-storage-access-by-user-activation"
	| "allow-top-navigation"
	| "allow-top-navigation-by-user-activation"
	| "allow-top-navigation-to-custom-protocols";

interface Directives {
	defaultSrc?: string[] | boolean;
	baseUri?: string[] | boolean;
	fontSrc?: string[] | boolean;
	formActions?: string[] | boolean;
	frameAncestors?: string[] | boolean;
	imgSrc?: string[] | boolean;
	objectSrc?: string[] | boolean;
	scriptSrc?: string[] | boolean;
	scriptSrcElem?: string[] | false;
	scriptSrcAttr?: string[] | boolean;
	styleSrc?: string[] | boolean;
	styleSrcElem?: string[] | false;
	styleSrcAttr?: string[] | false;
	workerSrc?: string[] | false;
	sandbox?: Sandbox[] | false;
	upgradeInsecureRequests?: boolean;
	childSrc?: string[] | false;
	connectSrc?: string[] | false;
	manifestSrc?: string[] | false;
	mediaSrc?: string[] | false;
	prefetchSrc?: string[] | false;
	requireTrustedTypesFor?: boolean;
	trustedTypes?: string[] | false;
	[key: string]: string[] | boolean | undefined;
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

const defaultCspDirectives: Directives = {
	defaultSrc: ["'self'"],
	baseUri: ["'self'"],
	fontSrc: ["'self' https: data:"],
	frameAncestors: ["'self'"],
	imgSrc: ["'self' data:"],
	objectSrc: ["'none'"],
	scriptSrc: ["'self'"],
	scriptSrcAttr: ["'self'"],
	styleSrc: ["'self' https: 'unsafe-inline'"],
	upgradeInsecureRequests: true,
	formAction: ["'self'"],
};

const createAllDirectives = (directives: Directives): Directives => {
	const allDirectives = defaultCspDirectives;
	const mergedDirectives = Object.assign(allDirectives, directives);
	for (const directive in mergedDirectives) {
		if (Object.prototype.hasOwnProperty.call(mergedDirectives, directive)) {
			if (mergedDirectives[directive] === false) {
				mergedDirectives[directive] = undefined;
			}
		}
	}
	return mergedDirectives;
};

const buildDirectivesString = (directives: Directives): string => {
	const {
		defaultSrc,
		baseUri,
		fontSrc,
		formActions,
		frameAncestors,
		imgSrc,
		objectSrc,
		scriptSrc,
		scriptSrcElem,
		scriptSrcAttr,
		styleSrc,
		styleSrcElem,
		styleSrcAttr,
		workerSrc,
		sandbox,
		upgradeInsecureRequests,
		childSrc,
		connectSrc,
		manifestSrc,
		mediaSrc,
		prefetchSrc,
		requireTrustedTypesFor,
		trustedTypes,
	} = directives;
	const arr = [];
	if (defaultSrc === undefined || defaultSrc === true) {
		arr.push("default-src 'self'");
	} else if (defaultSrc !== false) {
		arr.push(`default-src ${defaultSrc.join(" ")}`);
	}
	if (baseUri === undefined || baseUri === true) {
		arr.push("base-uri 'self'");
	} else if (baseUri !== false) {
		arr.push(`base-uri ${baseUri.join(" ")}`);
	}
	if (fontSrc === undefined || fontSrc === true) {
		arr.push("font-src 'self' https: data:");
	} else if (fontSrc !== false) {
		arr.push(`font-src ${fontSrc.join(" ")}`);
	}
	if (formActions === undefined || formActions === true) {
		arr.push("form-actions 'self'");
	} else if (formActions !== false) {
		arr.push(`form-actions ${formActions.join(" ")}`);
	}
	if (frameAncestors === undefined || frameAncestors === true) {
		arr.push("frame-ancestors 'self'");
	} else if (frameAncestors !== false) {
		arr.push(`frame-ancestors ${frameAncestors.join(" ")}`);
	}
	if (imgSrc === undefined || imgSrc === true) {
		arr.push("img-src 'self'");
	} else if (imgSrc !== false) {
		arr.push(`img-src ${imgSrc.join(" ")}`);
	}
	if (objectSrc === undefined || objectSrc === true) {
		arr.push("object-src 'none'");
	} else if (objectSrc !== false) {
		arr.push(`object-src ${objectSrc.join(" ")}`);
	}
	if (scriptSrc === undefined || scriptSrc === true) {
		arr.push("script-src 'self'");
	} else if (scriptSrc !== false) {
		arr.push(`script-src ${scriptSrc.join(" ")}`);
	}
	if (scriptSrcElem !== undefined && scriptSrcElem !== false) {
		arr.push(`script-src-elem ${scriptSrcElem.join(" ")}`);
	}
	if (scriptSrcAttr === undefined || scriptSrcAttr === true) {
		arr.push("script-src-attr 'self'");
	} else if (scriptSrcAttr !== false) {
		arr.push(`script-src-attr ${scriptSrcAttr.join(" ")}`);
	}
	if (styleSrc === undefined || styleSrc === true) {
		arr.push("style-src 'self' https: 'unsafe-inline'");
	} else if (styleSrc !== false) {
		arr.push(`style-src ${styleSrc.join(" ")}`);
	}
	if (styleSrcElem !== undefined && styleSrcElem !== false) {
		arr.push(`style-src-elem ${styleSrcElem.join(" ")}`);
	}
	if (styleSrcAttr !== undefined && styleSrcAttr !== false) {
		arr.push(`style-src-attr ${styleSrcAttr.join(" ")}`);
	}
	if (workerSrc !== undefined && workerSrc !== false) {
		arr.push(`worker-src ${workerSrc.join(" ")}`);
	}
	if (sandbox !== undefined && sandbox !== false) {
		arr.push(`sandbox ${sandbox.join(" ")}`);
	}
	if (upgradeInsecureRequests === undefined || upgradeInsecureRequests) {
		arr.push("upgrade-insecure-requests");
	}
	if (childSrc !== undefined && childSrc !== false) {
		arr.push(`child-src ${childSrc.join(" ")}`);
	}
	if (connectSrc !== undefined && connectSrc !== false) {
		arr.push(`child-src ${connectSrc.join(" ")}`);
	}
	if (manifestSrc !== undefined && manifestSrc !== false) {
		arr.push(`manifest-src ${manifestSrc.join(" ")}`);
	}
	if (mediaSrc !== undefined && mediaSrc !== false) {
		arr.push(`media-src ${mediaSrc.join(" ")}`);
	}
	if (prefetchSrc !== undefined && prefetchSrc !== false) {
		arr.push(`prefetch-src ${prefetchSrc.join(" ")}`);
	}
	if (trustedTypes !== undefined && trustedTypes !== false) {
		if (trustedTypes.length === 0) {
			arr.push("trusted-types");
		} else {
			arr.push(`trusted-types ${trustedTypes.join(" ")}`);
		}
	}
	if (requireTrustedTypesFor) {
		arr.push("require-trusted-types-for 'script'");
	}
	return arr.join(";");
};

class ContentSecurityPolicyHandler {
	value: string = "";
	header: string = "";
	set: (value: Context) => void;
	constructor(options: ContentSecurityPolicyOptions) {
		const { useDefaults, directives, reportOnly } = options;
		if (directives === undefined || Object.keys(directives).length === 0) {
			if (useDefaults === undefined || useDefaults) {
				this.value = buildDirectivesString(defaultCspDirectives);
				this.set = (c: Context) => {
					c.res.headers.set(this.header, this.value);
				};
				return;
			}
			this.set = (_: Context) => {};
			return;
		}
		if (useDefaults === false) {
			this.value = buildDirectivesString(directives);
		} else {
			this.value = buildDirectivesString(createAllDirectives(directives));
		}
		this.set = (c: Context) => {
			c.res.headers.set(this.header, this.value);
		};
		this.header =
			reportOnly === undefined || reportOnly === false
				? "Content-Security-Policy"
				: "Content-Security-Policy-Report-Only";
	}
	apply(c: Context): void {
		this.set(c);
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
