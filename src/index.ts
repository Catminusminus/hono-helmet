import type { Context, MiddlewareHandler, Env, HonoRequest } from "hono";

// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/sandbox
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

// For example, consider scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`].
// In that case, 'self' is a string directive value and
// (req, res) => `'nonce-${res.locals.cspNonce}'` is a functional directive value.
type FunctionalDirectiveValue = (req: HonoRequest, res: Response) => string;

// For example, consider scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`].
// In that case, ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`]'s type is
// (string | FunctionalDirectiveValue)[].
type Directive<T> = (T | FunctionalDirectiveValue)[];

// The option interface of CSP directives.
// You can specify not only Directive values, but also boolean value.
// For example, scriptSrc: false means that you disable scriptSrc.
// You can specify true for defaultSrc because there exists a default value of defaultSrc.
// You cannnot specify true for frameSrc because there does not exist a default value of frameSrc.
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
interface Directives {
	defaultSrc?: Directive<string> | boolean;
	baseUri?: Directive<string> | boolean;
	fontSrc?: Directive<string> | boolean;
	formAction?: Directive<string> | boolean;
	frameAncestors?: Directive<string> | boolean;
	frameSrc?: Directive<string> | false;
	imgSrc?: Directive<string> | boolean;
	objectSrc?: Directive<string> | boolean;
	scriptSrc?: Directive<string> | boolean;
	scriptSrcElem?: Directive<string> | false;
	scriptSrcAttr?: Directive<string> | boolean;
	styleSrc?: Directive<string> | boolean;
	styleSrcElem?: Directive<string> | false;
	styleSrcAttr?: Directive<string> | false;
	workerSrc?: Directive<string> | false;
	sandbox?: Directive<Sandbox> | false;
	upgradeInsecureRequests?: boolean;
	childSrc?: Directive<string> | false;
	connectSrc?: Directive<string> | false;
	manifestSrc?: Directive<string> | false;
	mediaSrc?: Directive<string> | false;
	prefetchSrc?: Directive<string> | false;
	requireTrustedTypesFor?: boolean;
	trustedTypes?: Directive<string> | false;
	reportUri?: Directive<string> | false;
	reportTo?: string | false;
}

// Since the Directive type is complex, we transform the Directive option
// to a simpler type value.
// Without functional directive values, we can almost treat the option values as
// just arrays of strings.
interface ValidatedStringDirectives {
	kind: "string";
	defaultSrc?: string[];
	baseUri?: string[];
	fontSrc?: string[];
	formAction?: string[];
	frameAncestors?: string[];
	frameSrc?: string[];
	imgSrc?: string[];
	objectSrc?: string[];
	scriptSrc?: string[];
	scriptSrcElem?: string[];
	scriptSrcAttr?: string[];
	styleSrc?: string[];
	styleSrcElem?: string[];
	styleSrcAttr?: string[];
	workerSrc?: string[];
	sandbox?: Sandbox[];
	upgradeInsecureRequests?: boolean;
	childSrc?: string[];
	connectSrc?: string[];
	manifestSrc?: string[];
	mediaSrc?: string[];
	prefetchSrc?: string[];
	requireTrustedTypesFor?: boolean;
	trustedTypes?: string[];
	reportUri?: string[];
	reportTo?: string;
}

// This data structure enables us to handle functional directive values.
interface ValueAndFunction<T> {
	value: T[];
	func?: FunctionalDirectiveValue[];
}

// For example, consider scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`].
// This directive value will be transformed to
// {value: ["'self'"], func: [(req, res) => `'nonce-${res.locals.cspNonce}'`]}
interface ValidatedFunctionalDirectives {
	kind: "functional";
	defaultSrc?: ValueAndFunction<string>;
	baseUri?: ValueAndFunction<string>;
	fontSrc?: ValueAndFunction<string>;
	formAction?: ValueAndFunction<string>;
	frameAncestors?: ValueAndFunction<string>;
	frameSrc?: ValueAndFunction<string>;
	imgSrc?: ValueAndFunction<string>;
	objectSrc?: ValueAndFunction<string>;
	scriptSrc?: ValueAndFunction<string>;
	scriptSrcElem?: ValueAndFunction<string>;
	scriptSrcAttr?: ValueAndFunction<string>;
	styleSrc?: ValueAndFunction<string>;
	styleSrcElem?: ValueAndFunction<string>;
	styleSrcAttr?: ValueAndFunction<string>;
	workerSrc?: ValueAndFunction<string>;
	sandbox?: ValueAndFunction<Sandbox>;
	upgradeInsecureRequests?: boolean;
	childSrc?: ValueAndFunction<string>;
	connectSrc?: ValueAndFunction<string>;
	manifestSrc?: ValueAndFunction<string>;
	mediaSrc?: ValueAndFunction<string>;
	prefetchSrc?: ValueAndFunction<string>;
	requireTrustedTypesFor?: boolean;
	trustedTypes?: ValueAndFunction<string>;
	reportUri?: ValueAndFunction<string>;
	reportTo?: string | FunctionalDirectiveValue;
}

type ValidatedDirectives =
	| ValidatedStringDirectives
	| ValidatedFunctionalDirectives;

interface ContentSecurityPolicyOptions {
	useDefaults?: boolean;
	directives?: Directives;
	reportOnly?: boolean;
}
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy
interface CrossOriginEmbedderPolicyOptions {
	policy: "unsafe-none" | "require-corp" | "credentialless";
}
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy
interface CrossOriginOpenerPolicyOptions {
	policy: "unsafe-none" | "same-origin-allow-popups" | "same-origin";
}
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy
interface CrossOriginResourcePolicyOptions {
	policy: "same-site" | "same-origin" | "cross-origin";
}
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
type ReferrerPolicy =
	| "no-referrer"
	| "no-referrer-when-downgrade"
	| "origin"
	| "origin-when-cross-origin"
	| "same-origin"
	| "strict-origin"
	| "strict-origin-when-cross-origin"
	| "unsafe-url";
interface ReferrerPolicyOptions {
	policy: ReferrerPolicy | [ReferrerPolicy, ...ReferrerPolicy[]];
}
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
interface HstsOptions {
	maxAge?: number;
	includeSubDomains?: boolean;
	preload?: boolean;
}
// See https://web.dev/origin-agent-cluster/
type OriginAgentClusterOptions = "?1" | "?0";
interface DnsPrefetchControlOptions {
	allow: boolean;
}
// See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
interface FrameguardOptions {
	action: "deny" | "sameorigin";
}
// See https://owasp.org/www-project-secure-headers/#x-permitted-cross-domain-policies
interface PermittedCrossDomainPoliciesOptions {
	permittedPolicies: "none" | "master-only" | "by-content-type" | "all";
}
// There are options with default values and without default values.
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
	reportingEndpoints?: Record<string, string> | false;
	// rome-ignore lint/suspicious/noExplicitAny: I could not find Report-To JSON Info
	reportTo?: [Record<string, any>, ...Record<string, any>[]] | false;
}

class ContentSecurityPolicyDefaultHandler {
	apply(c: Context): void {
		c.res.headers.set(
			"Content-Security-Policy",
			"default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests",
		);
	}
}

const defaultCspDirectives: ValidatedStringDirectives = {
	kind: "string",
	defaultSrc: ["'self'"],
	baseUri: ["'self'"],
	fontSrc: ["'self' https: data:"],
	frameAncestors: ["'self'"],
	imgSrc: ["'self' data:"],
	objectSrc: ["'none'"],
	scriptSrc: ["'self'"],
	scriptSrcAttr: ["'none'"],
	styleSrc: ["'self' https: 'unsafe-inline'"],
	upgradeInsecureRequests: true,
	formAction: ["'self'"],
};

// Convert the specified CSP directives into a more manageable format.
// If there are some functional directives, this function converts the specified
// directives into ValidatedFunctionalDirectives. Otherwise, it converts them into
// ValidatedStringDirectives.
const parseDirectives = (
	directives: Directives,
	useDefault: boolean,
): ValidatedDirectives => {
	const {
		defaultSrc,
		baseUri,
		fontSrc,
		formAction,
		frameAncestors,
		frameSrc,
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
		reportUri,
		reportTo,
	} = directives;
	let isFunctional = false;
	type Ret = string[] | undefined | ValueAndFunction<string>;
	const process = (directive: Directive<string> | false | undefined): Ret => {
		if (!directive) {
			return undefined;
		}
		const value = [];
		const func = [];
		for (const v of directive) {
			if (typeof v === "string") {
				value.push(v);
			} else {
				isFunctional = true;
				func.push(v);
			}
		}
		if (!isFunctional) {
			return value;
		}
		return { value, func };
	};
	type RetSandbox = Sandbox[] | undefined | ValueAndFunction<Sandbox>;
	const processSandbox = (
		directive: Directive<Sandbox> | false | undefined,
	): RetSandbox => {
		if (!directive) {
			return undefined;
		}
		const value: Sandbox[] = [];
		const func = [];
		for (const v of directive) {
			if (typeof v === "string") {
				value.push(v);
			} else {
				isFunctional = true;
				func.push(v);
			}
		}
		if (!isFunctional) {
			return value;
		}
		return { value, func };
	};
	type RetReportTo = string | undefined | FunctionalDirectiveValue;
	const processReportTo = (
		reportTo: string | FunctionalDirectiveValue | undefined | false,
	): RetReportTo => {
		if (!reportTo) {
			return undefined;
		}
		if (typeof reportTo === "string") {
			return reportTo;
		}
		isFunctional = true;
		return reportTo;
	};
	const newDefaultSrc =
		defaultSrc === true || (useDefault && defaultSrc === undefined)
			? defaultCspDirectives.defaultSrc
			: process(defaultSrc);
	const newBaseUri =
		baseUri === true || (useDefault && baseUri === undefined)
			? defaultCspDirectives.baseUri
			: process(baseUri);
	const newFontSrc =
		fontSrc === true || (useDefault && fontSrc === undefined)
			? defaultCspDirectives.fontSrc
			: process(fontSrc);
	const newFormAction =
		formAction === true || (useDefault && formAction === undefined)
			? defaultCspDirectives.formAction
			: process(formAction);
	const newFrameAncestors =
		frameAncestors === true || (useDefault && frameAncestors === undefined)
			? defaultCspDirectives.frameAncestors
			: process(frameAncestors);
	const newFrameSrc = process(frameSrc);
	const newImgSrc =
		imgSrc === true || (useDefault && imgSrc === undefined)
			? defaultCspDirectives.imgSrc
			: process(imgSrc);
	const newObjectSrc =
		objectSrc === true || (useDefault && objectSrc === undefined)
			? defaultCspDirectives.objectSrc
			: process(objectSrc);
	const newScriptSrc =
		scriptSrc === true || (useDefault && scriptSrc === undefined)
			? defaultCspDirectives.scriptSrc
			: process(scriptSrc);
	const newScriptSrcElem = process(scriptSrcElem);
	const newScriptSrcAttr =
		scriptSrcAttr === true || (useDefault && scriptSrcAttr === undefined)
			? defaultCspDirectives.scriptSrcAttr
			: process(scriptSrcAttr);
	const newStyleSrc =
		styleSrc === true || (useDefault && styleSrc === undefined)
			? defaultCspDirectives.styleSrc
			: process(styleSrc);
	const newStyleSrcElem = process(styleSrcElem);
	const newStyleSrcAttr = process(styleSrcAttr);
	const newWorkerSrc = process(workerSrc);
	const newSandbox = processSandbox(sandbox);
	const newUpgradeInsecureRequests =
		upgradeInsecureRequests === true ||
		(useDefault && upgradeInsecureRequests === undefined)
			? defaultCspDirectives.upgradeInsecureRequests
			: upgradeInsecureRequests;
	const newChildSrc = process(childSrc);
	const newConnectSrc = process(connectSrc);
	const newManifestSrc = process(manifestSrc);
	const newMediaSrc = process(mediaSrc);
	const newPrefetchSrc = process(prefetchSrc);
	const newRequireTrustedTypesFor = !!requireTrustedTypesFor;
	const newTrustedTypes = process(trustedTypes);
	const newReportUri = process(reportUri);
	const newReportTo = processReportTo(reportTo);
	return {
		kind: isFunctional ? "functional" : "string",
		defaultSrc: newDefaultSrc,
		baseUri: newBaseUri,
		fontSrc: newFontSrc,
		formAction: newFormAction,
		frameAncestors: newFrameAncestors,
		frameSrc: newFrameSrc,
		imgSrc: newImgSrc,
		objectSrc: newObjectSrc,
		scriptSrc: newScriptSrc,
		scriptSrcElem: newScriptSrcElem,
		scriptSrcAttr: newScriptSrcAttr,
		styleSrc: newStyleSrc,
		styleSrcElem: newStyleSrcElem,
		styleSrcAttr: newStyleSrcAttr,
		workerSrc: newWorkerSrc,
		sandbox: newSandbox,
		upgradeInsecureRequests: newUpgradeInsecureRequests,
		childSrc: newChildSrc,
		connectSrc: newConnectSrc,
		manifestSrc: newManifestSrc,
		mediaSrc: newMediaSrc,
		prefetchSrc: newPrefetchSrc,
		requireTrustedTypesFor: newRequireTrustedTypesFor,
		trustedTypes: newTrustedTypes,
		reportUri: newReportUri,
		reportTo: newReportTo,
	} as ValidatedDirectives;
};

// Build the CSP field value for string-only case
const buildStringDirectives = (
	directives: ValidatedStringDirectives,
): string => {
	const {
		defaultSrc,
		baseUri,
		fontSrc,
		formAction,
		frameAncestors,
		frameSrc,
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
		reportUri,
		reportTo,
	} = directives;
	const arr = [];
	if (defaultSrc) {
		arr.push(`default-src ${defaultSrc.join(" ")}`);
	}
	if (baseUri) {
		arr.push(`base-uri ${baseUri.join(" ")}`);
	}
	if (fontSrc) {
		arr.push(`font-src ${fontSrc.join(" ")}`);
	}
	if (formAction) {
		arr.push(`form-action ${formAction.join(" ")}`);
	}
	if (frameAncestors) {
		arr.push(`frame-ancestors ${frameAncestors.join(" ")}`);
	}
	if (frameSrc) {
		arr.push(`frame-src ${frameSrc.join(" ")}`);
	}
	if (imgSrc) {
		arr.push(`img-src ${imgSrc.join(" ")}`);
	}
	if (objectSrc) {
		arr.push(`object-src ${objectSrc.join(" ")}`);
	}
	if (scriptSrc) {
		arr.push(`script-src ${scriptSrc.join(" ")}`);
	}
	if (scriptSrcElem) {
		arr.push(`script-src-elem ${scriptSrcElem.join(" ")}`);
	}
	if (scriptSrcAttr) {
		arr.push(`script-src-attr ${scriptSrcAttr.join(" ")}`);
	}
	if (styleSrc) {
		arr.push(`style-src ${styleSrc.join(" ")}`);
	}
	if (styleSrcElem) {
		arr.push(`style-src-elem ${styleSrcElem.join(" ")}`);
	}
	if (styleSrcAttr) {
		arr.push(`style-src-attr ${styleSrcAttr.join(" ")}`);
	}
	if (workerSrc) {
		arr.push(`worker-src ${workerSrc.join(" ")}`);
	}
	if (sandbox) {
		arr.push(`sandbox ${sandbox.join(" ")}`);
	}
	if (upgradeInsecureRequests) {
		arr.push("upgrade-insecure-requests");
	}
	if (childSrc) {
		arr.push(`child-src ${childSrc.join(" ")}`);
	}
	if (connectSrc) {
		arr.push(`connect-src ${connectSrc.join(" ")}`);
	}
	if (manifestSrc) {
		arr.push(`manifest-src ${manifestSrc.join(" ")}`);
	}
	if (mediaSrc) {
		arr.push(`media-src ${mediaSrc.join(" ")}`);
	}
	if (prefetchSrc) {
		arr.push(`prefetch-src ${prefetchSrc.join(" ")}`);
	}
	if (trustedTypes) {
		if (trustedTypes.length === 0) {
			arr.push("trusted-types");
		} else {
			arr.push(`trusted-types ${trustedTypes.join(" ")}`);
		}
	}
	if (requireTrustedTypesFor) {
		arr.push("require-trusted-types-for 'script'");
	}
	if (reportUri) {
		arr.push(`report-uri ${reportUri.join(" ")}`);
	}
	if (reportTo) {
		arr.push(`report-to ${reportTo}`);
	}
	return arr.join(";");
};

// Build the CSP field value for functional directives case
const buildFunctionalDirectives = (
	directives: ValidatedFunctionalDirectives,
) => {
	const {
		defaultSrc,
		baseUri,
		fontSrc,
		formAction,
		frameAncestors,
		frameSrc,
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
		reportUri,
		reportTo,
	} = directives;
	const arr: FunctionalDirectiveValue[] = [];
	const push = (
		directive: ValueAndFunction<string> | undefined,
		name: string,
	) => {
		if (directive) {
			const len = directive.value.length;
			if (directive.func) {
				if (len === 0) {
					arr.push(
						(req: HonoRequest, res: Response) =>
							`${name} ${directive.func?.map((f) => f(req, res)).join(" ")}`,
					);
				} else {
					arr.push(
						(req: HonoRequest, res: Response) =>
							`${name} ${directive.value.join(" ")} ${directive.func
								?.map((f) => f(req, res))
								.join(" ")}`,
					);
				}
			} else {
				arr.push(
					(_req: HonoRequest, _res: Response) =>
						`${name} ${directive.value.join(" ")}`,
				);
			}
		}
	};
	push(defaultSrc, "default-src");
	push(baseUri, "base-uri");
	push(fontSrc, "font-src");
	push(formAction, "form-action");
	push(frameAncestors, "frame-ancestors");
	push(frameSrc, "frame-src");
	push(imgSrc, "img-src");
	push(objectSrc, "object-src");
	push(scriptSrc, "script-src");
	push(scriptSrcElem, "script-src-elem");
	push(scriptSrcAttr, "script-src-attr");
	push(styleSrc, "style-src");
	push(styleSrcElem, "style-src-elem");
	push(styleSrcAttr, "style-src-attr");
	push(workerSrc, "worker-src");
	push(sandbox, "sandbox");
	if (upgradeInsecureRequests) {
		arr.push(
			(_req: HonoRequest, _res: Response) => "upgrade-insecure-requests",
		);
	}
	push(childSrc, "child-src");
	push(connectSrc, "connect-src");
	push(manifestSrc, "manifest-src");
	push(mediaSrc, "media-src");
	push(prefetchSrc, "prefetch-src");
	if (trustedTypes) {
		const len = trustedTypes.value.length;
		if (trustedTypes.func) {
			if (len === 0) {
				arr.push(
					(req: HonoRequest, res: Response) =>
						`trusted-types ${trustedTypes.func
							?.map((f) => f(req, res))
							.join(" ")}`,
				);
			} else {
				arr.push(
					(req: HonoRequest, res: Response) =>
						`trusted-types ${trustedTypes.value.join(" ")} ${trustedTypes.func
							?.map((f) => f(req, res))
							.join(" ")}`,
				);
			}
		} else {
			if (len === 0) {
				arr.push((_req: HonoRequest, _res: Response) => "trusted-types");
			} else {
				arr.push(
					(_req: HonoRequest, _res: Response) =>
						`trusted-types ${trustedTypes.value.join(" ")}`,
				);
			}
		}
	}
	if (requireTrustedTypesFor) {
		arr.push(
			(_req: HonoRequest, _res: Response) =>
				"require-trusted-types-for 'script'",
		);
	}
	push(reportUri, "report-uri");
	if (typeof reportTo === "string") {
		arr.push((_req: HonoRequest, _res: Response) => `report-to ${reportTo}`);
	} else if (reportTo) {
		arr.push(
			(req: HonoRequest, res: Response) => `report-to ${reportTo(req, res)}`,
		);
	}
	return (req: HonoRequest, res: Response) => {
		let str = "";
		for (let i = 0; i < arr.length; i++) {
			str += arr[i](req, res);
			if (i < arr.length - 1) {
				str += ";";
			}
		}
		return str;
	};
};

// Header Fields Handlers
class ContentSecurityPolicyHandler {
	value: string | FunctionalDirectiveValue = "";
	header: string = "";
	set: (value: Context) => void;
	constructor(options: ContentSecurityPolicyOptions) {
		const { useDefaults, directives, reportOnly } = options;
		this.header =
			reportOnly === undefined || reportOnly === false
				? "Content-Security-Policy"
				: "Content-Security-Policy-Report-Only";
		if (directives === undefined || Object.keys(directives).length === 0) {
			if (useDefaults === false) {
				this.value = "";
				this.set = (_: Context) => {};
				return;
			}
			this.value = buildStringDirectives(defaultCspDirectives);
			this.set = (c: Context) => {
				c.res.headers.set(this.header, this.value as string);
			};
			return;
		}
		const validatedDirectives = parseDirectives(
			directives,
			!(useDefaults === false),
		);
		if (validatedDirectives.kind === "string") {
			this.value = buildStringDirectives(validatedDirectives);
			this.set = (c: Context) => {
				c.res.headers.set(this.header, this.value as string);
			};
		} else {
			this.value = buildFunctionalDirectives(validatedDirectives);
			this.set = (c: Context) => {
				c.res.headers.set(
					this.header,
					(this.value as FunctionalDirectiveValue)(c.req, c.res),
				);
			};
		}
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

class ReportToHandler {
	value: string;
	// rome-ignore lint/suspicious/noExplicitAny: I could not find Report-To JSON Info
	constructor(options: [Record<string, any>, ...Record<string, any>[]]) {
		this.value = options.map((v) => JSON.stringify(v)).join(",");
	}
	apply(c: Context): void {
		c.res.headers.set("Report-To", this.value);
	}
}

class ReportingEndpointsHandler {
	value: string;
	constructor(options: Record<string, string>) {
		let str = "";
		for (const property in options) {
			str += `${property}="${options[property]}"`;
		}
		this.value = str;
	}
	apply(c: Context): void {
		c.res.headers.set("Reporting-Endpoints", this.value);
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
	| XssFilterHandler
	| ReportToHandler
	| ReportingEndpointsHandler;

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
			reportingEndpoints,
			reportTo,
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
		if (reportingEndpoints) {
			handlers.push(new ReportingEndpointsHandler(reportingEndpoints));
		}
		if (reportTo) {
			handlers.push(new ReportToHandler(reportTo));
		}
	}
	return async (c, next) => {
		await next();
		handlers.forEach((handler) => handler.apply(c));
	};
};
