import { honoHelmet } from "../src/index";
import { Hono } from "hono";

test("All Default", async () => {
	const app = new Hono();
	app.use(honoHelmet());
	app.all("*", (c) => c.text("Hello"));

	const res = await app.request("http://localhost/", {
		method: "GET",
	});
	expect(res).not.toBeNull();
	expect(res.status).toBe(200);
	expect(res.headers.get("Content-Security-Policy")).toEqual(
		"default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests",
	);
});

describe("default configuration without", () => {
	let app: Hono;
	let res;
	beforeEach(() => {
		app = new Hono();
	});
	test("csp", async () => {
		app.use(honoHelmet({ contentSecurityPolicy: false }));
		app.all("*", (c) => c.text("Hello"));
		res = await app.request("http://localhost/", {
			method: "GET",
		});
		expect(res).not.toBeNull();
		expect(res.status).toBe(200);
		expect(res.headers.get("Content-Security-Policy")).toBeNull();
	});
	test("coep", async () => {
		app.use(honoHelmet({ crossOriginEmbedderPolicy: false }));
		app.all("*", (c) => c.text("Hello"));
		res = await app.request("http://localhost/", {
			method: "GET",
		});
		expect(res).not.toBeNull();
		expect(res.status).toBe(200);
		expect(res.headers.get("Cross-Origin-Embedder-Policy")).toBeNull();
	});
	test("coop", async () => {
		app.use(honoHelmet({ crossOriginOpenerPolicy: false }));
		app.all("*", (c) => c.text("Hello"));
		res = await app.request("http://localhost/", {
			method: "GET",
		});
		expect(res).not.toBeNull();
		expect(res.status).toBe(200);
		expect(res.headers.get("Cross-Origin-Opener-Policy")).toBeNull();
	});
	test("corp", async () => {
		app.use(honoHelmet({ crossOriginResourcePolicy: false }));
		app.all("*", (c) => c.text("Hello"));
		res = await app.request("http://localhost/", {
			method: "GET",
		});
		expect(res).not.toBeNull();
		expect(res.status).toBe(200);
		expect(res.headers.get("Cross-Origin-Resource-Policy")).toBeNull();
	});
	test("rp", async () => {
		app.use(honoHelmet({ referrerPolicy: false }));
		app.all("*", (c) => c.text("Hello"));
		res = await app.request("http://localhost/", {
			method: "GET",
		});
		expect(res).not.toBeNull();
		expect(res.status).toBe(200);
		expect(res.headers.get("Referrer-Policy")).toBeNull();
	});
});
