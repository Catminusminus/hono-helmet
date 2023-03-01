# Helmet Middleware for Hono

Bring [helmet](https://github.com/helmetjs/helmet) to
[Hono](https://github.com/honojs/hono).

## Quick Demo with Deno

```ts
import { serve } from "https://deno.land/std@0.167.0/http/server.ts";
import { Hono } from "npm:hono@2.7.7";
import { honoHelmet } from "https://github.com/Catminusminus/hono-helmet/raw/main/src/index.ts";

const app = new Hono();

app.use(honoHelmet());
app.get("/", (c) => c.text("Hello Hono!"));

serve(app.fetch);
```

## Requirements

<strong>Sorry, but not published yet</strong>

```sh
npm i @catminusminus/hono-helmet
```

or

```plain
yarn add @catminusminus/hono-helmet
```

## Usage

index.js:

```js
import { Hono } from "hono";
import { honoHelmet } from "@catminusminus/hono-helmet";
import { serve } from "@hono/node-server";

const app = new Hono();

app.use(honoHelmet());
app.get("/", (c) => c.text("Hello Hono!"));

serve(app);
```

The default header fields are as follows:

```
Content-Security-Policy: default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Origin-Agent-Cluster: ?1
Referrer-Policy: no-referrer
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 0
```

To set custom options:

```js
app.use(
  honoHelmet({
    permittedCrossDomainPolicies: {
      permittedPolicies: "all",
    },
  }),
);
```

To disable header fields:

```js
app.use(
  honoHelmet({
    contentSecurityPolicy: false,
  }),
);
```

## Reference

<details>
<summary><code>honoHelmet(options)</code></summary>

```ts
// Use the default header fields
app.use(honoHelmet());

// Disable one or more header fields
app.use(
  honoHelmet({
    contentSecurityPolicy: false,
  }),
);

// Use the default header fields but X-Permitted-Cross-Domain-Policies: all
app.use(
  honoHelmet({
    permittedCrossDomainPolicies: {
      permittedPolicies: "all",
    },
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({contentSecurityPolicy: options})</code></summary>

The default directives are as follows:

```
"default-src 'self';base-uri 'self';font-src 'self' https: data:;form-action 'self';frame-ancestors 'self';img-src 'self' data:;object-src 'none';script-src 'self';script-src-attr 'none';style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests",
```

```ts
// Use the defaults but "default-src 'none'
app.use(
  honoHelmet({
    contentSecurityPolicy: {
      defaultSrc: ["'none'"],
    },
  }),
);

// Use the defaults but "default-src 'self' 'nonce-<nonce>'
app.use(
  honoHelmet({
    contentSecurityPolicy: {
      defaultSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
    },
  }),
);

// Use the defaults but disable "default-src"
app.use(
  honoHelmet({
    contentSecurityPolicy: {
      defaultSrc: false,
    },
  }),
);

// Disable the defaults and "default-src 'none'
app.use(
  honoHelmet({
    contentSecurityPolicy: {
      useDefaults: false,
      defaultSrc: ["'none'"],
    },
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({crossOriginEmbedderPolicy: options})</code></summary>

Default:

```
Cross-Origin-Embedder-Policy: require-corp
```

```ts
// Cross-Origin-Embedder-Policy: credentialless
app.use(
  honoHelmet({
    crossOriginEmbedderPolicy: {
      policy: "credentialless",
    },
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({crossOriginOpenerPolicy: options})</code></summary>

Default:

```
Cross-Origin-Opener-Policy: same-origin
```

```ts
// Cross-Origin-Opener-Policy: same-origin-allow-popups
app.use(
  honoHelmet({
    crossOriginOpenerPolicy: {
      policy: "same-origin-allow-popups",
    },
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({referrerPolicy: options})</code></summary>

Default:

```
Referrer-Policy: no-referrer
```

```ts
// Referrer-Policy: no-referrer-when-downgrade
app.use(
  honoHelmet({
    referrerPolicy: {
      policy: "no-referrer-when-downgrade",
    },
  }),
);

// Referrer-Policy: origin,no-referrer-when-downgrade
app.use(
  honoHelmet({
    referrerPolicy: {
      policy: ["origin", "no-referrer-when-downgrade"],
    },
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({hsts: options})</code></summary>

Default:

```
Strict-Transport-Security: max-age=15552000; includeSubDomains
```

```ts
// Strict-Transport-Security: max-age=123456; includeSubDomains
app.use(
  honoHelmet.hsts({
    maxAge: 123456,
  }),
);

// Strict-Transport-Security: max-age=123456
app.use(
  honoHelmet.hsts({
    maxAge: 123456,
    includeSubDomains: false,
  }),
);

// Strict-Transport-Security: max-age=123456; includeSubDomains; preload
app.use(
  honoHelmet.hsts({
    maxAge: 63072000,
    preload: true,
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({nosniff: options})</code></summary>

Default:

```
X-Content-Type-Options: nosniff
```

```ts
// Disable X-Content-Type-Options: nosniff
app.use(
  honoHelmet({
    nosniff: false,
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({originAgentCluster: options})</code></summary>

Default:

```
Origin-Agent-Cluster: ?1
```

```ts
// Origin-Agent-Cluster: ?0
app.use(
  honoHelmet({
    originAgentCluster: "?0",
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({dnsPrefetchControl: options})</code></summary>

Default:

```
X-DNS-Prefetch-Control: off
```

```ts
// X-DNS-Prefetch-Control: on
app.use(
  honoHelmet({
    dnsPrefetchControl: {
      allow: true,
    },
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({ieNoOpen: options})</code></summary>

Default:

```
X-Download-Options: noopen
```

```ts
// Disable X-Download-Options: noopen
app.use(
  honoHelmet({
    ieNoOpen: false,
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({frameguard: options})</code></summary>

Default:

```
X-Frame-Options: SAMEORIGIN
```

```ts
// X-Frame-Options: DENY
app.use(
  honoHelmet({
    frameguard: {
      action: "deny",
    },
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({permittedCrossDomainPolicies: options})</code></summary>

Default:

```
X-Permitted-Cross-Domain-Policies: none
```

```ts
// X-Permitted-Cross-Domain-Policies: by-content-type
app.use(
  honoHelmet({
    permittedCrossDomainPolicies: {
      permittedPolicies: "by-content-type",
    },
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({hidePoweredBy: options})</code></summary>

Default: options === true

```ts
// X-Permitted-Cross-Domain-Policies: by-content-type
app.use(
  honoHelmet({
    hidePoweredBy: false,
  }),
);
```

</details>

<details>
<summary><code>honoHelmet({xssFilter: options})</code></summary>

Default:

```
X-XSS-Protection: 0
```

```ts
// Disable X-XSS-Protection: 0
app.use(
  honoHelmet({
    xssFilter: false,
  }),
);
```

</details>
