# Helmet Middleware for Hono

Bring [helmet](https://github.com/helmetjs/helmet) to
[Hono](https://github.com/honojs/hono).

## Quick Demo with Deno

```
import { serve } from "https://deno.land/std@0.167.0/http/server.ts";
import { Hono } from "npm:hono@2.7.7";
import { honoHelmet } from "https://github.com/Catminusminus/hono-helmet/raw/main/src/index.ts"

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

The default headers are as follows:

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

To disable headers:

```js
app.use(
  honoHelmet({
    contentSecurityPolicy: false,
  }),
);
```
