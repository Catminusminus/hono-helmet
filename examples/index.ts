import { Hono } from "hono";
import { honoHelmet } from "../src/index";
import { serve } from "@hono/node-server";

export const app = new Hono();

app.use(honoHelmet());
app.get("/", (c) => c.text("Hello Hono!"));

serve(app);
