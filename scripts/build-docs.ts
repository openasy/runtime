// Copies Swagger UI from node_modules next to our page, so the image serves it without a CDN.
import { copyFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const out = new URL("../dist/docs/", import.meta.url).pathname;
const swagger = dirname(createRequire(import.meta.url).resolve("swagger-ui-dist/package.json"));
const src = new URL("../api-docs/", import.meta.url).pathname;

mkdirSync(out, { recursive: true });
for (const f of ["swagger-ui-bundle.js", "swagger-ui.css"]) copyFileSync(join(swagger, f), join(out, f));
for (const f of ["index.html", "init.js"]) copyFileSync(join(src, f), join(out, f));
console.log(`API reference written to ${out}`);
