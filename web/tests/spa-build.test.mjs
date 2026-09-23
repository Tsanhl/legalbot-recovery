import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

async function read(relativePath) {
  return readFile(new URL(relativePath, root), "utf8");
}

async function builtJavaScript() {
  const assetsUrl = new URL("dist/assets/", root);
  const assets = await readdir(assetsUrl);
  const scripts = assets.filter((name) => name.endsWith(".js"));
  assert.ok(scripts.length > 0, "Vite must emit a JavaScript application bundle");
  return Promise.all(scripts.map((name) => readFile(new URL(name, assetsUrl), "utf8")))
    .then((parts) => parts.join("\n"));
}

test("one chat bundle excludes owner dashboards and privileged controls", async () => {
  const [html, bundle, entry] = await Promise.all([read("dist/index.html"), builtJavaScript(), read("src/main.tsx")]);
  assert.match(html, /assets\/[^"']+\.js/);
  assert.match(entry, /<LegalBotApp \/>/);
  assert.match(bundle, /Legal research you can inspect/);
  assert.match(bundle, /Full OSCOLA by default/);
  assert.doesNotMatch(bundle, /Clean-room system|Local owner console|Live evaluation observability|Owner access key|authority hash/);
});

test("session API does not persist credentials or send privileged headers", async () => {
  const source = await read("app/lib/chat-api.ts");
  assert.match(source, /credentials: 'same-origin'/);
  assert.match(source, /X-Remote-Processing-Consent/);
  assert.doesNotMatch(source, /localStorage|sessionStorage|x-development-chat-access-key|process\.env/);
});

test("released Markdown citations become safe evidence controls", async () => {
  const [source, drawer] = await Promise.all([
    read("app/components/AnswerMarkdown.tsx"),
    read("app/components/EvidenceDrawer.tsx"),
  ]);
  assert.match(source, /#evidence-/);
  assert.match(source, /className="inline-citation"/);
  assert.match(source, /onEvidence\(citation\)/);
  assert.match(source, /citationLabelContent/);
  assert.match(source, /<em key=/);
  assert.match(source, /replaceAll\("&amp;", "&"\)/);
  assert.match(drawer, /citationLabelContent\(record\.canonical_citation/);
  assert.doesNotMatch(source, /dangerouslySetInnerHTML/);
  assert.doesNotMatch(drawer, /dangerouslySetInnerHTML/);
});

test("no Next, Vinext or Cloudflare runtime remains", async () => {
  const [manifest, lockfile] = await Promise.all([
    read("package.json"),
    read("package-lock.json"),
  ]);
  for (const text of [manifest, lockfile]) {
    assert.doesNotMatch(
      text,
      /@cloudflare\/vite-plugin|react-server-dom-webpack|wrangler|vinext|@vitejs\/plugin-rsc|@next\/eslint-plugin-next/,
    );
  }
});
