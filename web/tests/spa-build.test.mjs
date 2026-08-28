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

test("Vite emits a local SPA shell and both owner views", async () => {
  const [html, bundle, entry] = await Promise.all([
    read("dist/index.html"),
    builtJavaScript(),
    read("src/main.tsx"),
  ]);
  assert.match(html, /<div id="root"><\/div>/);
  assert.match(html, /<title>Counsel — Verified legal research<\/title>/);
  assert.match(html, /assets\/[^"']+\.js/);
  assert.match(entry, /window\.location\.pathname === "\/admin"/);
  assert.match(entry, /<AdminDashboard \/>/);
  assert.match(entry, /<LegalBotApp \/>/);
  assert.match(bundle, /Legal research you can inspect\./);
  assert.match(bundle, /Claim-level evidence/);
  assert.match(bundle, /Full OSCOLA by default/);
  assert.match(bundle, /Advisory 70\+ structure target/);
  assert.match(bundle, /Advisory academic guidance/);
  assert.match(bundle, /advisory structure score/);
  assert.doesNotMatch(bundle, />70\+ academic rubric</);
  assert.match(bundle, /Live evaluation observability/);
  assert.match(bundle, /Stage percentiles/);
  assert.match(bundle, /Active jobs/);
  assert.match(bundle, /Internal, provisional and observe-only/);
  assert.match(bundle, /Live evaluation results and refinement ledger/);
  assert.match(bundle, /No controlled live-evaluation run exists/);
  assert.match(bundle, /Feedback, incidents, regressions and curation/);
  assert.match(bundle, /Source and release health/);
  assert.match(bundle, /Coverage ledger/);
  assert.match(bundle, /A second scan is blocked/);
  assert.match(bundle, /Retry failed scan/);
  assert.match(bundle, /All statuses/);
  assert.match(bundle, /All queues \(advanced\)/);
  assert.match(bundle, /Assessment standards \(owner\)/);
  assert.match(bundle, /Needs verification/);
  assert.match(bundle, /Privacy-safe source IDs are not tasks/);
  assert.match(bundle, /Previous/);
  assert.match(bundle, /matching reviews/);
  assert.match(bundle, /Local owner console/);
  assert.doesNotMatch(bundle, />\s*Sign in\s*</i);
});

test("the API client uses only the clean versioned surface", async () => {
  const source = await read("app/lib/api.ts");
  assert.match(source, /VITE_LEGAL_API_BASE/);
  assert.match(source, /\/api\/v1/);
  assert.match(source, /"\/questions"/);
  assert.match(source, /\/jobs\/\$\{encodeURIComponent\(jobId\)\}\/events/);
  assert.match(source, /jobWebSocketUrl/);
  assert.match(source, /url\.protocol === "https:" \? "wss:" : "ws:"/);
  assert.match(source, /\/answers\/\$\{encodeURIComponent\(answerId\)\}\/evidence/);
  assert.match(source, /"\/uploads"/);
  assert.match(source, /items<ConversationSummary>\("\/conversations"\)/);
  assert.match(source, /\/admin\/reviews\/\$\{encodeURIComponent\(id\)\}\/\$\{decision\}/);
  assert.match(source, /request<ReviewPageResponse>\(`\/admin\/reviews\$\{suffix\}`/);
  assert.match(source, /query\.set\("limit"/);
  assert.match(source, /query\.set\("offset"/);
  assert.match(source, /query\.set\("review_type"/);
  assert.match(source, /query\.set\("status"/);
  assert.match(source, /"\/admin\/sources\/scan"/);
  assert.match(source, /request<ObservabilityAdminView>\("\/admin\/observability"\)/);
  assert.match(source, /request<LiveEvaluationRunList>\("\/admin\/live-evaluations"\)/);
  assert.match(source, /liveEvaluationAnswer/);
  assert.match(source, /request<RuntimeRecordsStatus>\("\/admin\/runtime-records"\)/);
  assert.match(source, /\/admin\/source-scans\/\$\{encodeURIComponent\(id\)\}\/resume/);
  assert.doesNotMatch(source, /NEXT_PUBLIC|\/conversations\/\$\{|evidence_id=/);
  assert.doesNotMatch(source, /chroma|legal_chat_ui|localStorage/i);
});

test("the live-30 owner view exposes safe diagnostics and released prose separately", async () => {
  const [dashboard, panel, contracts] = await Promise.all([
    read("app/components/AdminDashboard.tsx"),
    read("app/components/admin/LiveEvaluationPanel.tsx"),
    read("app/lib/contracts.ts"),
  ]);
  assert.match(dashboard, /<LiveEvaluationPanel/);
  assert.ok(
    dashboard.indexOf("<LiveEvaluationPanel") < dashboard.indexOf('id="sources"'),
    "live evaluation review must precede source operations",
  );
  const start = panel.indexOf('<section className="admin-section" id="live-evaluation">');
  const end = panel.lastIndexOf("</section>");
  assert.ok(start >= 0 && end > start, "live evaluation panel must own the section");
  const section = panel.slice(start, end);
  assert.match(section, /liveRunDetail\?\.cases\.map/);
  assert.match(section, /item\.passes\.at\(-1\)/);
  assert.match(section, /triggered_assessment_rule_ids/);
  assert.match(section, /bundle membership is not treated as a trigger/);
  assert.match(section, /latestPass\.evidence\.map/);
  assert.match(section, /item\.issues/);
  assert.match(section, /item\.knowledge_gaps/);
  assert.match(section, /onOpenReleasedAnswer/);
  assert.match(section, /Held and failed answers cannot be opened/);
  assert.doesNotMatch(section, /dangerouslySetInnerHTML/);
  assert.doesNotMatch(section, /\.question\b|\.answer_artifact_id\b|\.path\b|\.filename\b/);
  assert.match(contracts, /interface LiveEvaluationRunDetail/);
  assert.match(contracts, /interface LiveEvaluationReleasedAnswer/);
});

test("the admin observability component exposes safe live progress and percentile views", async () => {
  const [component, contracts] = await Promise.all([
    read("app/components/AdminDashboard.tsx"),
    read("app/lib/contracts.ts"),
  ]);
  const start = component.indexOf('<section className="admin-section" id="observability">');
  const end = component.indexOf('<section className="admin-section split-section" id="sources">');
  assert.ok(start >= 0 && end > start, "observability section must precede source operations");
  const section = component.slice(start, end);
  assert.match(section, /Provisional SLO/);
  assert.match(section, /Queue depth/);
  assert.match(section, /Oldest queued job/);
  assert.match(section, /progress_state/);
  assert.match(section, /trace_id/);
  assert.match(section, /word_band/);
  assert.match(section, /row\.p50/);
  assert.match(section, /row\.p95/);
  assert.match(section, /row\.p99/);
  assert.doesNotMatch(section, /job\.(?:question|answer|prompt|path|filename|source_text)\b/);
  assert.doesNotMatch(section, /dangerouslySetInnerHTML/);
  assert.match(component, /setInterval\(\(\) => void loadObservability\(\), 5_000\)/);
  assert.match(component, /has not been blind-calibrated/);
  assert.match(component, /not a release gate or a guarantee of a 70\+ mark/);
  assert.match(contracts, /interface ObservabilityAdminView/);
  assert.match(contracts, /progress_state: "fresh" \| "stale" \| "stuck" \| "unbanded"/);
});

test("review pagination stays server-backed and refreshes the current filtered page", async () => {
  const source = await read("app/components/AdminDashboard.tsx");
  assert.match(source, /const REVIEW_PAGE_LIMIT = 50/);
  assert.match(source, /const \[reviewOffset, setReviewOffset\]/);
  assert.match(source, /const \[reviewStatus, setReviewStatus\]/);
  assert.match(source, /const \[reviewType, setReviewType\]/);
  assert.match(source, /reviewRequestSequence/);
  assert.match(source, /reviewAbortController/);
  assert.match(source, /await loadReviews\(\)/);
  assert.match(source, /reviewPage\.items\.map/);
  assert.match(source, /item\.status === "pending"/);
  assert.doesNotMatch(source, /pendingReviewCount/);
  assert.match(source, /setReviewOffset\(lastOffset\)/);
  assert.match(source, /useState\("assessment_rule"\)/);
  assert.match(source, /sourceReadyForOwnerApproval/);
  assert.match(source, /System verification is incomplete/);
  assert.match(source, /Owner review complete/);
  assert.doesNotMatch(source, /data\.reviews|pendingReviews\.map/);
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

test("internal approvals never submit a rejected local-path identity", async () => {
  const source = await read("app/components/AdminDashboard.tsx");
  assert.match(source, /const INTERNAL_SOURCE_ID/);
  assert.match(source, /content-sha256/);
  assert.match(source, /stable_identifier: internalSourceIdentifier\(context\)/);
  assert.match(
    source,
    /function citableSourceIdentifier[\s\S]*?public_identifier_candidate\?\.stable_identifier \|\| context\?\.stable_identifier \|\| ""/,
  );
  assert.match(source, /stable_identifier: citableSourceIdentifier\(context\)/);
  assert.match(source, /context\.material_type === "case" && context\.currentness_status === "historical"/);
  assert.match(source, /span\+proposition-scoped review workflow/);
});

test("research queue copy stays first-live and WebSocket reconnect hydrates by job id", async () => {
  const [admin, appSource] = await Promise.all([
    read("app/components/AdminDashboard.tsx"),
    read("app/components/LegalBotApp.tsx"),
  ]);
  assert.match(admin, /id="research-updates"/);
  assert.match(admin, /Check now/);
  assert.match(admin, /No crawler task has been admitted/);
  assert.match(admin, /Connected scheduling[\s\S]*Disabled/);
  assert.match(admin, /Enabled only after the separate connected-crawler canary/);
  assert.match(appSource, /URLSearchParams\(window\.location\.search\)\.get\("job"\)/);
  assert.match(appSource, /await api\.job\(activeJobId\)/);
  assert.match(appSource, /new WebSocket\(/);
  assert.match(appSource, /socket\.onerror = \(\) => \{/);
  assert.match(appSource, /lastSequence/);
  assert.match(
    appSource,
    /const installAnswer[\s\S]*?submitIdempotency\.current = "";[\s\S]*?clearJobQuery\(\)/,
  );
  assert.match(
    appSource,
    /const endWithoutAnswer[\s\S]*?submitIdempotency\.current = "";[\s\S]*?clearJobQuery\(\)/,
  );
});

test("the owner SPA is loopback-only and proxies only the versioned API", async () => {
  const [manifest, vite] = await Promise.all([
    read("package.json"),
    read("vite.config.ts"),
  ]);
  assert.match(manifest, /vite --host 127\.0\.0\.1 --port 8777 --strictPort/);
  assert.match(manifest, /vite preview --host 127\.0\.0\.1 --port 8777 --strictPort/);
  assert.match(vite, /"\/api"/);
  assert.match(vite, /target: "http:\/\/127\.0\.0\.1:8776"/);
  assert.match(vite, /proxy: apiProxy/);
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
