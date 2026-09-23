import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";

const stamp = "2026-09-08T12:00:00+00:00";

function answer(answerId: string, jobId: string) {
  return {
    id: answerId,
    job_id: jobId,
    content: "The released explanation is supported by [*Example Act* 2026, s 1](#evidence-ev-1).",
    word_count: 12,
    release_state: "verified_full",
    policy_version: "policy-browser-fixture",
    model_version: "model-browser-fixture",
    index_build_id: "index-browser-fixture",
    quality: null,
    created_at: stamp,
  };
}

function job(jobId: string, overrides: Record<string, unknown> = {}) {
  return {
    id: jobId,
    status: "complete",
    stage: "complete",
    progress: 1,
    question_summary: "A visible browser test question",
    answer_id: `answer-${jobId}`,
    release_state: "verified_full",
    message: "Released",
    jurisdiction: "Texas",
    as_of_date: "2026-09-08",
    conversation_id: "conversation-restored-browser",
    trace_id: `trace-${jobId}`,
    last_progress_at: stamp,
    created_at: stamp,
    updated_at: stamp,
    ...overrides,
  };
}

function evidence(answerId: string) {
  return {
    answer_id: answerId,
    claims: [{
      id: "claim-1",
      section_id: "section-1",
      text: "The released explanation is supported.",
      material: true,
      verification_status: "verified",
      verification_reason: null,
      evidence_ids: ["ev-1"],
    }],
    evidence: [{
      id: "ev-1",
      source_version_id: "source-version-1",
      chunk_id: "chunk-1",
      locator: "section 1",
      lane: "primary_authority",
      jurisdiction: "Texas",
      subject: "browser fixture",
      citation_data: { title: "Example Act" },
      canonical_citation: "*Example Act* 2026, s 1",
      currentness_status: "verified",
      content_sha256: "a".repeat(64),
      index_build_id: "index-browser-fixture",
      retrieval_relevance_score: 0.95,
      retrieval_route: "hybrid",
      retrieval_threshold: 0.5,
      retrieval_threshold_policy_sha256: "b".repeat(64),
      retrieval_threshold_qualified: true,
      retrieval_qualification_reason: null,
      legal_role: "binding_legal_rule",
      unapplied_effect_count: 0,
      provision_extent_status: "verified",
      identity_verified: true,
      currentness_verified: true,
      case_currentness_reviews: [],
      case_currentness_manifest_seals: [],
    }],
  };
}

async function installApi(
  page: Page,
  onQuestion?: (body: Record<string, unknown>, headers: Record<string, string>) => void,
) {
  await page.route("**/api/v1/**", async (route: Route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const json = (value: unknown, status = 200) => route.fulfill({
      status,
      contentType: "application/json",
      body: JSON.stringify(value),
    });
    if (path === "/api/v1/health") {
      return json({
        status: "ready",
        api_version: "v1",
        owner_only: true,
        database_ready: true,
        worker_ready: true,
        active_index: "index-browser-fixture",
        model_ready: true,
        model_id: "model-browser-fixture",
        prompt_version: "prompt-browser-fixture",
        router_version: "router-browser-fixture",
        classifier_version: "classifier-browser-fixture",
        policy_sha256: "c".repeat(64),
        assessment_bundle_sha256: "d".repeat(64),
        reasons: [],
      });
    }
    if (path === "/api/v1/conversations") return json({ items: [] });
    if (path === "/api/v1/questions" && request.method() === "POST") {
      const body = request.postDataJSON() as Record<string, unknown>;
      onQuestion?.(body, request.headers());
      return json({
        job_id: "job-submitted",
        status: "queued",
        stage: "queued",
        events_url: "/api/v1/jobs/job-submitted/events",
        conversation_id: String(body.conversation_id),
      }, 202);
    }
    const jobMatch = path.match(/^\/api\/v1\/jobs\/([^/]+)$/);
    if (jobMatch) return json(job(jobMatch[1]));
    const evidenceMatch = path.match(/^\/api\/v1\/answers\/([^/]+)\/evidence$/);
    if (evidenceMatch) return json(evidence(evidenceMatch[1]));
    const answerMatch = path.match(/^\/api\/v1\/answers\/([^/]+)$/);
    if (answerMatch) return json(answer(answerMatch[1], answerMatch[1].replace(/^answer-/, "")));
    return json({ detail: `Unmocked browser fixture route: ${path}` }, 404);
  });
}

test("submits exact UK/USA location and legal as-of date", async ({ page }) => {
  const submitted: Record<string, unknown>[] = [];
  await installApi(page, (body) => submitted.push(body));
  await page.goto("/");
  await page.getByLabel("Jurisdiction").selectOption("Texas");
  await page.getByLabel("Law as of date").fill("2026-09-08");
  await page.getByLabel("Legal research question").fill("Explain the visible Texas rule.");
  await page.getByRole("button", { name: "Research", exact: true }).click();
  await expect(page.getByText("The released explanation is supported by")).toBeVisible();
  expect(submitted).toHaveLength(1);
  expect(submitted[0]).toMatchObject({
    jurisdiction: "Texas",
    as_of_date: "2026-09-08",
    question: "Explain the visible Texas rule.",
  });
  expect(String(submitted[0].conversation_id)).toMatch(/^conversation-/);
});

test("reconnect restores the conversation, jurisdiction and legal date", async ({ page }) => {
  const submitted: Record<string, unknown>[] = [];
  await installApi(page, (body) => submitted.push(body));
  await page.goto("/?job=job-reconnect");
  await expect(page.getByText("The released explanation is supported by")).toBeVisible();
  await expect(page.getByLabel("Jurisdiction")).toHaveValue("Texas");
  await expect(page.getByLabel("Law as of date")).toHaveValue("2026-09-08");
  await page.getByLabel("Legal research question").fill("Continue this restored matter.");
  await page.getByRole("button", { name: "Research", exact: true }).click();
  expect(submitted[0]).toMatchObject({
    conversation_id: "conversation-restored-browser",
    jurisdiction: "Texas",
    as_of_date: "2026-09-08",
  });
});

test("evidence dialog traps focus, restores it, and has no serious axe violations", async ({ page }) => {
  await installApi(page);
  await page.goto("/?job=job-evidence");
  const citation = page.getByRole("button", { name: "Example Act 2026, s 1" });
  await citation.click();
  const dialog = page.getByRole("dialog", { name: "Claim evidence" });
  await expect(dialog).toBeVisible();
  await expect(page.getByRole("button", { name: "Close evidence drawer" })).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(dialog.locator("summary")).toBeFocused();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Close evidence drawer" })).toBeFocused();
  const scan = await new AxeBuilder({ page }).include(".evidence-drawer").analyze();
  expect(scan.violations.filter((item) => ["serious", "critical"].includes(item.impact || ""))).toEqual([]);
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(citation).toBeFocused();
});

test("two browser sessions create distinct conversation identities", async ({ browser }) => {
  const firstContext = await browser.newContext();
  const secondContext = await browser.newContext();
  const first = await firstContext.newPage();
  const second = await secondContext.newPage();
  const identities: string[] = [];
  await installApi(first, (body) => identities.push(String(body.conversation_id)));
  await installApi(second, (body) => identities.push(String(body.conversation_id)));
  await Promise.all([first.goto("/"), second.goto("/")]);
  await first.getByLabel("Legal research question").fill("First isolated visible question.");
  await second.getByLabel("Legal research question").fill("Second isolated visible question.");
  await Promise.all([
    first.getByRole("button", { name: "Research", exact: true }).click(),
    second.getByRole("button", { name: "Research", exact: true }).click(),
  ]);
  expect(identities).toHaveLength(2);
  expect(identities[0]).not.toBe(identities[1]);
  await Promise.all([firstContext.close(), secondContext.close()]);
});

test("development chat sends the selected Codex route and carries a case follow-up", async ({ page }) => {
  const submissions: Array<{ body: Record<string, unknown>; headers: Record<string, string> }> = [];
  await installApi(page, (body, headers) => submissions.push({ body, headers }));
  await page.goto("/");
  await page.getByLabel("Jurisdiction").selectOption("Other");
  await page.getByLabel("Specify jurisdiction").fill("India, Maharashtra");
  await page.getByLabel("Law as of date").fill("2026-09-23");
  await page.getByLabel("Owner development chat").check();
  await page.getByLabel("Development model route").selectOption("codex_bridge");
  await page.getByLabel("Development authority SHA-256").fill("a".repeat(64));
  await page.getByLabel("Development owner access key").fill("local-test-access-key");
  await page.getByLabel("Send this question and selected evidence to the remote model").check();
  await page.getByLabel("Legal research question").fill("A tenancy question with missing facts.");
  await page.getByRole("button", { name: "Research", exact: true }).click();
  await expect(page.getByText("The released explanation is supported by")).toBeVisible();
  await page.getByLabel("Legal research question").fill("Here are the missing facts. Continue the same case.");
  await page.getByRole("button", { name: "Research", exact: true }).click();
  expect(submissions).toHaveLength(2);
  expect(submissions[0].headers["x-development-chat-route"]).toBe("codex_bridge");
  expect(submissions[0].headers["x-development-chat-remote-consent"]).toBe("yes");
  expect(submissions[0].body.jurisdiction).toBe("India, Maharashtra");
  expect(submissions[0].body.conversation_id).toBeUndefined();
  expect(String(submissions[1].body.question)).toContain("A tenancy question with missing facts.");
  expect(String(submissions[1].body.question)).toContain("Here are the missing facts.");
});
