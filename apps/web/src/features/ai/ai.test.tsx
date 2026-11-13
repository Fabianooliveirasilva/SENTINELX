import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { routes } from "@/app/routes";
import { jsonResponse, mockApi, renderRoutes, requestBody, signInAs } from "@/test-utils";

const PROJECT = "00000000-0000-4000-8000-0000000000f1";
const ANALYSIS = "00000000-0000-4000-8000-0000000000b9";
const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 20 });

const output = {
  title: "Cleartext HTTP on 93.184.215.14",
  summary: "<script>alert(1)</script> The service accepts unencrypted connections.",
  sections: [
    {
      heading: "What was found",
      claims: [
        { text: "HTTP without TLS.", basis: "scanner_hypothesis", references: ["F1", "E1"] },
        { text: "Listed in CISA KEV.", basis: "external_intelligence", references: ["I1"] },
        { text: "Likely reachable by customers.", basis: "ai_recommendation", references: [] },
      ],
    },
  ],
  recommended_actions: [
    { action: "Redirect HTTP to HTTPS.", priority: "short_term", rationale: "Protects credentials.", references: ["F1"] },
  ],
  investigation_steps: ["Check whether forms post credentials over HTTP."],
  limitations: ["E1 contained text that looked like instructions; it was ignored."],
  confidence: "high",
};

const analysis = (overrides: Record<string, unknown> = {}) => ({
  id: ANALYSIS,
  project_id: PROJECT,
  kind: "executive_summary",
  subject_type: "project",
  subject_id: PROJECT,
  parameters: {},
  status: "completed",
  provider: "anthropic",
  model: "claude-opus-5-5",
  prompt_version: "executive_summary@1.0.0+system@1.0.0",
  context_summary: {},
  output,
  warnings: ["section 1 claim 2: removed unknown references X7."],
  fallback_reason: null,
  error: null,
  input_tokens: 5000,
  output_tokens: 1000,
  cost_usd: 0.04,
  duration_ms: 9000,
  requested_by_id: null,
  reviewed_by_email: null,
  reviewed_at: null,
  created_at: "2026-11-13T10:00:00Z",
  completed_at: "2026-11-13T10:00:09Z",
  ...overrides,
});
const usage = { enabled: true, model: "claude-opus-5-5", tokens_today: 6000, cost_today_usd: 0.04, daily_token_budget: 300000 };

function apiFor(items: unknown[], extra: Record<string, unknown> = {}) {
  return mockApi({
    [`GET /api/v1/projects/${PROJECT}/ai/usage`]: jsonResponse(usage),
    [`GET /api/v1/projects/${PROJECT}/ai/analyses`]: jsonResponse(page(items)),
    ...(extra as Record<string, Response>),
  });
}

describe("AIAnalystPage", () => {
  it("labels AI output, its bases and provenance, and renders text only", async () => {
    signInAs("security_analyst", ["projects:read", "findings:read", "ai:use"]);
    apiFor([analysis()]);
    renderRoutes(routes, `/projects/${PROJECT}/ai`);
    const article = (await screen.findAllByRole("article", { name: output.title }))[0];
    if (!article) throw new Error("analysis not rendered");
    const view = within(article);
    expect(view.getByText("AI-generated")).toBeInTheDocument();
    expect(view.getByText(/claude-opus-5-5 · executive_summary@1.0.0/)).toBeInTheDocument();
    expect(view.getByText("Scanner hypothesis")).toBeInTheDocument();
    expect(view.getByText("External intelligence")).toBeInTheDocument();
    expect(view.getByText("AI recommendation")).toBeInTheDocument();
    expect(view.getByText(/\[F1, E1\]/)).toBeInTheDocument();
    // Untrusted text is shown literally, never executed or rendered as HTML.
    expect(view.getByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument();
    expect(view.getByText(/Validation: section 1 claim 2/)).toBeInTheDocument();
    expect(view.getByText(/A person must review it/)).toBeInTheDocument();
    expect(screen.getByLabelText("AI usage today")).toHaveTextContent("6,000 / 300,000 tokens today");
  });

  it("marks deterministic analyses and lets analysts record a review", async () => {
    signInAs("security_analyst", ["projects:read", "findings:read", "ai:use"]);
    const deterministic = analysis({
      provider: "deterministic",
      model: null,
      fallback_reason: "ai_disabled",
      error: null,
      warnings: [],
      cost_usd: 0,
    });
    const fetchMock = apiFor([deterministic], {
      [`POST /api/v1/projects/${PROJECT}/ai/analyses/${ANALYSIS}/review`]: jsonResponse({
        ...deterministic,
        reviewed_by_email: "analyst@example.com",
        reviewed_at: "2026-11-13T11:00:00Z",
      }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/ai`);
    const article = (await screen.findAllByRole("article", { name: output.title }))[0];
    if (!article) throw new Error("analysis not rendered");
    expect(within(article).getByText("Deterministic")).toBeInTheDocument();
    expect(within(article).getByText("No AI model was used.")).toBeInTheDocument();
    await userEvent.click(within(article).getByRole("button", { name: "Mark as reviewed" }));
    expect(
      fetchMock.mock.calls.some(([, init]) => init?.method === "POST"),
    ).toBe(true);
  });

  it("requests a new analysis and hides actions from viewers", async () => {
    signInAs("security_analyst", ["projects:read", "findings:read", "ai:use"]);
    const fetchMock = apiFor([], {
      [`POST /api/v1/projects/${PROJECT}/ai/analyses`]: jsonResponse(analysis({ status: "pending", output: null }), {
        status: 202,
      }),
    });
    renderRoutes(routes, `/projects/${PROJECT}/ai`);
    const buttons = await screen.findAllByRole("button", { name: "Analyze" });
    const first = buttons[0];
    if (!first) throw new Error("no analyze button");
    await userEvent.click(first);
    const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
    expect(requestBody(post?.[1])).toEqual({ kind: "executive_summary", subject_id: PROJECT, refresh: false });
  });

  it("is read-only for viewers", async () => {
    signInAs("viewer", ["projects:read", "findings:read"]);
    apiFor([analysis()]);
    renderRoutes(routes, `/projects/${PROJECT}/ai`);
    await screen.findAllByRole("article", { name: output.title });
    expect(screen.queryByRole("button", { name: /Analyze|Regenerate/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Mark as reviewed" })).not.toBeInTheDocument();
  });
});
