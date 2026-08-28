import type {
  LiveEvaluationReleasedAnswer,
  LiveEvaluationRunDetail,
  LiveEvaluationRunList,
  LiveEvaluationRunSummary,
} from "../../lib/contracts";
import { Icons } from "../Icons";
import { MetricCard, Status, duration, number } from "./widgets";

interface LiveEvaluationPanelProps {
  liveEvaluations: LiveEvaluationRunList;
  selectedLiveRun: LiveEvaluationRunSummary | undefined;
  effectiveLiveRunId: string;
  liveRunDetail: LiveEvaluationRunDetail | null;
  liveRunLoading: boolean;
  releasedEvaluationAnswer: LiveEvaluationReleasedAnswer | null;
  onSelectRun: (runId: string) => void;
  onOpenReleasedAnswer: (caseId: string, passNumber: number) => void;
  onCloseReleasedAnswer: () => void;
}

export function LiveEvaluationPanel({
  liveEvaluations,
  selectedLiveRun,
  effectiveLiveRunId,
  liveRunDetail,
  liveRunLoading,
  releasedEvaluationAnswer,
  onSelectRun,
  onOpenReleasedAnswer,
  onCloseReleasedAnswer,
}: LiveEvaluationPanelProps) {
  return (
    <section className="admin-section" id="live-evaluation">
      <div className="section-heading inline-heading">
        <div>
          <span className="eyebrow">Evaluation-only · owner view</span>
          <h2>Live evaluation results and refinement ledger</h2>
        </div>
        <label className="review-filter live-run-selector">
          <span>Run</span>
          <select
            aria-label="Live evaluation run"
            disabled={!liveEvaluations.items.length || liveRunLoading}
            value={effectiveLiveRunId}
            onChange={(event) => onSelectRun(event.target.value)}
          >
            {!liveEvaluations.items.length && <option value="">No runs created</option>}
            {liveEvaluations.items.map((run) => (
              <option key={run.run_id} value={run.run_id}>
                {run.run_id} · {run.status.replaceAll("_", " ")}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="live-evaluation-privacy-note">
        This list contains safe IDs, gates and diagnostics only. Questions and held drafts stay
        encrypted. A full answer is decrypted into this local owner view only after its release,
        evidence and privacy records all pass again.
      </p>

      {selectedLiveRun ? (
        <>
          <div className="metric-grid">
            <MetricCard
              label="Pass-one terminal cases"
              value={`${selectedLiveRun.completed_case_count}/${selectedLiveRun.selected_generation_case_count ?? selectedLiveRun.expected_case_count}`}
              note={`${selectedLiveRun.pass_outcome_count} total pass outcomes recorded`}
              tone={selectedLiveRun.completed_case_count === (selectedLiveRun.selected_generation_case_count ?? selectedLiveRun.expected_case_count) ? "green" : "default"}
            />
            <MetricCard
              label="Released outcomes"
              value={number(selectedLiveRun.released_outcome_count)}
              note={`${number(selectedLiveRun.limited_outcome_count)} verified limited`}
            />
            <MetricCard
              label="Held or failed"
              value={number(selectedLiveRun.held_or_failed_outcome_count)}
              note="Never decrypted by the results feed"
              tone={selectedLiveRun.held_or_failed_outcome_count ? "amber" : "green"}
            />
            <MetricCard
              label="Run privacy report"
              value={selectedLiveRun.privacy_report_passed === true ? "Passed" : selectedLiveRun.privacy_report_passed === false ? "Failed" : "Not finalised"}
              note={`${selectedLiveRun.as_of_date} · local-only · not training data`}
              tone={selectedLiveRun.privacy_report_passed === true ? "green" : selectedLiveRun.privacy_report_passed === false ? "amber" : "default"}
            />
          </div>

          <div className="table-shell live-evaluation-table-shell" aria-busy={liveRunLoading}>
            <table>
              <thead>
                <tr><th>Case</th><th>Route / target</th><th>Passes</th><th>Latest outcome</th><th>Evidence / review</th></tr>
              </thead>
              <tbody>
                {liveRunDetail?.cases.map((item) => {
                  const latestPass = item.passes.at(-1);
                  return (
                    <tr key={item.case_id}>
                      <td><strong>Q{item.ordinal}</strong><small className="table-subline"><code>{item.case_id}</code></small></td>
                      <td>
                        {item.expected_research_route?.replaceAll("_", " ") || "—"}
                        <small className="table-subline">{number(item.word_target)} words</small>
                      </td>
                      <td>
                        {item.passes.length ? item.passes.map((pass) => (
                          <button
                            className={`pass-button ${pass.released ? "released" : "not-released"}`}
                            disabled={!pass.released}
                            key={pass.pass_number}
                            onClick={() => void onOpenReleasedAnswer(item.case_id, pass.pass_number)}
                            title={pass.released ? "Open released answer" : "Held and failed answers cannot be opened"}
                            type="button"
                          >
                            P{pass.pass_number} · {pass.release_state.replaceAll("_", " ")}
                          </button>
                        )) : <span className="table-muted">Not run</span>}
                      </td>
                      <td>
                        <Status value={item.release_state} />
                        {latestPass && <small className="table-subline">
                          {number(latestPass.word_count || undefined)} words · {duration((latestPass.completion_duration_ms || 0) / 1_000)}
                        </small>}
                      </td>
                      <td>
                        {latestPass ? (
                          <details className="live-case-diagnostics">
                            <summary>
                              {latestPass.evidence.length} evidence · {item.issues.length} issues · {item.knowledge_gaps.length} gaps
                            </summary>
                            <div className="live-case-diagnostic-body">
                              <p><strong>Trace:</strong> <code>{latestPass.trace_id || "not recorded"}</code></p>
                              <p><strong>Advisory rules fired:</strong> {latestPass.rule_evaluation_state === "recorded"
                                ? latestPass.triggered_assessment_rule_ids.join(", ") || "none"
                                : "not recorded — bundle membership is not treated as a trigger"}</p>
                              <p><strong>Repairs:</strong> {latestPass.repairs.length
                                ? latestPass.repairs.map((repair) => `${repair.reason_code} (${repair.status})`).join(", ")
                                : "none recorded"}</p>
                              <p><strong>Failure codes:</strong> {latestPass.failure_codes.join(", ") || "none"}</p>
                              {latestPass.evidence.map((evidence) => (
                                <div className="safe-evidence-row" key={evidence.evidence_span_id}>
                                  <code>{evidence.evidence_span_id}</code>
                                  <span>{evidence.stable_source_id} · {evidence.legal_locator}</span>
                                  <small>{evidence.legal_role} · {evidence.support_state} · {evidence.currentness_state} · {evidence.jurisdiction_state}</small>
                                </div>
                              ))}
                              {[...item.issues, ...item.knowledge_gaps].map((diagnostic) => (
                                <div className="safe-diagnostic-row" key={diagnostic.id}>
                                  <code>{diagnostic.id}</code>
                                  <span>{diagnostic.category.replaceAll("_", " ")} · {diagnostic.status.replaceAll("_", " ")}</span>
                                </div>
                              ))}
                            </div>
                          </details>
                        ) : <span className="table-muted">Awaiting execution</span>}
                      </td>
                    </tr>
                  );
                })}
                {!liveRunDetail?.cases.length && (
                  <tr><td colSpan={5} className="empty-table">{liveRunLoading ? "Loading the safe run manifest…" : "The selected run has no readable case registry."}</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      ) : (
        <div className="review-empty live-evaluation-empty">
          <Icons.file size={24} />
          <strong>No controlled live-evaluation run exists</strong>
          <p>No ACTIVE candidate or answer generation is implied. Once a controlled manifest-driven run is created, every selected and coverage-only case will appear explicitly.</p>
          {liveEvaluations.invalid_run_count > 0 && <p>{liveEvaluations.invalid_run_count} invalid run director{liveEvaluations.invalid_run_count === 1 ? "y was" : "ies were"} excluded by integrity checks.</p>}
        </div>
      )}

      {releasedEvaluationAnswer && (
        <article className="admin-panel released-evaluation-answer" aria-label="Released evaluation answer">
          <div className="panel-heading">
            <div>
              <span className="eyebrow">Released owner artifact</span>
              <h2>{releasedEvaluationAnswer.case_id} · pass {releasedEvaluationAnswer.pass_number}</h2>
            </div>
            <button type="button" onClick={onCloseReleasedAnswer}>Close</button>
          </div>
          <p>{number(releasedEvaluationAnswer.word_count || undefined)} words · {releasedEvaluationAnswer.release_state.replaceAll("_", " ")} · digest <code>{releasedEvaluationAnswer.answer_sha256}</code></p>
          <pre>{releasedEvaluationAnswer.content}</pre>
        </article>
      )}
    </section>
  );
}
