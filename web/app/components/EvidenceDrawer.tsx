import { useEffect, useMemo, useState } from "react";
import { api, formatApiError } from "../lib/api";
import type { AnswerEvidence, EvidenceRecord } from "../lib/contracts";
import { citationLabelContent } from "./AnswerMarkdown";
import { Icons } from "./Icons";

export interface EvidenceSelection {
  answerId: string;
  evidenceId: string;
  citationLabel: string;
}

interface EvidenceDrawerProps {
  selection: EvidenceSelection | null;
  onClose: () => void;
}

function sourceTitle(evidence: EvidenceRecord): string {
  const data = evidence.citation_data;
  for (const value of [data.title, data.case_name, data.book_title]) {
    if (typeof value === "string" && value.trim()) return value;
  }
  return evidence.canonical_citation || "Verified legal source";
}

export function EvidenceDrawer({ selection, onClose }: EvidenceDrawerProps) {
  const [response, setResponse] = useState<AnswerEvidence | null>(null);
  const [failure, setFailure] = useState<{ answerId: string; message: string } | null>(null);
  const bundle = response?.answer_id === selection?.answerId ? response : null;
  const error = failure && failure.answerId === selection?.answerId ? failure.message : "";

  useEffect(() => {
    if (!selection) return;
    let current = true;
    api.evidence(selection.answerId)
      .then((value) => {
        if (!current) return;
        setResponse(value);
        setFailure(null);
      })
      .catch((reason) => {
        if (!current) return;
        setFailure({ answerId: selection.answerId, message: formatApiError(reason) });
      });
    return () => {
      current = false;
    };
  }, [selection]);

  useEffect(() => {
    if (!selection) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [selection, onClose]);

  const record = useMemo(
    () => bundle?.evidence.find((item) => item.id === selection?.evidenceId) || null,
    [bundle, selection],
  );
  const claims = useMemo(
    () => bundle?.claims.filter((claim) => selection && claim.evidence_ids.includes(selection.evidenceId)) || [],
    [bundle, selection],
  );
  const currentnessReview = record?.case_currentness_reviews.at(-1) || null;

  if (!selection) return null;

  return (
    <>
      <button className="drawer-scrim" aria-label="Close evidence" onClick={onClose} />
      <aside className="evidence-drawer" aria-label="Source evidence" aria-modal="true" role="dialog">
        <div className="evidence-head">
          <div>
            <span className="eyebrow">Source of truth</span>
            <h2>Claim evidence</h2>
          </div>
          <button className="icon-button" type="button" onClick={onClose} aria-label="Close evidence drawer">
            <Icons.close />
          </button>
        </div>

        {!bundle && !error && (
          <div className="drawer-loading" role="status">
            <span className="spinner" />
            Loading exact source span…
          </div>
        )}

        {error && (
          <div className="empty-state compact" role="alert">
            <Icons.alert size={22} />
            <strong>Evidence is temporarily unavailable</strong>
            <p>{error}</p>
          </div>
        )}

        {bundle && !record && (
          <div className="empty-state compact" role="alert">
            <Icons.alert size={22} />
            <strong>Evidence record not found</strong>
            <p>The answer references {selection.evidenceId}, but that span is not in the released evidence bundle.</p>
          </div>
        )}

        {bundle && record && (
          <div className="evidence-content">
            <section className="evidence-section claim-section">
              <span className="section-label">Supported answer claim{claims.length === 1 ? "" : "s"}</span>
              {claims.length ? claims.map((claim) => (
                <div key={claim.id} className="claim-record">
                  <p>{claim.text}</p>
                  <span className={`status-label ${claim.verification_status.replaceAll("_", "-")}`}>
                    <i />{claim.verification_status.replaceAll("_", " ")}
                  </span>
                  {claim.verification_reason && <small>{claim.verification_reason}</small>}
                </div>
              )) : <p>No claim link was returned for this evidence span.</p>}
            </section>

            <section className="citation-panel">
              <span className="section-label">Full OSCOLA citation</span>
              <p>{citationLabelContent(record.canonical_citation || selection.citationLabel)}</p>
              <div className="evidence-tags">
                <span>{record.lane.replaceAll("_", " ")}</span>
                <span>{record.subject}</span>
                <span>{record.jurisdiction}</span>
              </div>
            </section>

            <section className="evidence-section">
              <div className="evidence-title-row">
                <div>
                  <span className="section-label">Verified source</span>
                  <h3>{sourceTitle(record)}</h3>
                </div>
              </div>
              <dl className="evidence-meta">
                <div><dt>Currentness</dt><dd>{record.currentness_status}</dd></div>
                <div><dt>Identity</dt><dd>{record.identity_verified ? "Verified" : "Not verified"}</dd></div>
                <div><dt>Current law</dt><dd>{record.currentness_verified ? "Verified" : "Not verified"}</dd></div>
                {currentnessReview && (
                  <>
                    <div><dt>Later treatment</dt><dd>{currentnessReview.later_treatment_status.replaceAll("_", " ")}</dd></div>
                    <div><dt>Reviewed as of</dt><dd>{currentnessReview.later_treatment_reviewed_as_of_date}</dd></div>
                  </>
                )}
                <div><dt>Index build</dt><dd>{record.index_build_id}</dd></div>
              </dl>
            </section>

            <section className="evidence-section">
              <span className="section-label">Reviewed legal locator</span>
              <p>{record.locator}</p>
              <small>Source text remains in the encrypted, owner-reviewed evidence store.</small>
            </section>

            <details className="provenance-details">
              <summary>Technical provenance</summary>
              <dl>
                <div><dt>Evidence ID</dt><dd>{record.id}</dd></div>
                <div><dt>Content hash</dt><dd>{record.content_sha256}</dd></div>
                <div><dt>Source version</dt><dd>{record.source_version_id}</dd></div>
                <div><dt>Chunk ID</dt><dd>{record.chunk_id}</dd></div>
                {typeof record.retrieval_relevance_score === "number" && (
                  <div><dt>Retrieval relevance</dt><dd>{Math.round(record.retrieval_relevance_score * 100)}%</dd></div>
                )}
                <div><dt>Legal role</dt><dd>{record.legal_role || "Unclassified"}</dd></div>
              </dl>
            </details>
          </div>
        )}
      </aside>
    </>
  );
}
