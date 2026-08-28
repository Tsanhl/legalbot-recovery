import { useCallback, useEffect, useState } from "react";
import { api, formatApiError } from "../../lib/api";
import type { RuntimeRecordsStatus } from "../../lib/contracts";
import { MetricCard, number } from "./widgets";

const EMPTY_STATUS: RuntimeRecordsStatus = {
  schema: "legalbot.runtime-records-status.v1",
  feedback_count: 0,
  open_incident_count: 0,
  regression_count: 0,
  curation_counts: {},
  eligible_for_training: false,
  training_export_allowed: false,
  plaintext_secrets: false,
};

export function RuntimeRecordsPanel() {
  const [snapshot, setSnapshot] = useState<RuntimeRecordsStatus>(EMPTY_STATUS);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setSnapshot(await api.admin.runtimeRecords());
      setError("");
    } catch (reason) {
      setError(formatApiError(reason));
    }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const curationTotal = Object.values(snapshot.curation_counts).reduce((sum, count) => sum + count, 0);

  return (
    <section className="admin-section" id="runtime-records">
      <div className="section-heading">
        <div>
          <span className="eyebrow">Owner status · no plaintext secrets</span>
          <h2>Feedback, incidents, regressions and curation</h2>
        </div>
      </div>
      <p className="live-evaluation-privacy-note">
        Counts only. Encrypted notes and crash bundles stay in local objects.
        Evaluation artefacts remain ineligible for training.
      </p>
      {error && <p className="admin-error">{error}</p>}
      <div className="metric-grid">
        <MetricCard
          label="Feedback records"
          value={number(snapshot.feedback_count)}
          note="Wrong-answer kinds; notes encrypted"
        />
        <MetricCard
          label="Open incidents"
          value={number(snapshot.open_incident_count)}
          note="Class and fingerprint only in this view"
          tone={snapshot.open_incident_count ? "amber" : "green"}
        />
        <MetricCard
          label="Regression cases"
          value={number(snapshot.regression_count)}
          note="Required before closing a fixable incident"
        />
        <MetricCard
          label="Curation items"
          value={number(curationTotal)}
          note="Live30/Live60 sources cannot enter curation"
        />
      </div>
      <p className="registry-note">
        Training export allowed: {snapshot.training_export_allowed ? "yes" : "no"}
        {" · "}
        Eligible for training: {snapshot.eligible_for_training ? "yes" : "no"}
        {" · "}
        Plaintext secrets: {snapshot.plaintext_secrets ? "present" : "absent"}
      </p>
    </section>
  );
}
