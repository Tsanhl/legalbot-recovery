export function number(value: number | undefined): string {
  return typeof value === "number" ? value.toLocaleString() : "—";
}

export function duration(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "—";
  if (value < 1) return `${Math.round(value * 1_000)} ms`;
  if (value < 60) return `${value.toFixed(value < 10 ? 2 : 1)} s`;
  const minutes = Math.floor(value / 60);
  const seconds = Math.round(value % 60);
  return `${minutes}m ${seconds}s`;
}

export function MetricCard({
  label,
  value,
  note,
  tone = "default",
}: {
  label: string;
  value: string;
  note: string;
  tone?: string;
}) {
  return (
    <article className={`metric-card ${tone}`}>
      <span>{label}</span><strong>{value}</strong><p>{note}</p>
    </article>
  );
}

export function Status({ value }: { value: string }) {
  return <span className={`status-label ${value.replaceAll("_", "-")}`}><i />{value.replaceAll("_", " ")}</span>;
}
