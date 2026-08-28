import type { ReactNode } from "react";

// The label may itself contain OSCOLA neutral-citation brackets such as [2025].
const CITATION = /\[([^\n]*?)\]\(#evidence-([^)]+)\)/g;

export interface CitationToken {
  evidenceId: string;
  label: string;
}

export interface AnswerMarkdownProps {
  content: string;
  onEvidence: (citation: CitationToken) => void;
}

function decodeCitationEntities(value: string): string {
  // The backend HTML-escapes deterministic citation text before embedding it
  // in Markdown. Decode only that fixed escape set and keep React in charge of
  // escaping the resulting text; arbitrary HTML is never parsed or injected.
  return value.replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&amp;", "&");
}

export function citationLabelContent(label: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const emphasis = /\*([^*\n]+)\*/g;
  let cursor = 0;
  let match: RegExpExecArray | null;
  while ((match = emphasis.exec(label)) !== null) {
    if (match.index > cursor) {
      nodes.push(decodeCitationEntities(label.slice(cursor, match.index)));
    }
    nodes.push(<em key={`citation-em-${match.index}`}>{decodeCitationEntities(match[1])}</em>);
    cursor = match.index + match[0].length;
  }
  if (cursor < label.length) nodes.push(decodeCitationEntities(label.slice(cursor)));
  return nodes;
}

function inlineContent(text: string, onEvidence: AnswerMarkdownProps["onEvidence"]): ReactNode[] {
  const nodes: ReactNode[] = [];
  let cursor = 0;
  let match: RegExpExecArray | null;
  CITATION.lastIndex = 0;
  while ((match = CITATION.exec(text)) !== null) {
    if (match.index > cursor) nodes.push(text.slice(cursor, match.index));
    const citation = { label: match[1], evidenceId: match[2] };
    nodes.push(
      <button
        className="inline-citation"
        key={`${citation.evidenceId}-${match.index}`}
        onClick={() => onEvidence(citation)}
        title="Open the exact supporting source span"
        type="button"
      >
        {citationLabelContent(citation.label)}
      </button>,
    );
    cursor = match.index + match[0].length;
  }
  if (cursor < text.length) nodes.push(text.slice(cursor));
  return nodes;
}

export function AnswerMarkdown({ content, onEvidence }: AnswerMarkdownProps) {
  const lines = content.replaceAll("\r\n", "\n").split("\n");
  return (
    <div className="answer-prose">
      {lines.map((line, index) => {
        const key = `${index}-${line.slice(0, 24)}`;
        if (!line.trim()) return <span className="markdown-break" aria-hidden="true" key={key} />;
        if (line.startsWith("# ")) return <h1 key={key}>{inlineContent(line.slice(2), onEvidence)}</h1>;
        if (line.startsWith("## ")) return <h2 key={key}>{inlineContent(line.slice(3), onEvidence)}</h2>;
        if (line.startsWith("### ")) return <h3 key={key}>{inlineContent(line.slice(4), onEvidence)}</h3>;
        if (line.startsWith("- ")) {
          return <ul key={key}><li>{inlineContent(line.slice(2), onEvidence)}</li></ul>;
        }
        return <p key={key}>{inlineContent(line, onEvidence)}</p>;
      })}
    </div>
  );
}

export function citationTokens(content: string): CitationToken[] {
  const matches: CitationToken[] = [];
  CITATION.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = CITATION.exec(content)) !== null) {
    matches.push({ label: match[1], evidenceId: match[2] });
  }
  return matches;
}
