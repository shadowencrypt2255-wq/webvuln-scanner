"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import type { AiAnswer } from "@/lib/types";
import { NeedProject, PageTitle } from "@/components/page";
import { Button, Card, CardHeader } from "@/components/ui";

const SUGGESTIONS = [
  "What are our highest-risk findings?",
  "Summarize the most recent scan.",
  "Which findings are correlated with alerts?",
  "Generate a remediation plan.",
];

export default function AiPage() {
  const { project } = useAuth();
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<AiAnswer | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  if (!project) return <NeedProject />;

  async function ask(q: string) {
    setBusy(true);
    setError("");
    setAnswer(null);
    try {
      const res = await api<AiAnswer>("/ai/query", {
        method: "POST",
        body: { question: q, project_id: project!.id },
      });
      setAnswer(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Query failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageTitle title="AI Security Analyst" subtitle="Read-only analysis of your authorized data. It never takes actions." />

      <Card className="mb-6 p-5">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (question.trim()) ask(question.trim());
          }}
          className="space-y-3"
        >
          <textarea
            className="w-full rounded-md border border-border bg-surface2 px-3 py-2 text-sm text-fg outline-none focus:border-accent"
            rows={3}
            placeholder="Ask about your findings, risk, scans or correlations…"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
          />
          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" disabled={busy || !question.trim()}>
              {busy ? "Analyzing…" : "Ask analyst"}
            </Button>
            {SUGGESTIONS.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => {
                  setQuestion(s);
                  ask(s);
                }}
                className="rounded-full border border-border px-3 py-1 text-xs text-muted hover:text-fg"
              >
                {s}
              </button>
            ))}
          </div>
        </form>
      </Card>

      {error && <p className="rounded-md border border-high/40 bg-high/10 px-3 py-2 text-sm text-red-300">{error}</p>}

      {answer && (
        <div className="space-y-4">
          <Card>
            <CardHeader title="Facts" subtitle="Drawn directly from your data" />
            <ul className="list-inside list-disc space-y-1 p-5 text-sm text-muted">
              {answer.facts.map((f, i) => (
                <li key={i}>{f}</li>
              ))}
            </ul>
          </Card>
          <Card>
            <CardHeader title="Analysis" subtitle={`Provider: ${answer.provider}`} />
            <p className="whitespace-pre-wrap p-5 text-sm text-fg">{answer.answer}</p>
          </Card>
          <p className="text-xs italic text-muted">{answer.disclaimer}</p>
        </div>
      )}
    </>
  );
}
