"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, setTokens } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Button, Card, Input } from "@/components/ui";

export default function RegisterPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [fullName, setFullName] = useState("");
  const [org, setOrg] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const data = await api<{ access_token: string; refresh_token: string }>("/auth/register", {
        method: "POST",
        body: { email, password, full_name: fullName, organization_name: org },
      });
      setTokens(data.access_token, data.refresh_token);
      await login(email, password);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center px-4 py-10">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-bold tracking-tight">
            Sentinel<span className="text-accent">X</span>
          </h1>
          <p className="mt-1 text-sm text-muted">Create your organization</p>
        </div>
        <Card className="p-6">
          <form onSubmit={submit} className="space-y-4">
            <Input label="Full name" value={fullName} onChange={setFullName} placeholder="Alex Analyst" />
            <Input label="Email" type="email" value={email} onChange={setEmail} required placeholder="you@company.com" />
            <Input label="Organization name" value={org} onChange={setOrg} required placeholder="Acme Security" />
            <Input label="Password (min 10 chars)" type="password" value={password} onChange={setPassword} required />
            {error && <p className="rounded-md border border-high/40 bg-high/10 px-3 py-2 text-sm text-red-300">{error}</p>}
            <Button type="submit" disabled={busy} className="w-full">
              {busy ? "Creating…" : "Create account"}
            </Button>
          </form>
        </Card>
        <p className="mt-4 text-center text-sm text-muted">
          Already have an account?{" "}
          <Link href="/login" className="text-accent hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </main>
  );
}
