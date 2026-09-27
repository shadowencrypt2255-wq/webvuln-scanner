"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { api, clearTokens, setTokens } from "./api";
import type { Me, MeOrganization, Project } from "./types";

interface AuthState {
  me: Me | null;
  loading: boolean;
  org: MeOrganization | null;
  project: Project | null;
  projects: Project[];
  setOrg: (orgId: number) => void;
  setProject: (project: Project | null) => void;
  refreshProjects: () => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  hasPerm: (perm: string) => boolean;
}

const Ctx = createContext<AuthState | null>(null);

const ORG_KEY = "sx_org";
const PROJECT_KEY = "sx_project";

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [org, setOrgState] = useState<MeOrganization | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [project, setProjectState] = useState<Project | null>(null);

  const loadMe = useCallback(async () => {
    try {
      const data = await api<Me>("/auth/me");
      setMe(data);
      let selectedOrg = data.organizations[0] || null;
      try {
        const savedOrg = Number(localStorage.getItem(ORG_KEY));
        const found = data.organizations.find((o) => o.id === savedOrg);
        if (found) selectedOrg = found;
      } catch {
        /* ignore */
      }
      setOrgState(selectedOrg);
    } catch {
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadMe();
  }, [loadMe]);

  const refreshProjects = useCallback(async () => {
    if (!org) {
      setProjects([]);
      return;
    }
    try {
      const data = await api<Project[]>(`/organizations/${org.id}/projects`);
      setProjects(data);
      let selected = data[0] || null;
      try {
        const savedP = Number(localStorage.getItem(PROJECT_KEY));
        const found = data.find((p) => p.id === savedP);
        if (found) selected = found;
      } catch {
        /* ignore */
      }
      setProjectState(selected);
    } catch {
      setProjects([]);
    }
  }, [org]);

  useEffect(() => {
    if (org) refreshProjects();
  }, [org, refreshProjects]);

  const setOrg = useCallback(
    (orgId: number) => {
      const found = me?.organizations.find((o) => o.id === orgId) || null;
      setOrgState(found);
      setProjectState(null);
      try {
        if (found) localStorage.setItem(ORG_KEY, String(found.id));
      } catch {
        /* ignore */
      }
    },
    [me],
  );

  const setProject = useCallback((p: Project | null) => {
    setProjectState(p);
    try {
      if (p) localStorage.setItem(PROJECT_KEY, String(p.id));
    } catch {
      /* ignore */
    }
  }, []);

  const login = useCallback(
    async (email: string, password: string) => {
      const data = await api<{ access_token: string; refresh_token: string }>("/auth/login", {
        method: "POST",
        body: { email, password },
      });
      setTokens(data.access_token, data.refresh_token);
      setLoading(true);
      await loadMe();
      router.push("/dashboard");
    },
    [loadMe, router],
  );

  const logout = useCallback(() => {
    api("/auth/logout", { method: "POST" }).catch(() => undefined);
    clearTokens();
    setMe(null);
    setOrgState(null);
    setProjects([]);
    setProjectState(null);
    router.push("/login");
  }, [router]);

  const hasPerm = useCallback(
    (perm: string) => !!org && org.permissions.includes(perm),
    [org],
  );

  return (
    <Ctx.Provider
      value={{
        me,
        loading,
        org,
        project,
        projects,
        setOrg,
        setProject,
        refreshProjects,
        login,
        logout,
        hasPerm,
      }}
    >
      {children}
    </Ctx.Provider>
  );
}

export function useAuth(): AuthState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
