import { buildUrl, fetchJson } from "../http";

export type CrmAccount = {
  id: string;
  name: string;
  domain: string;
  plan: string;
  arr_usd: number;
  region: string;
  managed: boolean;
  csm: string | null;
  contacts: Array<{
    name: string;
    role: string;
    email: string;
    primary?: boolean;
  }>;
};

type MatchResponse = {
  assignee: {
    name: string;
    email: string;
    focus: string;
    embedded_team: string;
    prior_fixes: string[];
  } | null;
  score: number;
};

export class CrmClient {
  constructor(private readonly baseUrl: string) {}

  async getAccountByDomain(domain: string): Promise<CrmAccount> {
    return fetchJson<CrmAccount>(
      buildUrl(this.baseUrl, `/accounts/by-domain/${encodeURIComponent(domain)}`),
      {},
      5000
    );
  }

  async matchEngineer(focus: string, label: string): Promise<MatchResponse> {
    return fetchJson<MatchResponse>(
      buildUrl(this.baseUrl, "/support-engineers/match", { focus, label }),
      {},
      5000
    );
  }
}
