/**
 * darkmatter-js — TypeScript/Node.js SDK
 * npm install darkmatter-js
 */

const DM_BASE = 'https://darkmatterhub.ai';

function getKey(): string {
  const key = process.env.DARKMATTER_API_KEY || '';
  if (!key) throw new Error(
    'No API key found. Set DARKMATTER_API_KEY or pass apiKey option.\n' +
    'Get a free key: https://darkmatterhub.ai/signup'
  );
  return key;
}

interface DarkMatterOptions {
  apiKey?: string;
  baseUrl?: string;
}

interface CommitOptions {
  toAgentId: string;
  payload: Record<string, unknown>;
  parentId?: string;
  traceId?: string;
  branchKey?: string;
  eventType?: string;
  agent?: { role?: string; provider?: string; model?: string };
  apiKey?: string;
}

interface CommitResult {
  id: string;
  integrity: { verification_status: string; integrity_hash: string };
  created_at: string;
}

async function req<T>(
  method: string,
  path: string,
  body?: unknown,
  apiKey?: string
): Promise<T> {
  const key = apiKey || getKey();
  const url = DM_BASE + path;

  const response = await fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${key}`,
      'User-Agent': 'darkmatter-js/0.1.0',
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const data = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}

// ── Module-level functions ────────────────────────────────────────────────────

export async function commit(options: CommitOptions): Promise<CommitResult> {
  const { toAgentId, payload, parentId, traceId, branchKey, eventType, agent, apiKey } = options;
  return req<CommitResult>('POST', '/api/commit', {
    toAgentId, payload, parentId, traceId,
    branchKey: branchKey || 'main',
    eventType: eventType || 'commit',
    agent,
  }, apiKey);
}

export async function replay(ctxId: string, options?: { full?: boolean; apiKey?: string }) {
  const mode = options?.full ? '?mode=full' : '?mode=summary';
  return req('GET', `/api/replay/${ctxId}${mode}`, undefined, options?.apiKey);
}

export async function fork(ctxId: string, options?: { toAgentId?: string; branchKey?: string; apiKey?: string }) {
  return req('POST', `/api/fork/${ctxId}`, {
    toAgentId: options?.toAgentId,
    branchKey: options?.branchKey || 'fork',
  }, options?.apiKey);
}

export async function diff(ctxIdA: string, ctxIdB: string, options?: { apiKey?: string }) {
  return req('GET', `/api/diff/${ctxIdA}/${ctxIdB}`, undefined, options?.apiKey);
}

export async function verify(ctxId: string, options?: { apiKey?: string }) {
  return req('GET', `/api/verify/${ctxId}`, undefined, options?.apiKey);
}

export async function share(ctxId: string, label?: string, options?: { apiKey?: string }) {
  return req('POST', `/api/share/${ctxId}`, { label }, options?.apiKey);
}

export async function bundle(ctxId: string, options?: { apiKey?: string }) {
  return req('GET', `/api/bundle/${ctxId}`, undefined, options?.apiKey);
}

export async function me(options?: { apiKey?: string }) {
  return req('GET', '/api/me', undefined, options?.apiKey);
}

export async function spawn(name: string, options?: {
  role?: string; model?: string; provider?: string; apiKey?: string;
}) {
  return req('POST', '/api/agents/register', {
    agentName: name,
    role:     options?.role,
    model:    options?.model,
    provider: options?.provider,
  }, options?.apiKey);
}

// ── Class interface ───────────────────────────────────────────────────────────

export class DarkMatter {
  private key: string;
  agentId?: string;
  agentName?: string;

  constructor(options?: DarkMatterOptions) {
    this.key = options?.apiKey || getKey();
  }

  commit(options: Omit<CommitOptions, 'apiKey'>) {
    return commit({ ...options, apiKey: this.key });
  }
  replay(ctxId: string, full?: boolean) {
    return replay(ctxId, { full, apiKey: this.key });
  }
  fork(ctxId: string, toAgentId?: string, branchKey?: string) {
    return fork(ctxId, { toAgentId, branchKey, apiKey: this.key });
  }
  diff(a: string, b: string) {
    return diff(a, b, { apiKey: this.key });
  }
  verify(ctxId: string) {
    return verify(ctxId, { apiKey: this.key });
  }
  share(ctxId: string, label?: string) {
    return share(ctxId, label, { apiKey: this.key });
  }
  bundle(ctxId: string) {
    return bundle(ctxId, { apiKey: this.key });
  }
  me() {
    return me({ apiKey: this.key });
  }
  async spawn(name: string, role?: string, model?: string) {
    const child = await spawn(name, { role, model, apiKey: this.key }) as {
      agentId: string; apiKey: string; agentName: string;
    };
    const client = new DarkMatter({ apiKey: child.apiKey });
    client.agentId   = child.agentId;
    client.agentName = child.agentName;
    return client;
  }
}

export default DarkMatter;
