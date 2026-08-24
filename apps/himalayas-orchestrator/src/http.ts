export class HttpError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly body: string
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export async function fetchJson<T>(
  url: string,
  init: RequestInit = {},
  timeoutMs = 8000
): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      ...init,
      signal: controller.signal
    });
    const text = await response.text();

    if (!response.ok) {
      throw new HttpError(`${init.method ?? "GET"} ${url} failed with ${response.status}`, response.status, text);
    }

    return (text ? JSON.parse(text) : {}) as T;
  } finally {
    clearTimeout(timeout);
  }
}

export function buildUrl(baseUrl: string, path: string, query: Record<string, string | number | undefined> = {}): string {
  const url = new URL(path, normalizeBaseUrl(baseUrl));
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== "") {
      url.searchParams.set(key, String(value));
    }
  }
  return url.toString();
}

function normalizeBaseUrl(value: string): string {
  return value.endsWith("/") ? value : `${value}/`;
}
