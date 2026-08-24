const allowed = new Set(['docs_index_copied', 'docs_full_copied', 'agent_prompt_copied', 'support_guide_opened']);

export async function POST(request: Request) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get('content-type') ?? '')) return new Response(null, { status: 400 });
  const declared = request.headers.get('content-length');
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > 128)) return new Response(null, { status: 413 });
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > 128) return new Response(null, { status: 413 });
  let input: unknown;
  try { input = JSON.parse(text); } catch { return new Response(null, { status: 400 }); }
  if (!input || typeof input !== 'object' || Array.isArray(input) || Object.keys(input).length !== 1 || !allowed.has(String((input as { event?: unknown }).event ?? ''))) return new Response(null, { status: 400 });
  console.log(JSON.stringify({ event: 'lookout_docs_agent_action', action: (input as { event: string }).event }));
  return new Response(null, { status: 204 });
}
