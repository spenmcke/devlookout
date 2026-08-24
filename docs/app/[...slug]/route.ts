import { source } from '@/lib/source';

export async function GET(_request: Request, context: { params: Promise<{ slug: string[] }> }) {
  const { slug } = await context.params;
  const last = slug.at(-1);
  if (!last?.endsWith('.md')) return new Response('Not found', { status: 404 });
  const page = source.getPage([...slug.slice(0, -1), last.slice(0, -3)]);
  if (!page) return new Response('Not found', { status: 404 });
  return new Response(await page.data.getText('processed'), {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8', 'Cache-Control': 'public, max-age=300', 'X-Content-Type-Options': 'nosniff' },
  });
}
