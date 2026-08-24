import { llmsIndex } from '@/lib/agent-content';

export const dynamic = 'force-static';

export function GET() {
  return new Response(llmsIndex(), { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'public, max-age=300' } });
}
