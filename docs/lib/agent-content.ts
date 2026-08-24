import { source } from './source';

const origin = 'https://docs.devlookout.com';

export function publicPages() {
  return source.getPages().slice().sort((left, right) => left.url.localeCompare(right.url));
}

export function llmsIndex() {
  const entries = publicPages().map((page) => {
    const description = page.data.description ? `: ${page.data.description}` : '';
    return `- [${page.data.title}](${origin}${page.url}.md)${description}`;
  });
  return `# Lookout Documentation\n\nUse this index to retrieve only the Markdown pages relevant to a question. Cite the canonical documentation page associated with each Markdown route.\n\n${entries.join('\n')}\n`;
}

export async function llmsFull() {
  const sections = await Promise.all(publicPages().map(async (page) => {
    const markdown = await page.data.getText('processed');
    return `# ${page.data.title}\n\nCanonical URL: ${origin}${page.url}\n\n${markdown.trim()}`;
  }));
  return `# Lookout Documentation full corpus\n\n${sections.join('\n\n---\n\n')}\n`;
}
