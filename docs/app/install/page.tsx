import { source } from '@/lib/source';
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
} from 'fumadocs-ui/layouts/docs/page';
import { getMDXComponents } from '@/components/mdx';
import { AgentCommandLinks } from '@/components/agent-command-links';
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';

export const metadata: Metadata = {
  title: 'Quickstart',
  description: 'Install Lookout on supported Linux VMs through the guided Setup flow.',
  alternates: { canonical: '/install' },
};

export default function InstallPage() {
  const page = source.getPage(['install']);
  if (!page) notFound();

  const MDX = page.data.body;

  return (
    <DocsPage toc={page.data.toc} full={page.data.full}>
      <DocsTitle>{page.data.title}</DocsTitle>
      <DocsDescription className="quickstart-description">{page.data.description}</DocsDescription>
      <AgentCommandLinks />
      <DocsBody>
        <MDX components={getMDXComponents()} />
      </DocsBody>
    </DocsPage>
  );
}
