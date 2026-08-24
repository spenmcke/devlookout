import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import Image from 'next/image';
import Link from 'next/link';
import { appName } from './shared';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="brand-title">
          <Image src="/lookout-logo.svg" alt="" width={24} height={24} />
          {appName}
        </span>
      ),
      url: '/',
    },
    links: [
      {
        type: 'button',
        text: 'Open Lookout',
        url: 'https://app.devlookout.com',
        external: true,
      },
    ],
    searchToggle: {
      enabled: false,
    },
    themeSwitch: {
      enabled: false,
    },
  };
}

export function DocsSidebarFooter() {
  return <Link className="docs-sidebar-footer-link" href="/privacy">Privacy Policy</Link>;
}
