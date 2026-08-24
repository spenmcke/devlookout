import { RootProvider } from 'fumadocs-ui/provider/next';
import './global.css';
import type { Metadata } from 'next';

export const metadata: Metadata = {
  metadataBase: new URL('https://docs.devlookout.com'),
  title: {
    default: 'Lookout Documentation',
    template: '%s | Lookout Documentation',
  },
  description: 'Security observability for private networks and self-hosted applications.',
  alternates: {
    canonical: '/',
  },
  openGraph: {
    title: 'Lookout Documentation',
    description: 'Install Lookout security observability for private networks and self-hosted applications.',
    type: 'website',
  },
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en">
      <body className="flex flex-col min-h-screen">
        <RootProvider search={{ enabled: false }} theme={{ enabled: false }}>
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
