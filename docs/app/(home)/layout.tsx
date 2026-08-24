import { HomeLayout } from 'fumadocs-ui/layouts/home';
import { baseOptions } from '@/lib/layout.shared';

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <HomeLayout {...baseOptions()}>
      {children}
      <footer className="site-footer">
        <span>Lookout</span>
        <a href="mailto:support@devlookout.com">support@devlookout.com</a>
      </footer>
    </HomeLayout>
  );
}
