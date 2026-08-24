import { source } from '@/lib/source';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { baseOptions, DocsSidebarFooter } from '@/lib/layout.shared';
import styles from '../install/layout.module.css';

export default function PrivacyLayout({ children }: LayoutProps<'/privacy'>) {
  return (
    <DocsLayout
      {...baseOptions()}
      tree={source.getPageTree()}
      sidebar={{ footer: <DocsSidebarFooter /> }}
      containerProps={{ className: styles.layout }}
    >
      {children}
    </DocsLayout>
  );
}
