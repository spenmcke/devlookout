import { source } from '@/lib/source';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import { baseOptions, DocsSidebarFooter } from '@/lib/layout.shared';
import styles from './layout.module.css';

export default function InstallLayout({ children }: LayoutProps<'/install'>) {
  const options = baseOptions();

  return (
    <DocsLayout
      {...options}
      tree={source.getPageTree()}
      sidebar={{ footer: <DocsSidebarFooter /> }}
      containerProps={{ className: styles.layout }}
    >
      {children}
    </DocsLayout>
  );
}
