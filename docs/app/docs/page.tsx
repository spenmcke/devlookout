import { permanentRedirect } from 'next/navigation';

export default function LegacyDocsPage() {
  permanentRedirect('/install');
}
