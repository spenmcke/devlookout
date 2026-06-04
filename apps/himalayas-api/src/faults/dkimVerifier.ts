import { DkimVerificationError } from "../errors";
import { addBreadcrumb } from "../sentry";

type DkimSignature = {
  domain: string;
  selector: string;
  bodyHash: string;
  valid: boolean;
};

const forwardedMessage = `DKIM-Signature: v=1; d=forwarder.example; s=mx1; bh=bad;
DKIM-Signature: v=1; d=velto.de; s=mail; bh=good;
From: alerts@velto.de
To: user@example.com
Subject: Invoice notification`;

export function verifyForwardedMessageDkim(): void {
  const signatures = parseDkimSignatures(forwardedMessage);
  addBreadcrumb("dkim signatures parsed", { count: signatures.length });
  const result = verifyFirstSignatureOnly(signatures);

  if (!result.valid) {
    throw new DkimVerificationError(
      `DKIM false negative for ${result.domain}; verifier checked forwarded signature before original domain`
    );
  }
}

function parseDkimSignatures(raw: string): DkimSignature[] {
  return raw
    .split("\n")
    .filter((line) => line.startsWith("DKIM-Signature:"))
    .map((line) => ({
      domain: extract(line, "d") ?? "unknown",
      selector: extract(line, "s") ?? "default",
      bodyHash: extract(line, "bh") ?? "",
      valid: extract(line, "bh") === "good"
    }));
}

function verifyFirstSignatureOnly(signatures: DkimSignature[]): DkimSignature {
  if (signatures.length === 0) {
    throw new DkimVerificationError("no DKIM signatures present");
  }

  for (const signature of signatures) {
    if (signature.valid) {
      addBreadcrumb("dkim verifier selected signature", {
        domain: signature.domain,
        selector: signature.selector,
        body_hash: signature.bodyHash
      });
      return signature;
    }
  }

  const firstDomain = signatures[0]?.domain ?? "unknown";
  throw new DkimVerificationError(`no valid DKIM signatures found; checked ${signatures.length} signature(s) starting with ${firstDomain}`);
}

function extract(line: string, key: string): string | undefined {
  const match = line.match(new RegExp(`${key}=([^;\\s]+)`));
  return match?.[1];
}
