import fs from "node:fs/promises";
import path from "node:path";
import type { FaultCase } from "../../../../packages/shared/src/faults";

export async function readFaultSource(fault: FaultCase): Promise<{ file: string; contents: string }> {
  const absolute = path.resolve(process.cwd(), fault.sourceFile);
  const contents = await fs.readFile(absolute, "utf8");
  return {
    file: fault.sourceFile,
    contents
  };
}
