import fs from "node:fs/promises";
import path from "node:path";
import type { Diagnosis } from "../types";

type CacheRecord = {
  created_at: string;
  diagnosis: Diagnosis;
};

export class DiagnosisCache {
  constructor(private readonly directory: string) {}

  async read(key: string): Promise<Diagnosis | undefined> {
    try {
      const raw = await fs.readFile(this.fileFor(key), "utf8");
      const parsed = JSON.parse(raw) as CacheRecord;
      return parsed.diagnosis;
    } catch {
      return undefined;
    }
  }

  async write(key: string, diagnosis: Diagnosis): Promise<void> {
    await fs.mkdir(this.directory, { recursive: true });
    const record: CacheRecord = {
      created_at: new Date().toISOString(),
      diagnosis
    };
    await fs.writeFile(this.fileFor(key), JSON.stringify(record, null, 2));
  }

  private fileFor(key: string): string {
    return path.join(this.directory, `${key}.json`);
  }
}
