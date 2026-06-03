import fs from "node:fs";
import path from "node:path";
import dotenv from "dotenv";

let loaded = false;

export function loadEnvFiles(startDir = process.cwd()): void {
  if (loaded) {
    return;
  }

  const candidates = [
    path.resolve(startDir, ".env.local"),
    path.resolve(startDir, ".env"),
    path.resolve(startDir, "../.env"),
    path.resolve(startDir, "../../.env")
  ];

  for (const file of candidates) {
    if (fs.existsSync(file)) {
      dotenv.config({ path: file, override: false });
    }
  }

  loaded = true;
}

export function firstEnv(keys: string[], fallback = ""): string {
  for (const key of keys) {
    const value = process.env[key];
    if (value && value.trim()) {
      return value.trim();
    }
  }
  return fallback;
}

export function envNumber(key: string, fallback: number): number {
  const value = process.env[key];
  if (!value) {
    return fallback;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}
