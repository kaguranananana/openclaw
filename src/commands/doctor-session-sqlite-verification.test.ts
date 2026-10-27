import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, expect, it } from "vitest";
import type { SessionSqliteMigrationTargetManifest } from "../infra/session-sqlite-migration-manifest.js";
import { createTrackedTempDirs } from "../test-utils/tracked-temp-dirs.js";
import { createRecoveryDestinationVerifier } from "./doctor-session-sqlite-verification.js";

const tempDirs = createTrackedTempDirs();
afterEach(async () => {
  await tempDirs.cleanup();
});

function createWalDatabase(sqlitePath: string): void {
  fs.mkdirSync(path.dirname(sqlitePath), { recursive: true });
  const db = new DatabaseSync(sqlitePath);
  try {
    db.exec("PRAGMA journal_mode=WAL");
    db.exec("CREATE TABLE sessions (key TEXT PRIMARY KEY, value TEXT)");
  } finally {
    db.close();
  }
}

function fixtureTarget(root: string): {
  target: SessionSqliteMigrationTargetManifest;
  sqlitePath: string;
} {
  const sqlitePath = path.join(root, "agents", "main", "agent", "openclaw-agent.sqlite");
  createWalDatabase(sqlitePath);
  const stat = fs.statSync(sqlitePath, { bigint: true });
  const target = {
    agentId: "main",
    databaseIdentity: { dev: String(stat.dev), ino: String(stat.ino) },
    completedMoves: [],
    issues: [],
    plannedMoves: [],
    sqlitePath,
    storePath: sqlitePath,
    validationBeforeArchive: "passed",
  } as SessionSqliteMigrationTargetManifest;
  return { target, sqlitePath };
}

/** Mirrors the apply's own read-only verification opens; each open moves -shm. */
function openAndCloseReadOnly(sqlitePath: string): void {
  const db = new DatabaseSync(sqlitePath, { readOnly: true });
  try {
    db.prepare("SELECT count(*) FROM sessions").get();
  } finally {
    db.close();
  }
}

it("tolerates sidecar changes from the cleanup's own read-only SQLite opens", async () => {
  const root = await tempDirs.make("recovery-destination-");
  const { target } = fixtureTarget(root);
  const verifier = createRecoveryDestinationVerifier(root);

  expect(() => verifier([{ target }])).not.toThrow();

  openAndCloseReadOnly(target.sqlitePath);
  expect(fs.existsSync(`${target.sqlitePath}-shm`)).toBe(true);
  expect(() => verifier([{ target }])).not.toThrow();
});

it("still rejects a replaced destination database file", async () => {
  const root = await tempDirs.make("recovery-destination-");
  const { target, sqlitePath } = fixtureTarget(root);
  const verifier = createRecoveryDestinationVerifier(root);
  expect(() => verifier([{ target }])).not.toThrow();

  fs.rmSync(sqlitePath);
  createWalDatabase(sqlitePath);
  expect(() => verifier([{ target }])).toThrowError(
    "Recovery destination database changed; preview cleanup again.",
  );
});

it("still rejects main database timestamp changes", async () => {
  const root = await tempDirs.make("recovery-destination-");
  const { target, sqlitePath } = fixtureTarget(root);
  const verifier = createRecoveryDestinationVerifier(root);
  expect(() => verifier([{ target }])).not.toThrow();

  const future = new Date(Date.now() + 5_000);
  fs.utimesSync(sqlitePath, future, future);
  expect(() => verifier([{ target }])).toThrowError(
    "Recovery destination database changed; preview cleanup again.",
  );
});
