#!/usr/bin/env node
// Follow public repos without the maintainer installing anything (docs/findings.md).
//
//   node scripts/watch.mjs   (env below; run by .github/workflows/watch.yml)
//
// 1. Targets: "owner/repo path" lines from TARGETS_URL (the ledger's scan-targets.txt).
// 2. Fast path: GH Archive (a public record of GitHub events) for the last few
//    hours; a PushEvent to a target repo makes its targets candidates. GitHub's
//    public event feed is sampled (a few thousand events an hour), so this only
//    catches some pushes early.
// 3. Sweep, the main path: up to SWEEP more targets, never-checked first, then
//    least recently checked. Hourly runs of a few thousand cycle through every
//    target about once a day.
// 4. For each candidate, one batched GraphQL query reads the latest commit that
//    touched its path on the default branch. A commit not yet in the state is
//    dispatched to scan.yml at SCAN_TAG, 50 per run.
//
// State (STATE_IN → STATE_OUT, a TSV of repo, path, commit, checkedAt) carries the
// last commit dispatched per target between runs. Nothing here signs anything:
// scan.yml does, at a release tag.
//
// Env: GH_TOKEN, TARGETS_URL, STATE_IN, STATE_OUT, SCAN_TAG, HOURS (default 3),
//      SWEEP (default 3000), MAX (default 1000), DRY_RUN=1, REPO (default workrr-trust/certify)
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createInterface } from "node:readline";
import { Readable } from "node:stream";
import { createGunzip } from "node:zlib";

const env = process.env;
const REPO = env.REPO || "workrr-trust/certify";
const HOURS = Number(env.HOURS || 3);
const SWEEP = Number(env.SWEEP || 3000);
const MAX = Number(env.MAX || 1000);
const DRY = env.DRY_RUN === "1";
const REPO_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
const PATH_RE = /^([A-Za-z0-9._@+-]+(\/[A-Za-z0-9._@+-]+)*|\.)$/;

const log = (...a) => console.log(...a);

async function gh(method, url, body) {
  for (let attempt = 1; ; attempt++) {
    const res = await fetch(`https://api.github.com${url}`, {
      method,
      headers: {
        authorization: `Bearer ${env.GH_TOKEN}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
      },
      body: body && JSON.stringify(body),
    });
    if (res.ok) return res.status === 204 ? null : res.json();
    if (attempt < 4 && (res.status >= 500 || res.status === 403 || res.status === 429)) {
      await new Promise((r) => setTimeout(r, attempt * 15000));
      continue;
    }
    throw new Error(`${method} ${url}: ${res.status} ${(await res.text()).slice(0, 300)}`);
  }
}

async function loadTargets() {
  const text = env.TARGETS_URL.startsWith("http")
    ? await (await fetch(env.TARGETS_URL)).text()
    : readFileSync(env.TARGETS_URL, "utf8");
  const out = [];
  const seen = new Set();
  for (const raw of text.split("\n")) {
    const [repo, path] = raw.replace(/#.*/, "").trim().split(/\s+/);
    if (!repo) continue;
    const dotSegment = path !== "." && /\/\.\.?\//.test(`/${path}/`);
    if (!REPO_RE.test(repo) || !path || !PATH_RE.test(path) || dotSegment) {
      log(`skip target: ${raw.trim()}`);
      continue;
    }
    const key = `${repo.toLowerCase()} ${path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ repo, path, key });
  }
  return out;
}

function loadState() {
  const state = new Map();
  if (env.STATE_IN && existsSync(env.STATE_IN)) {
    for (const line of readFileSync(env.STATE_IN, "utf8").split("\n")) {
      const [repo, path, commit, checkedAt] = line.split("\t");
      if (repo && path) state.set(`${repo.toLowerCase()} ${path}`, { commit, checkedAt });
    }
  }
  return state;
}

// Repo names (lowercased) that had a PushEvent in one GH Archive hour.
async function pushedRepos(hour, wanted) {
  const name = `${hour.toISOString().slice(0, 10)}-${hour.getUTCHours()}`;
  const res = await fetch(`https://data.gharchive.org/${name}.json.gz`);
  if (!res.ok) {
    log(`gharchive ${name}: ${res.status}, skipped`);
    return new Set();
  }
  const found = new Set();
  const re = /"type":"PushEvent".*?"repo":\{"id":\d+,"name":"([^"]+)"/;
  const lines = createInterface({ input: Readable.fromWeb(res.body).pipe(createGunzip()), crlfDelay: Infinity });
  let n = 0;
  for await (const line of lines) {
    n++;
    if (!line.includes('"PushEvent"')) continue;
    const m = re.exec(line);
    if (m && wanted.has(m[1].toLowerCase())) found.add(m[1].toLowerCase());
  }
  log(`gharchive ${name}: ${n} events, ${found.size} target repo(s) pushed`);
  return found;
}

// Latest commit touching each target's path on its default branch.
async function latestCommits(targets) {
  const out = new Map();
  for (let i = 0; i < targets.length; i += 40) {
    const chunk = targets.slice(i, i + 40);
    const fields = chunk.map((t, j) => {
      const [owner, name] = t.repo.split("/");
      const history = t.path === "." ? "history(first: 1)" : `history(first: 1, path: ${JSON.stringify(t.path)})`;
      return `t${j}: repository(owner: ${JSON.stringify(owner)}, name: ${JSON.stringify(name)}) {
        isPrivate isArchived defaultBranchRef { target { ... on Commit { ${history} { nodes { oid } } } } } }`;
    });
    let data;
    try {
      data = (await gh("POST", "/graphql", { query: `{ ${fields.join("\n")} }` })).data ?? {};
    } catch (e) {
      log(`graphql: ${e.message}`);
      continue;
    }
    chunk.forEach((t, j) => {
      const r = data[`t${j}`];
      const oid = r?.defaultBranchRef?.target?.history?.nodes?.[0]?.oid;
      out.set(t.key, !r || r.isPrivate || r.isArchived ? { gone: true } : { commit: oid });
    });
  }
  return out;
}

async function main() {
  const targets = await loadTargets();
  const state = loadState();
  const byRepo = new Map();
  for (const t of targets) {
    const k = t.repo.toLowerCase();
    if (!byRepo.has(k)) byRepo.set(k, []);
    byRepo.get(k).push(t);
  }
  log(`${targets.length} target(s) in ${byRepo.size} repo(s); ${state.size} in state`);

  const candidates = new Map();
  const now = Date.now();
  for (let h = HOURS; h >= 1; h--) {
    const hour = new Date(now - h * 3600_000);
    for (const repo of await pushedRepos(hour, byRepo)) for (const t of byRepo.get(repo)) candidates.set(t.key, t);
  }
  const changed = candidates.size;
  const sweep = targets
    .filter((t) => !candidates.has(t.key))
    .sort((a, b) => (state.get(a.key)?.checkedAt ?? "").localeCompare(state.get(b.key)?.checkedAt ?? ""))
    .slice(0, SWEEP);
  for (const t of sweep) candidates.set(t.key, t);
  log(`${changed} changed, ${sweep.length} swept`);

  const latest = await latestCommits([...candidates.values()]);
  const checkedAt = new Date().toISOString();
  const queue = [];
  for (const t of candidates.values()) {
    const l = latest.get(t.key);
    if (!l) continue; // query failed; try again next run
    const prev = state.get(t.key) ?? {};
    if (!l.gone && l.commit && l.commit !== prev.commit) {
      if (queue.length >= MAX) continue; // over the cap: state untouched, so a later run dispatches it
      queue.push({ repository: t.repo, commit: l.commit, path: t.path });
      state.set(t.key, { commit: l.commit, checkedAt });
    } else {
      state.set(t.key, { commit: prev.commit ?? "", checkedAt });
    }
  }
  log(`${queue.length} to scan at ${env.SCAN_TAG}${DRY ? " (dry run)" : ""}`);
  for (let i = 0; i < queue.length; i += 50) {
    const batch = queue.slice(i, i + 50);
    for (const t of batch) log(`  ${t.repository}@${t.commit.slice(0, 12)} ${t.path}`);
    if (!DRY) {
      await gh("POST", `/repos/${REPO}/actions/workflows/scan.yml/dispatches`, {
        ref: env.SCAN_TAG,
        inputs: { targets: JSON.stringify(batch) },
      });
    }
  }
  if (env.STATE_OUT) {
    const byKey = new Map(targets.map((t) => [t.key, t]));
    const rows = [...state].map(([key, v]) => {
      const t = byKey.get(key);
      const [repo, path] = t ? [t.repo, t.path] : key.split(" ");
      return [repo, path, v.commit ?? "", v.checkedAt ?? ""].join("\t");
    });
    writeFileSync(env.STATE_OUT, rows.join("\n") + "\n");
  }
}

main().catch((e) => {
  console.error(`watch: ${e.message}`);
  process.exit(1);
});
