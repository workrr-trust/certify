# SkillSpector report (trial)

[SkillSpector](https://github.com/NVIDIA/SkillSpector) is NVIDIA's open-source
scanner for agent skills (Apache-2.0). It covers far more patterns than workrr's
known-pattern scan. workrr isn't affiliated with NVIDIA.

`skillspector-report.yml` runs a pinned SkillSpector commit on one public skill and
saves a repeatable report. **It is a trial.** Nothing is signed, and the report
changes no certificate, level, band or finding.

## Why it is separate from the checks

- **Two implementations.** TypeScript and Go must produce identical `checks`.
  SkillSpector is a Python tool, so it can't be a check.
- **Signing power.** It installs a large dependency tree. It runs in a job with a
  read-only token and no `id-token`, and a test holds that line. If reports are ever
  signed, a separate job signs the file this job produces. A compromised dependency
  could then at worst falsify a report; it could not sign as the certifier.
- **Not a verdict.** The report states what SkillSpector matched, and is attributed
  to it. It never becomes Flagged on its own.

## What the report keeps

Rule, severity, confidence, file and line, plus the tool's version and commit and
how much of the skill it read. `scripts/skillspector-report.mjs` drops:

| Dropped | Why |
|---|---|
| `recommendation`, risk score | The labels include `SAFE`, which workrr never says. `DO_NOT_INSTALL` isn't a workrr verdict |
| Finding text, code snippets | They copy third-party content |
| `finding_id`, `scanned_at`, local paths | They change on every run |
| Rule SC4 | It reads OSV.dev live, so the result depends on the day |
| Rule AE1 (counted under `coverage`) | It reports a limit of the scan, not something the skill does |

## Trial results

SkillSpector v2.13.4, static only, on 57 skills picked at random from
`scan-targets.txt` (2026-11-06), each scanned twice on one machine:

| Measure | Result |
|---|---|
| Time per scan | 8.3 s on average, 38 s at most, four at a time |
| Repeatable | 57 of 57, once `finding_id` and `scanned_at` are removed |
| Changed by going offline | 2 of 57, both only rule SC4 |
| Finished reading the skill | 49 of 57 (25 of those with caveats; 8 partial) |
| Skills with any finding | 24 of 57 |
| Rated `DO_NOT_INSTALL` | 5 of 57 |
| workrr scan failed | 1 of 57 (SkillSpector rated that one `CAUTION`) |

The five `DO_NOT_INSTALL` ratings came mostly from AE1, whitespace padding,
`subprocess` calls and unpinned dependencies. Reading the matched rules, none showed
clear malicious behavior, though the skills themselves weren't audited. That's why
raw results can't become Flagged: at this rate, about one public skill in eleven
would be accused on pattern matches alone.
