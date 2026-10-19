// Deterministic suite: the skill must declare its trigger and its steps.
const fs = require("node:fs");
const text = fs.readFileSync(__dirname + "/SKILL.md", "utf8");
const ok = /description: .*Use when/.test(text) && /^1\. /m.test(text);
if (!ok) { console.error("SKILL.md is missing a trigger or numbered steps"); process.exit(1); }
console.log("csv-summary: 1/1 checks pass");
