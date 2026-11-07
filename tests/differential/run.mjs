// Differential test of the JS core against the Rust core (PLAN.md phase 6). Reads the cases that
// `cargo run -p xtask -- differential` wrote (one JSON object per line: `op`, `input`, and Rust's `output` or `error`),
// runs each through the vector operations of packages/rootcard/test/ops.mjs and requires the same output or the same
// error code. Every disagreement, and every exception that is not a RootcardError, goes to the mismatch file.
//
//   node tests/differential/run.mjs <cases.jsonl> <mismatches.jsonl>
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { ops, setSha256Sync } from "../../packages/rootcard/test/ops.mjs";
import { canonicalString, RootcardError } from "../../packages/rootcard/src/index.js";

setSha256Sync((m) => new Uint8Array(createHash("sha256").update(m).digest()));

const [casesPath, mismatchPath] = process.argv.slice(2);
if (!casesPath || !mismatchPath) {
  console.error("usage: node tests/differential/run.mjs <cases.jsonl> <mismatches.jsonl>");
  process.exit(2);
}

const show = (r) => ("error" in r ? `error ${r.error}` : "exception" in r ? `exception ${r.exception}` : "output");

const lines = readFileSync(casesPath, "utf8").split("\n").filter((l) => l.length > 0);
const mismatches = [];
const perOp = new Map();
for (const [n, line] of lines.entries()) {
  const c = JSON.parse(line);
  const rust = "error" in c ? { error: c.error } : { output: c.output };
  let js;
  try {
    const op = ops[c.op];
    if (!op) throw new Error(`no operation ${c.op}`);
    js = { output: await op(c.input) };
  } catch (e) {
    js = e instanceof RootcardError ? { error: e.code } : { exception: String(e?.stack ?? e) };
  }
  let same = false;
  if ("output" in rust && "output" in js) {
    try {
      same = canonicalString(js.output) === canonicalString(rust.output);
    } catch (e) {
      js = { exception: `output is not canonical JSON: ${e}` };
    }
  } else if ("error" in rust && "error" in js) {
    same = rust.error === js.error;
  }
  const count = perOp.get(c.op) ?? { cases: 0, errors: 0, mismatches: 0 };
  count.cases += 1;
  if ("error" in rust) count.errors += 1;
  if (!same) {
    count.mismatches += 1;
    mismatches.push({ case: n + 1, op: c.op, input: c.input, rust, js });
  }
  perOp.set(c.op, count);
}

writeFileSync(mismatchPath, mismatches.map((m) => JSON.stringify(m)).join("\n") + (mismatches.length ? "\n" : ""));
for (const [op, { cases, errors, mismatches: bad }] of [...perOp].sort()) {
  console.log(`  ${op.padEnd(24)} ${String(cases).padStart(6)} cases, ${String(errors).padStart(6)} rejected${bad ? `, ${bad} MISMATCHES` : ""}`);
}
for (const m of mismatches.slice(0, 10)) {
  console.error(`case ${m.case} (${m.op}): Rust ${show(m.rust)}, JS ${show(m.js)}`);
  console.error(`  input ${JSON.stringify(m.input).slice(0, 400)}`);
}
if (mismatches.length > 0) {
  console.error(`${mismatches.length} of ${lines.length} cases disagree; all of them are in ${mismatchPath}`);
  process.exit(1);
}
console.log(`differential: the JS core agrees with the Rust core on all ${lines.length} cases`);
