"use strict";

/**
 * asep — Proof Gatekeeper agent for the zkVerify Agent Games.
 *
 * A single-file HTTPS endpoint. The platform POSTs HMAC-signed envelopes;
 * this service verifies the signature over the raw body, answers the
 * preflight handshake, and for each payment task makes a deterministic
 * APPROVE / REJECT decision, proves it locally with the official
 * gatekeeper Groth16 circuit (snarkjs), and returns a signed response.
 *
 * Fail-closed throughout: any error, malformed field, or uncertainty
 * resolves to REJECT — never to an unproven APPROVE.
 *
 * Secrets come only from the environment:
 *   AGENT_GAMES_HMAC_SECRET — platform secret (dashboard "Rotate Secret")
 */

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------- config

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const PROTOCOL_VERSION = "v1";
const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const SIG_HEADER = "x-agent-games-signature";
const PROVE_SOFT_DEADLINE_MS = 45_000;

const FIELD_P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const ON_VERCEL = !!process.env.VERCEL;
const STORE_PATH =
  process.env.SEEN_STORE_PATH ||
  (ON_VERCEL
    ? "/tmp/asep-gatekeeper-store.json"
    : path.join(__dirname, "..", "data", "store.json"));
const TMP_ARTIFACT_DIR = ON_VERCEL
  ? "/tmp/asep-circuits"
  : path.join(__dirname, "..", "circuits");
const ARTIFACT_SOURCES = [
  { dir: path.join(__dirname, "..", "circuits"), wasm: "gatekeeper.wasm", zkey: "gatekeeper_final.zkey" },
  { dir: TMP_ARTIFACT_DIR, wasm: "gatekeeper.wasm", zkey: "gatekeeper_final.zkey" },
];
const ARTIFACT_URLS = {
  wasm: "https://agentgames.zkverify.io/circuits/gatekeeper.wasm",
  zkey: "https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey",
};

// ---------------------------------------------------------------- HMAC

function signBody(secret, body) {
  return crypto.createHmac("sha256", secret).update(body).digest("hex");
}

function verifySignature(secret, rawBody, headerValue) {
  if (!secret || !headerValue) return false;
  let v = String(headerValue).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice("sha256=".length).trim();
  let candidate = null;
  if (/^[0-9a-fA-F]{64}$/.test(v)) {
    candidate = Buffer.from(v, "hex");
  } else {
    try {
      const b = Buffer.from(v, "base64");
      if (b.length === 32) candidate = b;
    } catch {
      /* not base64 */
    }
  }
  if (!candidate) return false;
  const expected = crypto.createHmac("sha256", secret).update(rawBody).digest();
  return candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected);
}

/** Deterministic per-task circuit salt, bound to the platform secret. */
function deriveSalt(taskId) {
  const digest = crypto
    .createHmac("sha256", SECRET || "asep-local-dev")
    .update("asep-gatekeeper-salt:" + taskId)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % FIELD_P;
}

// ------------------------------------------------------- field handling

/** Convert an envelope value to a BN128 field element (decimal string). */
function toFieldElement(v) {
  let n;
  if (typeof v === "bigint") {
    n = v;
  } else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else {
      // Free-form identifier (e.g. task_id "gk_8d31_x"): hash into the field.
      const digest = crypto.createHash("sha256").update(s).digest();
      n = BigInt("0x" + digest.toString("hex"));
    }
  }
  return (((n % FIELD_P) + FIELD_P) % FIELD_P).toString(10);
}

function parseUint(v) {
  if (typeof v === "number") {
    return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  }
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}

function normHex(v) {
  return (v ?? "").toString().trim().toLowerCase();
}

// ------------------------------------------------------------- the store
// Seen-set of proof references (PROOF_REUSED trap) plus a task_id ->
// response cache so a redelivered task is answered identically instead
// of being mistaken for proof reuse. Memory is authoritative; a JSON
// file backs it across restarts on a best-effort basis.

const store = {
  seenProofTx: new Set(),
  responseByTaskId: new Map(),
  loaded: false,
  load() {
    if (this.loaded) return;
    this.loaded = true;
    try {
      const data = JSON.parse(fs.readFileSync(STORE_PATH, "utf8"));
      for (const tx of data.proofTx || []) this.seenProofTx.add(normHex(tx));
      for (const [k, v] of Object.entries(data.responses || {})) {
        this.responseByTaskId.set(k, v);
      }
    } catch {
      /* missing or unreadable file -> start empty */
    }
  },
  persist() {
    try {
      fs.mkdirSync(path.dirname(STORE_PATH), { recursive: true });
      const tmp = STORE_PATH + ".tmp";
      fs.writeFileSync(
        tmp,
        JSON.stringify({
          proofTx: [...this.seenProofTx],
          responses: Object.fromEntries(this.responseByTaskId),
        }),
      );
      fs.renameSync(tmp, STORE_PATH);
    } catch (err) {
      console.error("[store] persist failed:", err.message);
    }
  },
  hasProofTx(tx) {
    this.load();
    return this.seenProofTx.has(normHex(tx));
  },
  recordProofTx(tx) {
    this.load();
    const key = normHex(tx);
    if (key && !this.seenProofTx.has(key)) {
      this.seenProofTx.add(key);
      this.persist();
    }
  },
  getResponse(taskId) {
    this.load();
    return this.responseByTaskId.get(taskId) || null;
  },
  recordResponse(taskId, body) {
    this.load();
    if (taskId && !this.responseByTaskId.has(taskId)) {
      this.responseByTaskId.set(taskId, body);
      this.persist();
    }
  },
};

// --------------------------------------------------------- decision core
// The documented trap taxonomy, checked in a fixed order. The gatekeeper
// circuit enforces exactly these comparisons: the `decision` input must
// equal the AND of the five field checks, or witness generation fails —
// so this evaluation mirrors the circuit, boundary semantics included:
//   public_balance >= minimum passes, amount <= max_transfer passes,
//   current_block < expiry_block passes.

function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const parsed = {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum: parseUint(input.minimum),
    publicBalance: parseUint(input.public_balance),
    expiryBlock: parseUint(input.expiry_block),
    currentBlock: parseUint(input.current_block),
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount: parseUint(input.amount),
    maxTransfer: parseUint(input.max_transfer),
    proofTx: input.proof_tx,
  };
  if (
    parsed.minimum === null ||
    parsed.publicBalance === null ||
    parsed.expiryBlock === null ||
    parsed.currentBlock === null ||
    parsed.amount === null ||
    parsed.maxTransfer === null
  ) {
    return null;
  }
  for (const key of ["registeredVk", "proofVk", "recipient", "conditionRecipient", "proofTx"]) {
    if (typeof parsed[key] !== "string" || !parsed[key]) return null;
  }
  return parsed;
}

function evaluate(parsed) {
  if (normHex(parsed.proofVk) !== normHex(parsed.registeredVk)) {
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  }
  if (store.hasProofTx(parsed.proofTx)) {
    // Documented special case: a reused proof has no proof to submit.
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  }
  if (parsed.publicBalance < parsed.minimum) {
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  }
  if (parsed.currentBlock >= parsed.expiryBlock) {
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  }
  if (normHex(parsed.recipient) !== normHex(parsed.conditionRecipient)) {
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  }
  if (parsed.amount > parsed.maxTransfer) {
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  }
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}

function buildCircuitInputs(taskId, parsed, decision) {
  return {
    taskId: toFieldElement(taskId),
    registeredVkHash: toFieldElement(parsed.registeredVk),
    proofVkHash: toFieldElement(parsed.proofVk),
    minimum: parsed.minimum.toString(10),
    publicBalance: parsed.publicBalance.toString(10),
    expiryBlock: parsed.expiryBlock.toString(10),
    currentBlock: parsed.currentBlock.toString(10),
    recipient: toFieldElement(parsed.recipient),
    conditionRecipient: toFieldElement(parsed.conditionRecipient),
    amount: parsed.amount.toString(10),
    maxTransfer: parsed.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: deriveSalt(taskId).toString(10),
  };
}

// ---------------------------------------------------------------- prover

let artifactsPromise = null;

async function download(url, dest) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`artifact download failed: ${url} -> HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, buf);
}

async function ensureArtifacts() {
  for (const src of ARTIFACT_SOURCES) {
    const wasm = path.join(src.dir, src.wasm);
    const zkey = path.join(src.dir, src.zkey);
    if (fs.existsSync(wasm) && fs.existsSync(zkey)) return { wasm, zkey };
  }
  if (!artifactsPromise) {
    artifactsPromise = (async () => {
      const wasm = path.join(TMP_ARTIFACT_DIR, "gatekeeper.wasm");
      const zkey = path.join(TMP_ARTIFACT_DIR, "gatekeeper_final.zkey");
      if (!fs.existsSync(wasm)) await download(ARTIFACT_URLS.wasm, wasm);
      if (!fs.existsSync(zkey)) await download(ARTIFACT_URLS.zkey, zkey);
      return { wasm, zkey };
    })().catch((err) => {
      artifactsPromise = null;
      throw err;
    });
  }
  return artifactsPromise;
}

async function prove(inputs) {
  const { wasm, zkey } = await ensureArtifacts();
  const snarkjs = require("snarkjs");
  const proving = snarkjs.groth16.fullProve(inputs, wasm, zkey);
  const timeout = new Promise((_, reject) =>
    setTimeout(() => reject(new Error("proving exceeded soft deadline")), PROVE_SOFT_DEADLINE_MS),
  );
  const { proof, publicSignals } = await Promise.race([proving, timeout]);
  return { proof, publicSignals };
}

// --------------------------------------------------------------- handler

function signedResult(status, obj) {
  const body = typeof obj === "string" ? obj : JSON.stringify(obj);
  return { status, body, signature: signBody(SECRET, body) };
}

async function handleTask(task) {
  // Idempotent redelivery: replay the original answer verbatim.
  if (task.task_id) {
    const cached = store.getResponse(task.task_id);
    if (cached) return signedResult(200, cached);
  }

  const parsed = task.task_id ? parseInput(task.input) : null;
  if (!parsed) {
    return signedResult(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }

  const evaluation = evaluate(parsed);
  const response = { decision: evaluation.decision, reason_code: evaluation.reason_code };

  if (evaluation.provable) {
    try {
      const inputs = buildCircuitInputs(task.task_id, parsed, evaluation.decision);
      const { proof, publicSignals } = await prove(inputs);
      response.proof = proof;
      response.public_signals = publicSignals;
      response.proof_tx = parsed.proofTx;
    } catch (err) {
      // Proving failed. Never let an APPROVE leave unproven; a REJECT
      // keeps its reason code but goes out without a proof.
      console.error("[agent] proving failed:", err.message);
      if (evaluation.decision === "APPROVE") {
        return signedResult(200, {
          decision: "REJECT",
          reason_code: "INVALID_TASK",
          proof_tx: parsed.proofTx,
        });
      }
      response.proof_tx = parsed.proofTx;
    }
  } else {
    // PROOF_REUSED — documented as having no proof to submit.
    response.proof_tx = parsed.proofTx;
  }

  const result = signedResult(200, response);
  // Record only after the answer is built, so a task never flags itself.
  store.recordProofTx(parsed.proofTx);
  store.recordResponse(task.task_id, result.body);
  return result;
}

async function handlePost(rawBody, signatureHeader) {
  if (!SECRET) {
    return {
      status: 500,
      body: JSON.stringify({ error: "server_misconfigured", detail: "AGENT_GAMES_HMAC_SECRET not set" }),
      signature: null,
    };
  }

  // Authenticate the RAW body before parsing anything.
  if (!verifySignature(SECRET, rawBody, signatureHeader)) {
    return { status: 401, body: JSON.stringify({ error: "invalid_signature" }), signature: null };
  }

  let envelope;
  try {
    envelope = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return signedResult(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }

  if (envelope && envelope.type === PREFLIGHT_TYPE) {
    return signedResult(200, { ok: true, protocolVersion: PROTOCOL_VERSION });
  }
  if (!envelope || envelope.type !== TASK_TYPE) {
    return signedResult(400, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }

  try {
    return await handleTask(envelope);
  } catch (err) {
    console.error("[agent] task handling error:", err.message);
    return signedResult(200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
}

// ------------------------------------------------------------ HTTP entry

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

async function handler(req, res) {
  try {
    if (req.method === "GET") {
      const body = JSON.stringify({
        ok: true,
        protocolVersion: PROTOCOL_VERSION,
        agent: "asep",
        event: "proof-gatekeeper",
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(body);
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "method_not_allowed" }));
      return;
    }
    const rawBody = await readRawBody(req);
    const result = await handlePost(rawBody, req.headers[SIG_HEADER]);
    const headers = { "content-type": "application/json" };
    if (result.signature) headers[SIG_HEADER] = result.signature;
    res.writeHead(result.status, headers);
    res.end(result.body);
  } catch (err) {
    console.error("[agent] http error:", err.message);
    if (!res.headersSent) res.writeHead(500, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "internal_error" }));
  }
}

module.exports = handler;
module.exports.config = { api: { bodyParser: false } };

// Local development: `node api/agent.js` serves on PORT (default 8787).
if (require.main === module) {
  const http = require("http");
  const port = Number(process.env.PORT || 8787);
  http.createServer(handler).listen(port, () => {
    console.log(`[agent] asep gatekeeper listening on :${port}`);
  });
}
