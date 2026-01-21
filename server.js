import express from "express";
import dotenv from "dotenv";
import { Client as SSHClient } from "ssh2";
import fs from "fs";
import * as Y from "yjs";

dotenv.config();

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(express.static("public"));

const PORT = Number(process.env.PORT || 8080);

// Active le dump des blocks inconnus dans /content
const DUMP_UNKNOWN_FLAVOURS =
  String(process.env.DUMP_UNKNOWN_FLAVOURS || "false").toLowerCase() === "true";

/* ---------------- TUNABLES (timeouts / perf) ---------------- */

// SSH
const SSH_READY_TIMEOUT = Number(process.env.SSH_READY_TIMEOUT || 45000); // ms
const SSH_KEEPALIVE_INTERVAL = Number(process.env.SSH_KEEPALIVE_INTERVAL || 10000); // ms
const SSH_KEEPALIVE_COUNT_MAX = Number(process.env.SSH_KEEPALIVE_COUNT_MAX || 3);
const SSH_EXEC_TIMEOUT_MS = Number(process.env.SSH_EXEC_TIMEOUT_MS || 30000); // ms per command

// Postgres statement timeout (appliqué via PGOPTIONS dans docker exec)
const PG_STATEMENT_TIMEOUT_MS = Number(process.env.PG_STATEMENT_TIMEOUT_MS || 25000);

// Backlinks scan
const LINKS_SCAN_LIMIT_DEFAULT = Number(process.env.LINKS_SCAN_LIMIT_DEFAULT || 200); // default if not provided
const LINKS_SCAN_LIMIT_MAX = Number(process.env.LINKS_SCAN_LIMIT_MAX || 2000);
const LINKS_CONCURRENCY = Number(process.env.LINKS_CONCURRENCY || 5);

/* ---------------- SSH / DOCKER ---------------- */

function dockerPrefix() {
  return String(process.env.DOCKER_USE_SUDO || "false").toLowerCase() === "true"
    ? "sudo docker"
    : "docker";
}

function sshConnect() {
  const host = process.env.VPS_HOST;
  const port = Number(process.env.VPS_PORT || 22);
  const username = process.env.VPS_USER || "root";
  const password = process.env.VPS_PASS;
  const keyPath = process.env.VPS_KEY_PATH;

  if (!host) throw new Error("VPS_HOST missing");
  if (!password && !keyPath) throw new Error("VPS_PASS or VPS_KEY_PATH required");

  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    conn.on("ready", () => resolve(conn));
    conn.on("error", reject);

    /** @type {any} */
    const cfg = {
      host,
      port,
      username,
      readyTimeout: SSH_READY_TIMEOUT,
      keepaliveInterval: SSH_KEEPALIVE_INTERVAL,
      keepaliveCountMax: SSH_KEEPALIVE_COUNT_MAX,
    };

    if (keyPath) {
      cfg.privateKey = fs.readFileSync(keyPath);
      if (password) cfg.passphrase = password; // clé chiffrée
    } else {
      cfg.password = password;
    }

    conn.connect(cfg);
  });
}

function withTimeout(promise, ms, label = "timeout") {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(label)), ms)),
  ]);
}

function sshExec(conn, command, timeoutMs = SSH_EXEC_TIMEOUT_MS) {
  return withTimeout(
    new Promise((resolve, reject) => {
      conn.exec(command, (err, stream) => {
        if (err) return reject(err);
        let stdout = "";
        let stderr = "";
        stream.on("data", d => (stdout += d.toString("utf8")));
        stream.stderr.on("data", d => (stderr += d.toString("utf8")));
        stream.on("close", code => resolve({ code, stdout, stderr }));
        stream.on("error", reject);
      });
    }),
    timeoutMs,
    `sshExec timeout after ${timeoutMs}ms`
  );
}

async function psqlQuery(conn, sql) {
  const docker = dockerPrefix();
  const container = process.env.AFFINE_PG_CONTAINER || "affine_postgres";
  const db = process.env.PG_DB || "affine";
  const user = process.env.PG_USER || "affine";

  // escape quotes for -c "..."
  const sqlEscaped = String(sql).replace(/"/g, '\\"');

  // Apply statement_timeout via PGOPTIONS (no need to modify SQL)
  const pgopts = `-c statement_timeout=${PG_STATEMENT_TIMEOUT_MS}`;

  const cmd =
    `${docker} exec -e PGOPTIONS="${pgopts}" ${container} ` +
    `psql -U ${user} -d ${db} -v ON_ERROR_STOP=1 -A -t -F "|" -c "${sqlEscaped}"`;

  const { code, stdout, stderr } = await sshExec(conn, cmd);
  if (code !== 0) throw new Error(stderr || stdout);
  return stdout.trim();
}

/* ---------------- YJS -> JSON-like ---------------- */

function yValueToJS(v) {
  if (v == null) return v;
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return v;

  if (v instanceof Uint8Array) return { __bytes__: true, len: v.length };
  if (Buffer.isBuffer(v)) return { __bytes__: true, len: v.length };

  if (v instanceof Y.Map) {
    const obj = {};
    v.forEach((val, key) => (obj[key] = yValueToJS(val)));
    return obj;
  }

  if (v instanceof Y.Array) {
    return v.toArray().map(yValueToJS);
  }

  if (v instanceof Y.Text) {
    return v.toString();
  }

  // Yjs XML types (rich text)
  if (v instanceof Y.XmlText) return v.toString();
  if (v instanceof Y.XmlFragment) return v.toString();
  if (v instanceof Y.XmlElement) return v.toString();

  if (typeof v?.toArray === "function") {
    try {
      return v.toArray().map(yValueToJS);
    } catch {}
  }

  try {
    return JSON.parse(JSON.stringify(v));
  } catch {}

  return String(v);
}

function decodeSnapshotToBlocks(blobBytes) {
  const doc = new Y.Doc();
  Y.applyUpdate(doc, new Uint8Array(blobBytes));

  const blocksMap = doc.getMap("blocks");
  const blocks = {};
  blocksMap.forEach((val, key) => {
    blocks[key] = yValueToJS(val);
  });

  return blocks;
}

/* ---------------- Tree helpers ---------------- */

function findRootPageBlock(blocks) {
  for (const [bid, b] of Object.entries(blocks)) {
    if (b && b["sys:flavour"] === "affine:page") return bid;
  }
  return null;
}

function findFirstNoteBlock(blocks) {
  for (const [bid, b] of Object.entries(blocks)) {
    if (b && b["sys:flavour"] === "affine:note") return bid;
  }
  return null;
}

function orderedBlockIds(blocks, rootId) {
  if (!rootId) return [];
  const visited = new Set();
  const ordered = [];

  function walk(id) {
    if (!id || visited.has(id)) return;
    visited.add(id);
    ordered.push(id);

    const b = blocks[id] || {};
    const children = b["sys:children"] || [];
    if (Array.isArray(children)) children.forEach(walk);
  }

  walk(rootId);
  return ordered;
}

/* ---------------- Deep scan utilities ---------------- */

function isMeaningfulText(t) {
  if (!t) return false;
  const s = String(t).trim();
  if (!s) return false;
  if (s === "." || s === "·") return false;
  if (/^[\s\.\-–—]+$/.test(s)) return false;
  return true;
}

function collectStringsDeep(obj, out, path = "", depth = 0) {
  if (depth > 12) return;
  if (obj == null) return;

  if (typeof obj === "string") {
    const s = obj.trim();
    if (s && s !== ".") out.push({ path, text: s });
    return;
  }

  if (Array.isArray(obj)) {
    obj.forEach((v, i) => collectStringsDeep(v, out, `${path}[${i}]`, depth + 1));
    return;
  }

  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      collectStringsDeep(v, out, path ? `${path}.${k}` : k, depth + 1);
    }
  }
}

function findAllStringsDeep(obj, out = [], path = "", depth = 0) {
  if (depth > 12 || obj == null) return out;

  if (typeof obj === "string") {
    out.push({ path, value: obj });
    return out;
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => findAllStringsDeep(v, out, `${path}[${i}]`, depth + 1));
    return out;
  }
  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      findAllStringsDeep(v, out, path ? `${path}.${k}` : k, depth + 1);
    }
  }
  return out;
}

/* ---------------- Surface summary ---------------- */

function getSurfaceSummary(block) {
  const val = block?.["prop:elements"]?.value;
  if (!val) return { count: 0, texts: [] };

  let count = 0;
  if (Array.isArray(val?.elements)) count = val.elements.length;
  else if (Array.isArray(val)) count = val.length;
  else if (typeof val === "object") count = Object.keys(val).length;

  const found = [];
  collectStringsDeep(val, found);

  const uniq = [];
  const seen = new Set();
  for (const x of found) {
    const t = x.text;
    if (seen.has(t)) continue;
    seen.add(t);
    uniq.push(t);
    if (uniq.length >= 20) break;
  }

  return { count, texts: uniq };
}

/* ---------------- Text extraction ---------------- */

function extractParagraphText(block) {
  // simple
  if (typeof block?.["prop:text"] === "string") return block["prop:text"];

  // if object
  const maybe = block?.["prop:text"];
  if (maybe && typeof maybe === "object") {
    const as = yValueToJS(maybe);
    if (typeof as === "string") return as;
  }

  // candidates
  const candidates = [
    "prop:richText",
    "prop:delta",
    "prop:content",
    "prop:markdown",
    "prop:html",
    "prop:source",
  ];

  for (const k of candidates) {
    if (!block?.[k]) continue;
    const as = yValueToJS(block[k]);
    if (typeof as === "string" && as.trim()) return as;
  }

  // last resort: deep scan
  const hits = [];
  collectStringsDeep(block, hits);
  const first = hits.map(x => x.text).find(s => isMeaningfulText(s));
  return first || "";
}

function isChecked(b) {
  return !!(b?.["prop:checked"] ?? b?.["prop:done"] ?? b?.["prop:completed"] ?? b?.["prop:checked:bool"]);
}

/* ---------------- Unknown flavour dump ---------------- */

function dumpBlockSummary(block, maxStrings = 12) {
  const flavour = block?.["sys:flavour"] || "unknown";
  const type = block?.["prop:type"] || "";
  const keys = block && typeof block === "object" ? Object.keys(block) : [];

  const found = [];
  collectStringsDeep(block, found);
  const texts = found.map(x => x.text).filter(isMeaningfulText);

  const uniq = [];
  const seen = new Set();
  for (const t of texts) {
    if (seen.has(t)) continue;
    seen.add(t);
    uniq.push(t);
    if (uniq.length >= maxStrings) break;
  }

  return { flavour, type, keys, texts: uniq };
}

/* ---------------- Blocks -> Markdown ---------------- */

function blocksToMarkdown(blocks) {
  // Root: page si possible, sinon note
  let rootId = findRootPageBlock(blocks);

  if (rootId) {
    const rootChildren = blocks[rootId]?.["sys:children"];
    const hasChildren = Array.isArray(rootChildren) && rootChildren.length > 0;
    if (!hasChildren) {
      const noteId = findFirstNoteBlock(blocks);
      if (noteId) rootId = noteId;
    }
  } else {
    const noteId = findFirstNoteBlock(blocks);
    if (noteId) rootId = noteId;
  }

  let pageTitle = "Untitled";
  if (rootId) {
    const maybeTitle = blocks[rootId]?.["prop:title"];
    if (typeof maybeTitle === "string" && maybeTitle.trim()) pageTitle = maybeTitle.trim();
  }

  if (!rootId) {
    return {
      title: "Untitled",
      markdown: "_No affine:page / affine:note root found_",
      debug: { blocksCount: Object.keys(blocks).length },
    };
  }

  const ordered = orderedBlockIds(blocks, rootId);
  const lines = [`# ${pageTitle || "Untitled"}`, ""];

  for (const bid of ordered) {
    const b = blocks[bid] || {};
    const flavour = b["sys:flavour"];
    const type = b["prop:type"];

    // NOTE container (edgeless)
    if (flavour === "affine:note") {
      const idx = b["prop:index"] ?? "";
      const xywh = b["prop:xywh"] ?? "";
      const hidden = b["prop:hidden"] ? "hidden" : "visible";
      lines.push("---");
      lines.push(`## Note ${idx}`.trim());
      lines.push(`_${hidden}${xywh ? ` • xywh=${xywh}` : ""}_`);
      lines.push("");
      continue;
    }

    // SURFACE (edgeless)
    if (flavour === "affine:surface") {
      const { count, texts } = getSurfaceSummary(b);
      lines.push("---");
      lines.push("## Surface");
      lines.push(`_(éléments détectés: ${count})_`);
      lines.push("");
      if (texts.length) {
        lines.push(...texts.map(t => `- ${t}`));
        lines.push("");
      } else {
        lines.push("_(pas de texte détecté dans la surface — éléments non-textuels ou non décodés)_");
        lines.push("");
      }
      continue;
    }

    // PARAGRAPH
    if (flavour === "affine:paragraph") {
      const t = (extractParagraphText(b) || "").trim();
      if (isMeaningfulText(t)) lines.push(t, "");
      continue;
    }

    // TODO / LIST
    if (flavour === "affine:list") {
      if (type === "todo") {
        const checked = isChecked(b) ? "x" : " ";
        const t = (extractParagraphText(b) || "").trim();
        const label = isMeaningfulText(t) ? t : "(vide)";
        lines.push(`- [${checked}] ${label}`.trim(), "");
      } else {
        const t = (extractParagraphText(b) || "").trim();
        if (isMeaningfulText(t)) lines.push(`- ${t}`, "");
      }
      continue;
    }

    // CODE (best effort)
    if (flavour === "affine:code") {
      const lang = (b["prop:language"] || b["prop:lang"] || "").toString();
      const code = (b["prop:text"] || extractParagraphText(b) || "").toString();
      lines.push("```" + lang, code, "```", "");
      continue;
    }

    // Fallback: afficher TOUS les flavours non gérés (si activé)
    if (DUMP_UNKNOWN_FLAVOURS) {
      const info = dumpBlockSummary(b, 15);

      lines.push("---");
      lines.push(`## ${info.flavour}${info.type ? ` (${info.type})` : ""}`);
      lines.push(`_id=${bid} • keys=${info.keys.length}_`);
      lines.push("");

      lines.push("**keys:**");
      lines.push(info.keys.map(k => `\`${k}\``).join(" "));
      lines.push("");

      if (info.texts.length) {
        lines.push("**strings trouvées:**");
        lines.push(...info.texts.map(t => `- ${t}`));
        lines.push("");
      } else {
        lines.push("_(aucune string utile détectée)_");
        lines.push("");
      }

      continue;
    }
  }

  return {
    title: pageTitle,
    markdown: lines.join("\n").trim() + "\n",
    debug: {
      rootId,
      orderedCount: ordered.length,
      blocksCount: Object.keys(blocks).length,
      dumpUnknownFlavours: DUMP_UNKNOWN_FLAVOURS,
    },
  };
}

/* ---------------- Reference finder (DEEP) ---------------- */

function findPageRefs(blocks) {
  const refs = [];
  const seen = new Set();

  for (const [id, b] of Object.entries(blocks)) {
    if (!b || typeof b !== "object") continue;

    const flavour = b["sys:flavour"];
    const type = b["prop:type"];
    const strings = findAllStringsDeep(b);

    for (const s of strings) {
      const v = (s.value || "").trim();
      if (!v) continue;

      // affine:// links
      if (v.startsWith("affine://")) {
        const sig = `${id}|${s.path}|${v}`;
        if (!seen.has(sig)) {
          seen.add(sig);
          refs.push({ block_id: id, flavour, type, key: s.path, value: v });
        }
        continue;
      }

      // heuristics: short ids / uuids often used by pages/docs
      const looksLikeShortId = /^[A-Za-z0-9_-]{8,24}$/.test(v);
      const looksLikeUUID =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);

      if (looksLikeShortId || looksLikeUUID) {
        const lowPath = s.path.toLowerCase();
        if (
          lowPath.includes("page") ||
          lowPath.includes("doc") ||
          lowPath.includes("ref") ||
          lowPath.includes("guid")
        ) {
          const sig = `${id}|${s.path}|${v}`;
          if (!seen.has(sig)) {
            seen.add(sig);
            refs.push({ block_id: id, flavour, type, key: s.path, value: v });
          }
        }
      }
    }
  }

  return refs;
}

/* ---------------- Snapshot fetcher ---------------- */

async function fetchSnapshotBlobBase64(conn, wid, pid) {
  return await psqlQuery(
    conn,
    `SELECT encode(blob,'base64')
     FROM snapshots
     WHERE workspace_id='${wid}'
       AND guid='${pid}'
     ORDER BY updated_at DESC
     LIMIT 1;`
  );
}

/* ---------------- Links helpers ---------------- */

function extractTargetPageIdFromRef(value) {
  if (!value) return null;
  const v = String(value).trim();

  // affine://... -> last id-like segment
  if (v.startsWith("affine://")) {
    const base = v.split(/[?#]/)[0];
    const parts = base.split("/").filter(Boolean);
    const last = parts[parts.length - 1];
    if (last && /^[A-Za-z0-9_-]{8,64}$/.test(last)) return last;
  }

  // UUID brut
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v)) {
    return v;
  }

  // shortId brut
  if (/^[A-Za-z0-9_-]{8,24}$/.test(v)) {
    return v;
  }

  return null;
}

async function fetchWorkspacePages(conn, wid) {
  const raw = await psqlQuery(
    conn,
    `SELECT page_id, COALESCE(title,'') as title
     FROM workspace_pages
     WHERE workspace_id='${wid}'
     ORDER BY title ASC;`
  );

  return raw
    ? raw.split("\n").map(line => {
        const [page_id, title] = line.split("|");
        return { page_id, title };
      })
    : [];
}

/* ---------------- SQL safety helpers ---------------- */

function normalizeSql(sql) {
  return String(sql || "").replace(/\u0000/g, "").trim();
}

function isSelectOnly(sql) {
  const s = normalizeSql(sql).toLowerCase();

  // block multi-statement
  if (s.includes(";")) return false;

  // ban writes/admin ops
  const banned = [
    "insert ",
    "update ",
    "delete ",
    "drop ",
    "alter ",
    "create ",
    "truncate ",
    "grant ",
    "revoke ",
    "comment ",
    "vacuum",
    "analyze",
    "reindex",
    "cluster",
    "copy ",
    "call ",
    "do ",
    "execute ",
    "set ",
    "show ",
    "listen",
    "notify",
    "unlisten",
    "refresh materialized",
  ];
  if (banned.some(k => s.includes(k))) return false;

  return s.startsWith("select ") || s.startsWith("with ");
}

function enforceLimit(sql, maxRows = 200) {
  const s = normalizeSql(sql);
  if (/\blimit\b/i.test(s)) return s;
  return `${s} LIMIT ${maxRows}`;
}

/* ---------------- Concurrency helper ---------------- */

async function mapLimit(items, limit, fn) {
  const ret = [];
  const executing = new Set();

  for (const item of items) {
    const p = Promise.resolve().then(() => fn(item));
    ret.push(p);
    executing.add(p);
    p.finally(() => executing.delete(p));

    if (executing.size >= limit) {
      await Promise.race(executing);
    }
  }
  return Promise.all(ret);
}

/* ---------------- API ---------------- */

app.get("/api/workspaces", async (_req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const raw = await psqlQuery(conn, "SELECT id, name, created_at FROM workspaces ORDER BY created_at DESC;");

    const workspaces = raw
      ? raw.split("\n").map(line => {
          const [id, name, created_at] = line.split("|");
          return { id, name, created_at };
        })
      : [];

    res.json({ workspaces });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

app.get("/api/db/tables-simple", async (_req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const raw = await psqlQuery(
      conn,
      `
      SELECT table_schema, table_name
      FROM information_schema.tables
      WHERE table_type='BASE TABLE'
        AND table_schema NOT IN ('pg_catalog','information_schema')
      ORDER BY table_schema, table_name;
      `
    );

    const tables = raw
      ? raw.split("\n").map(line => {
          const [schema, name] = line.split("|");
          return { schema, name };
        })
      : [];

    res.json({ count: tables.length, tables });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

/* ---------------- NEW: list db tables ---------------- */

app.get("/api/db/tables", async (req, res) => {
  let conn;
  try {
    conn = await sshConnect();

    const includeViews = String(req.query.views || "false").toLowerCase() === "true";
    const includeSystemSchemas = String(req.query.system || "false").toLowerCase() === "true";

    const schemaFilter = includeSystemSchemas
      ? "1=1"
      : `n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'`;

    const relKinds = includeViews ? "('r','p','v','m','f')" : "('r','p')";

    const raw = await psqlQuery(
      conn,
      `
      SELECT
        n.nspname AS schema,
        c.relname AS name,
        CASE c.relkind
          WHEN 'r' THEN 'table'
          WHEN 'p' THEN 'partitioned_table'
          WHEN 'v' THEN 'view'
          WHEN 'm' THEN 'materialized_view'
          WHEN 'f' THEN 'foreign_table'
          ELSE c.relkind::text
        END AS kind
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE c.relkind IN ${relKinds}
        AND ${schemaFilter}
      ORDER BY n.nspname, c.relname;
      `
    );

    const items = raw
      ? raw.split("\n").map(line => {
          const [schema, name, kind] = line.split("|");
          return { schema, name, kind };
        })
      : [];

    res.json({
      db: process.env.PG_DB || "affine",
      container: process.env.AFFINE_PG_CONTAINER || "affine_postgres",
      count: items.length,
      tables: items,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

/* ---------------- NEW: SQL query (READ ONLY) ---------------- */
/**
 * POST /api/db/query
 * Body: { sql: "SELECT ...", maxRows?: 200 }
 * Header (recommended): x-sql-token: <SQL_API_TOKEN>
 */
app.post("/api/db/query", async (req, res) => {
  let conn;
  try {
    const tokenExpected = process.env.SQL_API_TOKEN;
    if (tokenExpected) {
      const tokenGot = String(req.headers["x-sql-token"] || "");
      if (tokenGot !== tokenExpected) {
        return res.status(403).json({ error: "Forbidden" });
      }
    }

    const sqlRaw = req.body?.sql;
    if (!sqlRaw) return res.status(400).json({ error: "Missing body.sql" });

    const sql = normalizeSql(sqlRaw);

    if (!isSelectOnly(sql)) {
      return res.status(400).json({
        error: "Only single-statement read-only SELECT/CTE queries are allowed (no ';', no write/admin ops).",
      });
    }

    const maxRows = Math.min(Math.max(Number(req.body?.maxRows || 200), 1), 2000);
    const finalSql = enforceLimit(sql, maxRows);

    conn = await sshConnect();
    const raw = await psqlQuery(conn, finalSql);

    const rows = raw ? raw.split("\n").map(line => line.split("|")) : [];

    res.json({
      db: process.env.PG_DB || "affine",
      maxRows,
      sql: finalSql,
      rowCount: rows.length,
      rows,
      raw,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

app.get("/api/workspaces/:wid/pages", async (req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const wid = req.params.wid;

    const raw = await psqlQuery(
      conn,
      `SELECT page_id, title, mode, public, blocked
       FROM workspace_pages
       WHERE workspace_id='${wid}'
       ORDER BY title ASC;`
    );

    const pages = raw
      ? raw.split("\n").map(line => {
          const [page_id, title, mode, isPublic, blocked] = line.split("|");
          return { page_id, title, mode, public: isPublic, blocked };
        })
      : [];

    res.json({ workspace_id: wid, pages });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

/* ---------------- NEW: bidirectional page links ---------------- */
/**
 * GET /api/workspaces/:wid/pages/:pid/links
 * Query params:
 *   - scanLimit: number (0 = all pages)  <-- (maintenu)
 *
 * Patch: par défaut on NE scanne pas tout. Si scanLimit absent:
 *        on applique LINKS_SCAN_LIMIT_DEFAULT.
 */
app.get("/api/workspaces/:wid/pages/:pid/links", async (req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const { wid, pid } = req.params;

    // IMPORTANT: si scanLimit absent => défaut 200 (configurable)
    const scanLimitParam = req.query.scanLimit;
    const scanLimitRaw = scanLimitParam == null ? LINKS_SCAN_LIMIT_DEFAULT : Number(scanLimitParam || 0);
    const scanLimit = Math.min(Math.max(scanLimitRaw, 0), LINKS_SCAN_LIMIT_MAX);

    const pages = await fetchWorkspacePages(conn, wid);
    const scanPages = scanLimit > 0 ? pages.slice(0, scanLimit) : pages;

    // OUTGOING
    let outgoing = [];
    {
      const b64 = await fetchSnapshotBlobBase64(conn, wid, pid);
      if (!b64) return res.status(404).json({ error: "No snapshot found" });

      const blocks = decodeSnapshotToBlocks(Buffer.from(b64, "base64"));
      outgoing = findPageRefs(blocks).map(r => ({
        ...r,
        target_page_id: extractTargetPageIdFromRef(r.value),
      }));
    }

    // INCOMING (backlinks) - patch: concurrency limitée
    const incoming = [];
    await mapLimit(scanPages, LINKS_CONCURRENCY, async (p) => {
      if (p.page_id === pid) return;

      const b64 = await fetchSnapshotBlobBase64(conn, wid, p.page_id);
      if (!b64) return;

      const blocks = decodeSnapshotToBlocks(Buffer.from(b64, "base64"));
      const refs = findPageRefs(blocks);

      const matchedRef = refs.find(r => extractTargetPageIdFromRef(r.value) === pid);
      if (matchedRef) {
        incoming.push({
          page_id: p.page_id,
          title: p.title,
          via: matchedRef.value,
          block_id: matchedRef.block_id,
          key: matchedRef.key,
        });
      }
    });

    res.json({
      workspace_id: wid,
      page_id: pid,
      outgoing_count: outgoing.length,
      incoming_count: incoming.length,
      outgoing,
      incoming,
      scanned_pages: scanPages.length,
      total_pages: pages.length,
      // debug perf
      scanLimit,
      concurrency: LINKS_CONCURRENCY,
      ssh_exec_timeout_ms: SSH_EXEC_TIMEOUT_MS,
      pg_statement_timeout_ms: PG_STATEMENT_TIMEOUT_MS,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

app.get("/api/workspaces/:wid/pages/:pid/content", async (req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const { wid, pid } = req.params;

    const b64 = await fetchSnapshotBlobBase64(conn, wid, pid);
    if (!b64) return res.status(404).json({ error: "No snapshot found" });

    const blobBytes = Buffer.from(b64, "base64");
    const blocks = decodeSnapshotToBlocks(blobBytes);
    const decoded = blocksToMarkdown(blocks);
    const refs = findPageRefs(blocks);

    res.json({
      workspace_id: wid,
      page_id: pid,
      bytes: blobBytes.length,
      title: decoded.title,
      markdown: decoded.markdown,
      refs,
      debug: decoded.debug,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

app.get("/api/workspaces/:wid/pages/:pid/raw", async (req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const { wid, pid } = req.params;

    const b64 = await fetchSnapshotBlobBase64(conn, wid, pid);
    if (!b64) return res.status(404).json({ error: "No snapshot found" });

    const blobBytes = Buffer.from(b64, "base64");
    const blocks = decodeSnapshotToBlocks(blobBytes);

    const root = findRootPageBlock(blocks) || findFirstNoteBlock(blocks);
    const ordered = orderedBlockIds(blocks, root);
    const refs = findPageRefs(blocks);

    res.json({
      workspace_id: wid,
      page_id: pid,
      bytes: blobBytes.length,
      root_page_block: root,
      ordered_block_ids: ordered,
      refs,
      blocks,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

/* ---------------- NEW: stats (flavours) ---------------- */

app.get("/api/workspaces/:wid/pages/:pid/stats", async (req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const { wid, pid } = req.params;

    const b64 = await fetchSnapshotBlobBase64(conn, wid, pid);
    if (!b64) return res.status(404).json({ error: "No snapshot found" });

    const blocks = decodeSnapshotToBlocks(Buffer.from(b64, "base64"));

    const byFlavour = {};
    for (const b of Object.values(blocks)) {
      const f = b?.["sys:flavour"] || "unknown";
      byFlavour[f] = (byFlavour[f] || 0) + 1;
    }

    res.json({
      workspace_id: wid,
      page_id: pid,
      blocksCount: Object.keys(blocks).length,
      flavours: Object.entries(byFlavour)
        .sort((a, b) => b[1] - a[1])
        .map(([flavour, count]) => ({ flavour, count })),
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

/* ---------------- NEW: surface overview ---------------- */

function objectKeysSafe(o) {
  if (!o || typeof o !== "object") return [];
  return Object.keys(o);
}

app.get("/api/workspaces/:wid/pages/:pid/surface", async (req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const { wid, pid } = req.params;

    const b64 = await fetchSnapshotBlobBase64(conn, wid, pid);
    if (!b64) return res.status(404).json({ error: "No snapshot found" });

    const blocks = decodeSnapshotToBlocks(Buffer.from(b64, "base64"));

    const surfaces = Object.entries(blocks)
      .filter(([_, b]) => b?.["sys:flavour"] === "affine:surface")
      .map(([id, b]) => {
        const v = b?.["prop:elements"]?.value;
        return {
          id,
          elementsType: b?.["prop:elements"]?.type,
          valueType: v == null ? "null" : Array.isArray(v) ? "array" : typeof v,
          keysCount: objectKeysSafe(v).length,
          keysSample: objectKeysSafe(v).slice(0, 50),
          summary: getSurfaceSummary(b),
        };
      });

    res.json({ workspace_id: wid, page_id: pid, surfaces });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

/* ---------------- NEW: inspect one block ---------------- */

function findTextLikeFields(obj, hits = [], path = "", depth = 0) {
  if (depth > 12) return hits;
  if (!obj) return hits;

  if (typeof obj === "string") {
    const s = obj.trim();
    if (isMeaningfulText(s)) hits.push({ path, value: s });
    return hits;
  }

  if (Array.isArray(obj)) {
    obj.forEach((v, i) => findTextLikeFields(v, hits, `${path}[${i}]`, depth + 1));
    return hits;
  }

  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) {
      findTextLikeFields(v, hits, path ? `${path}.${k}` : k, depth + 1);
    }
  }

  return hits;
}

app.get("/api/workspaces/:wid/pages/:pid/block/:bid", async (req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const { wid, pid, bid } = req.params;

    const b64 = await fetchSnapshotBlobBase64(conn, wid, pid);
    if (!b64) return res.status(404).json({ error: "No snapshot found" });

    const blocks = decodeSnapshotToBlocks(Buffer.from(b64, "base64"));
    const block = blocks[bid];
    if (!block) return res.status(404).json({ error: "Block not found" });

    const hits = findTextLikeFields(block);

    res.json({
      workspace_id: wid,
      page_id: pid,
      block_id: bid,
      keys: Object.keys(block),
      text_hits: hits.slice(0, 200),
      block,
    });
  } catch (e) {
    res.status(500).json({ error: String(e.message || e) });
  } finally {
    if (conn) conn.end();
  }
});

/* ---------------- START ---------------- */

app.listen(PORT, () => {
  console.log(`AFFiNE navigator running on http://localhost:${PORT}`);
});
