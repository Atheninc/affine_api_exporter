import express from "express";
import dotenv from "dotenv";
import { Client as SSHClient } from "ssh2";
import fs from "fs";
import * as Y from "yjs";

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.static("public"));

const PORT = Number(process.env.PORT || 8080);

/* ---------------- SSH / DOCKER ---------------- */

function dockerPrefix() {
  return (String(process.env.DOCKER_USE_SUDO || "false").toLowerCase() === "true")
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

    const cfg = { host, port, username, readyTimeout: 15000 };

    if (keyPath) {
      cfg.privateKey = fs.readFileSync(keyPath);
      if (password) cfg.passphrase = password; // si clé chiffrée
    } else {
      cfg.password = password;
    }

    conn.connect(cfg);
  });
}

function sshExec(conn, command) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(err);
      let stdout = "";
      let stderr = "";
      stream.on("data", d => (stdout += d.toString("utf8")));
      stream.stderr.on("data", d => (stderr += d.toString("utf8")));
      stream.on("close", code => resolve({ code, stdout, stderr }));
    });
  });
}

async function psqlQuery(conn, sql) {
  const docker = dockerPrefix();
  const container = process.env.AFFINE_PG_CONTAINER || "affine_postgres";
  const db = process.env.PG_DB || "affine";
  const user = process.env.PG_USER || "affine";

  const sqlEscaped = sql.replace(/"/g, '\\"');
  const cmd = `${docker} exec ${container} psql -U ${user} -d ${db} -A -t -F "|" -c "${sqlEscaped}"`;

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

function findRootPageBlock(blocks) {
  for (const [bid, b] of Object.entries(blocks)) {
    if (b && b["sys:flavour"] === "affine:page") return bid;
  }
  return null;
}

function findFirstNoteBlock(blocks) {
  // souvent utile en mode edgeless
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

/* ---------------- Deep string extraction (surface) ---------------- */

function collectStringsDeep(obj, out, path = "", depth = 0) {
  if (depth > 10) return; // anti-boucle
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

function getSurfaceSummary(block) {
  const val = block?.["prop:elements"]?.value;
  if (!val) return { count: 0, texts: [] };

  // best effort count
  let count = 0;
  if (Array.isArray(val?.elements)) count = val.elements.length;
  else if (Array.isArray(val)) count = val.length;
  else if (typeof val === "object") count = Object.keys(val).length;

  // extract strings
  const found = [];
  collectStringsDeep(val, found);

  const uniq = [];
  const seen = new Set();
  for (const x of found) {
    const t = x.text;
    if (seen.has(t)) continue;
    seen.add(t);
    uniq.push(t);
    if (uniq.length >= 15) break;
  }

  return { count, texts: uniq };
}

/* ---------------- Blocks -> Markdown ---------------- */

function blocksToMarkdown(blocks) {
  // Root: page si possible, sinon fallback note (edgeless)
  let rootId = findRootPageBlock(blocks);

  // fallback si page sans children (souvent edgeless)
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
    // si on part d'une note, pas de titre -> fallback
    const maybeTitle = blocks[rootId]?.["prop:title"];
    if (typeof maybeTitle === "string" && maybeTitle.trim()) pageTitle = maybeTitle.trim();
  }

  if (!rootId) {
    return {
      title: "Untitled",
      markdown: "_No affine:page / affine:note root found_",
      debug: { blocksCount: Object.keys(blocks).length }
    };
  }

  const ordered = orderedBlockIds(blocks, rootId);
  const lines = [`# ${pageTitle || "Untitled"}`, ""];

  for (const bid of ordered) {
    const b = blocks[bid] || {};
    const flavour = b["sys:flavour"];

    // NOTE: afficher un petit header (structure edgeless)
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

    // SURFACE: afficher résumé + textes trouvés si présents
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
        lines.push("_(pas de texte détecté dans la surface)_");
        lines.push("");
      }
      continue;
    }

    // PARAGRAPH: ton comportement existant
    if (flavour === "affine:paragraph") {
      const txt = b["prop:text"];
      if (typeof txt === "string") {
        const t = txt.trim();
        if (t && t !== ".") lines.push(t, "");
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
      blocksCount: Object.keys(blocks).length
    }
  };
}

/* ---------------- Reference finder (clickable docs/pages) ---------------- */

function findPageRefs(blocks) {
  const refs = [];

  const directKeys = [
    "pageId", "docId", "refId",
    "prop:pageId", "prop:docId", "prop:reference", "prop:ref", "prop:linkedPageId",
    "prop:sourceId", "prop:targetId", "prop:targetPageId"
  ];

  for (const [id, b] of Object.entries(blocks)) {
    if (!b || typeof b !== "object") continue;

    const flavour = b["sys:flavour"];
    const type = b["prop:type"];

    for (const k of directKeys) {
      const v = b[k];
      if (typeof v === "string" && v.length >= 6) {
        refs.push({ block_id: id, flavour, type, key: k, value: v });
      }
    }

    // scan des sous-objets
    for (const [k, v] of Object.entries(b)) {
      if (!v || typeof v !== "object" || Array.isArray(v)) continue;
      for (const [kk, vv] of Object.entries(v)) {
        if (typeof vv !== "string") continue;
        const low = kk.toLowerCase();
        if (low.includes("page") || low.includes("doc") || low.includes("ref") || low.includes("guid")) {
          refs.push({ block_id: id, flavour, type, key: `${k}.${kk}`, value: vv });
        }
      }
    }

    // scan basique de strings "affine://" ou similaire
    for (const [k, v] of Object.entries(b)) {
      if (typeof v === "string" && v.startsWith("affine://")) {
        refs.push({ block_id: id, flavour, type, key: k, value: v });
      }
    }
  }

  // dédoublonne
  const seen = new Set();
  const out = [];
  for (const r of refs) {
    const sig = `${r.block_id}|${r.key}|${r.value}`;
    if (seen.has(sig)) continue;
    seen.add(sig);
    out.push(r);
  }
  return out;
}

/* ---------------- Snapshot fetcher ---------------- */

async function fetchSnapshotBlobBase64(conn, wid, pid) {
  // snapshots.guid == workspace_pages.page_id
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

/* ---------------- API ---------------- */

app.get("/api/workspaces", async (_req, res) => {
  let conn;
  try {
    conn = await sshConnect();
    const raw = await psqlQuery(
      conn,
      "SELECT id, name, created_at FROM workspaces ORDER BY created_at DESC;"
    );

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

    res.json({
      workspace_id: wid,
      page_id: pid,
      bytes: blobBytes.length,
      title: decoded.title,
      markdown: decoded.markdown,
      debug: decoded.debug
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
      blocks
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
