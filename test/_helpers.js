/**
 * Test helpers shared across verify/policy/endorsements suites.
 *
 * Provides:
 *   - sha256B64: Node-side SHA-256 -> unpadded Base64 per HTMLTrust spec §2.1
 *   - signEd25519: returns a base64 signature for a message
 *   - generateKey: ed25519 keypair + PEM
 *   - startServer / stopServer: tiny HTTP fixture server
 */

import { createHash, generateKeyPairSync, sign as nodeSign } from "node:crypto";
import { createServer } from "node:http";

export function sha256B64(text) {
  return createHash("sha256").update(text, "utf8").digest("base64").replace(/=+$/, "");
}

export async function sha256B64Async(text) {
  return sha256B64(text);
}

// Back-compat aliases for any tests still on the old hex names.
export const sha256Hex = sha256B64;
export const sha256HexAsync = sha256B64Async;

export function generateKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pem = publicKey.export({ type: "spki", format: "pem" }).toString();
  return { publicKey, privateKey, pem };
}

export function signEd25519(privateKey, message) {
  return nodeSign(null, Buffer.from(message, "utf8"), privateKey).toString("base64");
}

export function startServer(routes) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const url = req.url || "/";
      const handler = routes[url] || routes[url.split("?")[0]];
      if (!handler) {
        res.writeHead(404);
        res.end();
        return;
      }
      const r = handler(req);
      const body = typeof r.body === "string" ? r.body : JSON.stringify(r.body);
      res.writeHead(r.status || 200, r.headers || { "content-type": "application/json" });
      res.end(body);
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve({ server, port: addr.port, base: `http://127.0.0.1:${addr.port}` });
    });
  });
}

export function stopServer(server) {
  return new Promise((resolve) => server.close(resolve));
}
