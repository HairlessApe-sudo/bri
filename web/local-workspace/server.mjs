import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { composeLocalWorkspace, isPrivateWorkspaceRequest, LOCAL_HOST, LOCAL_PORT } from './bridge.mjs';

if (process.env.NODE_ENV && process.env.NODE_ENV !== 'development') throw new Error('Local workspace requires development mode');
process.env.NODE_ENV = 'development';
process.env.NEXT_TELEMETRY_DISABLED = '1';

// Snapshot and validate the launcher setting before Next can load its own environment files.
const handler = composeLocalWorkspace((req, res) => nextHandler(req, res));
const { default: next } = await import('next');
const nextUpgrades = createServer();
const app = next({
  dev: true, webpack: true, dir: fileURLToPath(new URL('.', import.meta.url)), hostname: LOCAL_HOST, port: LOCAL_PORT,
  // Keep Next's automatic upgrade hookup off the public-facing listener.
  httpServer: nextUpgrades,
});
await app.prepare();
const nextHandler = app.getRequestHandler();
const server = createServer((req, res) => {
  void handler(req, res).catch(() => {
    if (res.headersSent) res.destroy();
    else res.writeHead(503, { 'cache-control': 'no-store' }).end();
  });
});
server.on('upgrade', (req, socket, head) => {
  if (!isPrivateWorkspaceRequest(req) || !/^\/_next\/hmr(?:\?|$)/.test(req.url ?? '')) return socket.destroy();
  // App Router dev hydration receives its React debug stream over this socket.
  nextUpgrades.emit('upgrade', req, socket, head);
});
server.listen(LOCAL_PORT, LOCAL_HOST, () => console.log(`BRI local workspace: http://${LOCAL_HOST}:${LOCAL_PORT}/knowledge`));
