const WebSocket = require('ws');
function attempt(label, url) {
  return new Promise((resolve) => {
    const ws = new WebSocket(url, { headers: { Origin: 'http://evil.test' } });
    let done = false;
    const fin = (r) => { if (!done) { done = true; try { ws.close(); } catch {} resolve(console.log(`  ${label.padEnd(46)} -> ${r}`)); } };
    ws.on('open', () => fin('UPGRADE ACCEPTED'));
    ws.on('error', (e) => fin('rejected: ' + String(e.message).slice(0, 60)));
    ws.on('unexpected-response', (_, res) => fin('rejected: HTTP ' + res.statusCode));
    setTimeout(() => fin('timeout'), 4000);
  });
}
(async () => {
  console.log('=== HMR WebSocket upgrade, hostile Origin: http://evil.test ===');
  await attempt('plain /_next/hmr (expect rejected)', 'ws://localhost:3020/_next/hmr');
  await attempt('/_next/hmr?x=/_next/image  (bypass)', 'ws://localhost:3020/_next/hmr?x=/_next/image');
})();
