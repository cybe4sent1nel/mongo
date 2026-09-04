// Attacker "capture" server: serves the malicious page and logs nothing itself.
// We instead capture what the REAL victim (next dev on :3020) receives via its own
// request logging, by adding a temporary debug echo route is not possible (can't
// modify next dev). Instead we sniff via a raw TCP proxy in front of :3020 that logs
// headers then forwards, so we see exactly what Chromium sent.
const net = require('net');
const fs = require('fs');
const PORT = 3021, TARGET_PORT = 3020;
const logFile = '/tmp/csrfpoc/captured_requests.log';
fs.writeFileSync(logFile, '');
net.createServer(client => {
  const upstream = net.connect(TARGET_PORT, '127.0.0.1');
  let buf = '';
  let logged = false;
  client.on('data', d => {
    if (!logged) {
      buf += d.toString();
      if (buf.includes('\r\n\r\n') || buf.length > 8192) {
        fs.appendFileSync(logFile, '----REQUEST----\n' + buf.split('\r\n\r\n')[0] + '\n\n');
        logged = true;
      }
    }
    upstream.write(d);
  });
  client.on('error', ()=>{});
  upstream.on('error', ()=>{});
  upstream.pipe(client);
}).listen(PORT, '127.0.0.1', () => console.log('proxy listening on', PORT));
