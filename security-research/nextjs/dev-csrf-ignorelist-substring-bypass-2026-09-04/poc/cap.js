// Transparent TCP relay: 3021 -> 3020, logging every request line + headers.
const net = require('net');
const fs = require('fs');
const LOG = __dirname + '/captured.txt';
fs.writeFileSync(LOG, '');
net.createServer((c) => {
  const up = net.connect(3020, '127.0.0.1');
  let buf = '';
  let logged = false;
  c.on('data', (d) => {
    if (!logged) {
      buf += d.toString('latin1');
      const i = buf.indexOf('\r\n\r\n');
      if (i !== -1) { fs.appendFileSync(LOG, buf.slice(0, i) + '\n===\n'); logged = true; }
    }
    up.write(d);
  });
  up.on('data', (d) => c.write(d));
  c.on('error', () => {}); up.on('error', () => {});
  c.on('close', () => up.end()); up.on('close', () => c.end());
}).listen(3021, '0.0.0.0', () => console.log('relay 3021 -> 3020'));
