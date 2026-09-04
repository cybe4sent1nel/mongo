const { chromium } = require('/opt/node22/lib/node_modules/playwright');
(async () => {
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome', args: ['--no-sandbox'] });
  const page = await browser.newPage();
  page.on('console', m => console.log('PAGE LOG:', m.text()));
  await page.goto('http://attacker.test:8899/attack.html', { waitUntil: 'load' });
  await page.waitForTimeout(2000);
  await browser.close();
})();
