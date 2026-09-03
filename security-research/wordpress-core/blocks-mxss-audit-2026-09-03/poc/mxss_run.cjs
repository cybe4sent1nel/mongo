const { chromium } = require('/opt/node22/lib/node_modules/playwright');
const fs = require('fs');
(async()=>{
const kses=JSON.parse(fs.readFileSync('/home/user/wpaudit/mxss_out.json','utf8'));
const browser=await chromium.launch({executablePath:'/opt/pw-browsers/chromium',args:['--no-sandbox']});
const results={};
for(const [name,html] of Object.entries(kses)){
 const ctx=await browser.newContext();const page=await ctx.newPage();let fired=[];
 await page.exposeFunction('__xss',(t)=>{fired.push(t);});
 await page.addInitScript(()=>{window.alert=(x)=>window.__xss('alert:'+x);});
 const doc='<!doctype html><html><head></head><body><div id=content>'+html+'</div></body></html>';
 try{await page.setContent(doc,{waitUntil:'networkidle',timeout:4000});await page.waitForTimeout(250);
 await page.evaluate(()=>{document.querySelectorAll('*').forEach(el=>['mouseover','click','focus','load','error'].forEach(ev=>{try{el.dispatchEvent(new Event(ev));}catch(e){}}));});
 await page.waitForTimeout(150);}catch(e){results[name]='ERR:'+e.message.slice(0,40);await ctx.close();continue;}
 results[name]=fired.length?('*** FIRED: '+fired.join(',')+' ***'):'inert';await ctx.close();
}
console.log(JSON.stringify(results,null,1));await browser.close();
})().catch(e=>{console.error(e);process.exit(1);});
