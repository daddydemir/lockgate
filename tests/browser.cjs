// Run against a disposable LockGate instance. Requires Playwright with Chromium.
// LOCKGATE_BROWSER_URL and LOCKGATE_BROWSER_PASSWORD supply the test login.
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
(async () => {
  const base = process.env.LOCKGATE_BROWSER_URL || 'http://127.0.0.1:18089';
  const password = process.env.LOCKGATE_BROWSER_PASSWORD;
  if (!password) throw new Error('LOCKGATE_BROWSER_PASSWORD is required');
  const browser = await chromium.launch({headless:true, executablePath:process.env.CHROMIUM_EXECUTABLE || undefined, args:['--no-sandbox']});
  try {
    const page = await browser.newPage({viewport:{width:1440,height:1000}});
    page.setDefaultTimeout(120000);page.setDefaultNavigationTimeout(120000);
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await page.goto(base+'/admin/login');
    await page.getByLabel('Username').fill('admin');
    await page.getByLabel('Password',{exact:true}).fill(password);
    await page.getByRole('button',{name:'Sign in'}).click();
    await page.waitForURL(base+'/admin');
    const suffix=Date.now();const path=`projects/browser-${suffix}/prod/database`;
    await page.goto(base+'/admin/secrets');
    await page.getByLabel('Secret path',{exact:true}).fill(path);
    await page.getByLabel('Values · JSON object').fill(JSON.stringify({DB_USER:'postgres',DB_PASSWORD:'browser-test-only'}));
    await page.getByRole('button',{name:'Encrypt & save secret'}).click();
    await page.waitForURL(url => url.pathname === '/admin/secret');
    assert.equal(await page.locator('#secret-editor').isVisible(),false);
    await page.getByRole('button',{name:'Reveal & edit values'}).click();
    await page.getByLabel('Values · JSON object').fill(JSON.stringify({DB_USER:'postgres',DB_PASSWORD:'browser-updated'}));
    await page.getByRole('button',{name:'Save new version'}).click();
    await page.waitForURL(url => url.pathname === '/admin/secret');
    await page.getByText('v2',{exact:true}).waitFor();
    await page.goto(base+'/admin/applications');
    await page.getByLabel('Name',{exact:true}).fill('browser-service-'+suffix);
    await page.getByLabel('Environment',{exact:true}).fill('production');
    await page.getByLabel('Allowed secret paths').fill(`projects/browser-${suffix}/prod/*`);
    await page.getByRole('button',{name:'Create application'}).click();
    const token=await page.locator('#token').inputValue();assert.ok(token.startsWith('lg_app_'));
    const detail=await page.getByRole('link',{name:'Continue to application'}).getAttribute('href');
    const machine=async (method,path,body,key)=>{
      const r=await fetch(base+path,{method,headers:{Authorization:'Bearer '+token,'Content-Type':'application/json',...(key?{'Idempotency-Key':key}:{})},body:body?JSON.stringify(body):undefined});
      assert.ok([200,202].includes(r.status),`API returned ${r.status}`);return r.json();
    };
    await page.goto(base+'/admin/approvals');
    const waiting=await Promise.all(Array.from({length:4},(_,i)=>machine('POST','/api/v1/access',{secrets:[path]},'browser-'+suffix+'-'+i)));
    assert.equal(new Set(waiting.map(x=>x.approval_id)).size,1);
    // SSE must update the open page without a manual reload.
    await page.getByRole('link',{name:'browser-service-'+suffix,exact:true}).waitFor({timeout:30000});
    await page.locator('.waiting strong').filter({hasText:'4'}).waitFor();
    await page.screenshot({path:'.local/screenshots/approvals.png',fullPage:true});
    await page.getByRole('button',{name:'Approve access'}).click();
    await page.getByText("You're all caught up.").waitFor();
    const approved=await machine('GET','/api/v1/access/'+waiting[0].request_id);
    assert.equal(approved.secrets[path].DB_PASSWORD,'browser-updated');
    const restart=await machine('POST','/api/v1/access',{secrets:[path]},'restart-'+suffix);assert.equal(restart.status,'approved');
    await page.goto(base+'/admin');
    await page.screenshot({path:'.local/screenshots/dashboard.png',fullPage:true});
    await page.goto(base+detail);
    page.on('dialog',dialog=>dialog.accept());
    await page.getByRole('button',{name:'Revoke access'}).click();
    await page.getByText('Requires approval',{exact:true}).waitFor();
    const revoked=await machine('GET','/api/v1/access/'+waiting[0].request_id);assert.equal(revoked.status,'revoked');
    const again=await machine('POST','/api/v1/access',{secrets:[path]},'again-'+suffix);assert.equal(again.status,'waiting_approval');
    await page.goto(base+'/admin/approvals');
    await page.getByRole('button',{name:'Deny',exact:true}).click();
    const denied=await machine('GET','/api/v1/access/'+again.request_id);assert.equal(denied.status,'denied');
    await page.setViewportSize({width:390,height:844});
    await page.goto(base+'/admin/secrets');
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true,'mobile overflow');
    await page.screenshot({path:'.local/screenshots/mobile.png',fullPage:true});
    assert.deepEqual(errors,[]);
    console.log('Browser workflow passed: login, masked editing, versioning, token, four-instance SSE approval, restart, revoke, deny, mobile layout.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exit(1)});
