const {chromium}=require('playwright');const fs=require('fs');
(async()=>{
 fs.mkdirSync('qa',{recursive:true});
 const server=require('child_process').spawn(process.execPath,['node_modules/vite/bin/vite.js','--host','127.0.0.1','--port','5174'],{cwd:require('path').resolve(__dirname,'../../frontend'),stdio:'ignore'});process.on('exit',()=>server.kill());
 for(let n=0;n<60;n++){try{await fetch('http://127.0.0.1:5174');break;}catch{await new Promise(r=>setTimeout(r,100));}}
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});const page=await browser.newPage({viewport:{width:1440,height:1050},reducedMotion:'reduce'});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(()=>{
  localStorage.setItem('sentinelaudit.disclaimer.v1','accepted');
  const findings=['Windows Firewall Profiles','BitLocker Drive Encryption','TLS Protocol Posture','Password Policy'].map((name,i)=>({finding_id:'check.'+i,name,risk_level:i<2?'High':'Medium',status:i===0?'Fail':i===1?'Unknown':'Pass',description:'Checks the current Windows configuration against the security baseline.',details:{why_it_matters:'This control helps limit exposure to unauthorized access.',recommendation:'Review local evidence and apply the appropriate policy.'},fix_available:i===0,last_checked_utc:new Date().toISOString()}));
  const ok=async()=>({ok:true});const api={get_admin_status:async()=>({is_admin:true,version:'2.2'}),get_access_policy:async()=>({pin_required:false,setup_required:true}),verify_pin:ok,verify_login:ok,set_initial_login:async(username,password)=>{ window.createdAccount={username,passwordLength:password.length}; return {ok:true}; },change_login:ok,keep_session_alive:async()=>({ok:true,session:{expired:false,remaining_s:600}}),run_audit:ok,start_audit:async()=>{window.scanCancelled=false;return {ok:true}},cancel_audit:async()=>{window.scanCancelled=true;return {ok:true}},sync_last_audit:async()=>({queued:true,message:'Queued in the local Client. Admin receipt is not yet confirmed.'}),get_audit_progress:async()=>window.slowScan ? ({running:!window.scanCancelled,done:Boolean(window.scanCancelled),cancelled:Boolean(window.scanCancelled),total:4,completed:1,current_check:'BitLocker Drive Encryption',hardening_score:0,findings:findings.slice(0,1)}) : ({running:false,done:true,total:4,completed:4,hardening_score:67,findings,generated_utc:new Date().toISOString()}),fix_finding:ok,preview_fix:async()=>({supported:true,is_admin:true,changes:['Enable firewall profiles'],rollback_supported:true}),rollback_fix:ok,export_excel:async()=>window.exportMode==="error"?{saved_to:null,error:"Disk full"}:window.exportMode==="cancel"?{saved_to:null}:{saved_to:"C:/Reports/audit.xlsx"},backup_registry:async()=>({saved_to:"C:/Reports/backup.reg"}),open_updates_page:ok,set_tray_score:ok,exit_app:ok};window.pywebview={api};
 });
 await page.goto('http://127.0.0.1:5174');
 await page.getByRole('heading',{name:'Create your free local account'}).waitFor();
 await page.getByPlaceholder('Your username',{exact:true}).fill('New Tester');
 await page.getByPlaceholder('12+ chars, upper, lower, number, symbol').fill('StrongTest!2026');
 const passwords=page.locator('input[type=password]');
 await passwords.nth(1).fill('StrongTest!2026');
 await page.getByRole('button',{name:'Create account & get started'}).click();
 await page.getByRole('heading',{name:'How to use SentinelAudit'}).waitFor();
 if((await page.evaluate(()=>window.createdAccount)).username!=='New Tester')throw Error('Username not passed to bridge');
 for(const width of [1440,768,390]){
   await page.setViewportSize({width,height:950});
   if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('Guide overflow');
 }
 await page.getByRole('button',{name:'Got it — view my audit'}).click();
 await page.getByText('Audit completed',{exact:true}).waitFor();
 await page.getByRole('button',{name:'How to use',exact:true}).click();
 await page.getByRole('heading',{name:'How to use SentinelAudit'}).waitFor();
 await page.keyboard.press('Escape');
 await page.setViewportSize({width:1440,height:1050});
 await page.getByRole('button',{name:'Export Report',exact:true}).click();
 await page.getByText('Data exported successfully',{exact:true}).waitFor();
 await page.getByText('Excel report saved to C:/Reports/audit.xlsx',{exact:true}).waitFor();
 await page.getByRole('button',{name:'Dismiss export notification'}).click();
 await page.evaluate(()=>window.exportMode='cancel');
 await page.getByRole('button',{name:'Export Report',exact:true}).click();
 await page.getByText('Export cancelled',{exact:true}).waitFor();
 if(await page.getByText('Data exported successfully',{exact:true}).count())throw Error('Cancellation reported as success');
 await page.evaluate(()=>window.exportMode='error');
 await page.getByRole('button',{name:'Export Report',exact:true}).click();
 await page.getByText('Disk full',{exact:true}).waitFor();
 if(await page.getByText('Data exported successfully',{exact:true}).count())throw Error('Failure reported as success');
 await page.getByRole('button',{name:'Sync last scan to Admin',exact:true}).click();
 await page.getByText(/Queued in the local Client/).waitFor();
 await page.evaluate(()=>window.slowScan=true);
 await page.getByRole('button',{name:'Run Audit',exact:true}).click();
 await page.getByText('Checking: BitLocker Drive Encryption',{exact:true}).waitFor();
 for(const width of [1440,1024,768,390]){
   await page.setViewportSize({width,height:1050});
   const gauge=await page.locator('.sentinel-score-gauge').boundingBox();
   const progress=await page.locator('.sentinel-scan-progress').boundingBox();
   if(!gauge||!progress||gauge.y+gauge.height>progress.y+1)throw Error('Score overlaps scan status '+width);
   if(gauge.width<150)throw Error('Score squeezed '+width);
   if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('Scan overflow '+width);
 }
 await page.setViewportSize({width:1440,height:1050});
 await page.screenshot({path:'qa/scan-score-layout.png',fullPage:true});
 await page.getByRole('button',{name:'Cancel scan',exact:true}).click();
 await page.getByText('Audit cancelled',{exact:true}).waitFor();
 if(!await page.getByRole('button',{name:'Export Report',exact:true}).isDisabled())throw Error('Partial scan export enabled');
 if(!await page.getByRole('button',{name:'Sync last scan to Admin',exact:true}).isDisabled())throw Error('Partial sync enabled');
 for(const width of [1440,768,390]){
   await page.setViewportSize({width,height:950});
   if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('Workflow overflow '+width);
 }
 await page.evaluate(()=>{window.slowScan=false;window.exportMode='ok'});
 await page.getByRole('button',{name:'Run Audit',exact:true}).click();
 await page.getByText('Audit completed',{exact:true}).waitFor();
 fs.writeFileSync('qa/sentinel-workflow-results.json' ,JSON.stringify({scanCancellation:true,partialExportBlocked:true,syncQueue:true,success:true,savedPath:true,cancellation:true,failure:true,errors},null,2));
 await browser.close();server.kill();if(errors.length)throw Error(errors.join('\n'));
})().catch(e=>{console.error(e);process.exit(1)});
