const {chromium}=require('playwright');const fs=require('fs');
(async()=>{
 fs.mkdirSync('qa',{recursive:true});
 const server=require('child_process').spawn(process.execPath,['node_modules/vite/bin/vite.js','--host','127.0.0.1','--port','5174'],{cwd:require('path').resolve(__dirname,'../../frontend'),stdio:'ignore'});process.on('exit',()=>server.kill());
 for(let n=0;n<60;n++){try{await fetch('http://127.0.0.1:5174');break;}catch{await new Promise(r=>setTimeout(r,100));}}
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});const page=await browser.newPage({viewport:{width:1440,height:1050},reducedMotion:'reduce'});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(()=>{
  localStorage.setItem('sentinelaudit.disclaimer.v1','accepted');
  const findings=['Windows Firewall Profiles','BitLocker Drive Encryption','TLS Protocol Posture','Password Policy'].map((name,i)=>({finding_id:'check.'+i,name,risk_level:i<2?'High':'Medium',status:i===0?'Fail':i===1?'Unknown':'Pass',description:'Checks the current Windows configuration against the security baseline.',details:{why_it_matters:'This control helps limit exposure to unauthorized access.',recommendation:'Review local evidence and apply the appropriate policy.'},fix_available:i===0,last_checked_utc:new Date().toISOString()}));
  const ok=async()=>({ok:true});const api={get_admin_status:async()=>({is_admin:true,version:'2.2'}),get_access_policy:async()=>({pin_required:false,setup_required:false}),verify_pin:ok,verify_login:ok,set_initial_login:ok,change_login:ok,keep_session_alive:async()=>({ok:true,session:{expired:false,remaining_s:600}}),run_audit:ok,start_audit:ok,get_audit_progress:async()=>({running:false,done:true,total:4,completed:4,hardening_score:67,findings,generated_utc:new Date().toISOString()}),fix_finding:ok,preview_fix:async()=>({supported:true,is_admin:true,changes:['Enable firewall profiles'],rollback_supported:true}),rollback_fix:ok,export_excel:ok,backup_registry:ok,open_updates_page:ok,set_tray_score:ok,exit_app:ok};window.pywebview={api};
 });
 await page.goto('http://127.0.0.1:5174');await page.getByPlaceholder('Password',{exact:true}).fill('fixture-password');await page.getByRole('button',{name:'Login',exact:true}).click();await page.getByText('Audit completed',{exact:true}).waitFor();
 await page.screenshot({path:'qa/sentinel-desktop.png',fullPage:true});
 await page.getByRole('button',{name:/Needs attention/}).click();
 if(await page.getByText('BitLocker Drive Encryption',{exact:true}).count()!==0)throw Error('Local filter failed');
 await page.getByLabel('Search local findings').fill('nonsense');await page.getByText('No matching checks.',{exact:false}).waitFor();await page.getByLabel('Search local findings').fill('');
 await page.getByRole('button',{name:'Preview fix',exact:true}).click();await page.getByText('Enable firewall profiles',{exact:false}).waitFor();await page.keyboard.press('Escape');
 for(const width of [768,390]){await page.setViewportSize({width,height:950});await page.screenshot({path:`qa/sentinel-${width}.png`,fullPage:true});if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('Local overflow '+width);}
 fs.writeFileSync('qa/local-ui-results.json',JSON.stringify({mockBridge:true,summaryFilters:true,search:true,remediationPreview:true,widths:[1440,768,390],errors},null,2));await browser.close();server.kill();if(errors.length)throw Error(errors.join('\n'));
})().catch(e=>{console.error(e);process.exit(1)});
