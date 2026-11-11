const {chromium}=require('playwright');const fs=require('fs');
(async()=>{
 fs.mkdirSync('qa',{recursive:true});
 const server=require('child_process').spawn(process.execPath,['node_modules/vite/bin/vite.js','--host','127.0.0.1','--port','5174'],{cwd:require('path').resolve(__dirname,'../../frontend'),stdio:'ignore'});process.on('exit',()=>server.kill());
 for(let n=0;n<60;n++){try{await fetch('http://127.0.0.1:5174');break;}catch{await new Promise(r=>setTimeout(r,100));}}
 const browser=await chromium.launch({headless:true,executablePath:process.env.CHROMIUM_EXECUTABLE,args:['--no-sandbox','--disable-dev-shm-usage','--disable-gpu']});const page=await browser.newPage({viewport:{width:1440,height:1050},reducedMotion:'reduce'});const errors=[];page.on('pageerror',e=>errors.push(e.message));
 await page.addInitScript(()=>{
  localStorage.setItem('sentinelaudit.disclaimer.v1','accepted');
  const findings=['Windows Firewall Profiles','BitLocker Drive Encryption','TLS Protocol Posture','Password Policy'].map((name,i)=>({finding_id:'check.'+i,name,risk_level:i<2?'High':'Medium',status:i===0?'Fail':i===1?'Unknown':'Pass',description:'Checks the current Windows configuration against the security baseline.',details:{why_it_matters:'This control helps limit exposure to unauthorized access.',recommendation:'Review local evidence and apply the appropriate policy.'},fix_available:i===0,last_checked_utc:new Date().toISOString()}));
  const ok=async()=>({ok:true});const api={get_admin_status:async()=>({is_admin:true,version:'2.2'}),get_access_policy:async()=>({pin_required:false,setup_required:false}),verify_pin:ok,verify_login:ok,set_initial_login:ok,change_login:ok,keep_session_alive:async()=>({ok:true,session:{expired:false,remaining_s:600}}),run_audit:ok,start_audit:ok,get_audit_progress:async()=>({running:false,done:true,total:4,completed:4,hardening_score:67,findings,generated_utc:new Date().toISOString()}),fix_finding:ok,preview_fix:async()=>({supported:true,is_admin:true,changes:['Enable firewall profiles'],rollback_supported:true}),rollback_fix:ok,export_excel:async()=>window.exportMode==="error"?{saved_to:null,error:"Disk full"}:window.exportMode==="cancel"?{saved_to:null}:{saved_to:"C:/Reports/audit.xlsx"},backup_registry:async()=>({saved_to:"C:/Reports/backup.reg"}),open_updates_page:ok,set_tray_score:ok,exit_app:ok};window.pywebview={api};
 });
 await page.goto('http://127.0.0.1:5174');await page.getByPlaceholder('Password',{exact:true}).fill('fixture-password');await page.getByRole('button',{name:'Login',exact:true}).click();await page.getByText('Audit completed',{exact:true}).waitFor();
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
 fs.writeFileSync('qa/sentinel-export-results.json',JSON.stringify({success:true,savedPath:true,cancellation:true,failure:true,errors},null,2));
 await browser.close();server.kill();if(errors.length)throw Error(errors.join('\n'));
})().catch(e=>{console.error(e);process.exit(1)});
