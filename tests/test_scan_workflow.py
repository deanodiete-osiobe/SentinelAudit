import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace,ModuleType
from unittest.mock import Mock,patch
from sentinelaudit.audit.base import CheckContext
from sentinelaudit.audit.engine import run_checks,AuditCancelled
from sentinelaudit.models import Finding,RiskLevel,FindingStatus,AuditResult
from sentinelaudit.posture import build_posture_report
from sentinelaudit.activity import Ledger
from sentinelaudit.sync import queue_report

# Test only Python bridge logic; native WebView is a separate Windows pilot.
with patch.dict(sys.modules, {'webview':ModuleType('webview')}):
    spec=importlib.util.spec_from_file_location('desktop_under_test',Path(__file__).parents[1]/'app/main.py')
    desktop=importlib.util.module_from_spec(spec);spec.loader.exec_module(desktop)

def finding():
    return Finding(finding_id='network_defense.firewall_profiles',name='Firewall',description='Firewall check',
        risk_level=RiskLevel.high,status=FindingStatus.pass_,details={'domain_state':'ON','secret':'NEVER_SYNC'})

def check(fn=None):
    return SimpleNamespace(finding_id='network_defense.firewall_profiles',name='Firewall',description='Firewall check',risk_level=RiskLevel.high,check=fn or (lambda ctx:finding()))

class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.storage=patch('sentinelaudit.activity.activity_directory',return_value=self.root);self.storage.start()
        self.admin=patch('sentinelaudit.windows.is_admin',return_value=False);self.admin.start()
        with patch.object(desktop.DesktopApi,'_load_rollback_cache',return_value={}):self.api=desktop.DesktopApi()
        self.release=threading.Event()
    def tearDown(self):
        self.release.set()
        if self.api._audit_thread:self.api._audit_thread.join(3)
        self.admin.stop();self.storage.stop();self.temp.cleanup()
    def events(self):
        db=self.api._activity_ledger.connect()
        try:return [json.loads(row[0]) for row in db.execute('SELECT payload FROM ledger ORDER BY seq')]
        finally:db.close()
    def complete(self):
        with patch('sentinelaudit.services.audit_registry.load_checks',return_value=[check()]):
            self.assertTrue(self.api.start_audit()['ok']);self.api._audit_thread.join(3)
        self.assertTrue(self.api.get_audit_progress()['done'])
    def test_completed_scan_has_progress_report_and_ledger(self):
        self.complete();state=self.api.get_audit_progress()
        self.assertEqual(state['completed'],1);self.assertFalse(state['cancelled'])
        self.assertEqual(self.api._last_report['schema_version'],1)
        self.assertNotIn('NEVER_SYNC',json.dumps(self.api._last_report))
        self.assertEqual([e['action'] for e in self.events()],['scan_started','scan_completed'])
    def test_cancel_waits_current_check_and_never_publishes_partial_report(self):
        entered=threading.Event()
        def blocked(ctx):entered.set();self.release.wait(3);return finding()
        with patch('sentinelaudit.services.audit_registry.load_checks',return_value=[check(blocked),check()]):
            self.api.start_audit();self.assertTrue(entered.wait(1));self.api.cancel_audit()
            self.assertTrue(self.api.get_audit_progress()['cancelling'])
            self.release.set();self.api._audit_thread.join(3)
        state=self.api.get_audit_progress();self.assertTrue(state['cancelled']);self.assertEqual(state['completed'],1)
        self.assertIsNone(self.api._last_report)
        self.assertIn('Complete',self.api.export_excel()['error'])
        self.assertIn('scan_cancelled',[e['action'] for e in self.events()])
    def test_duplicate_start_does_not_spawn_second_worker(self):
        entered=threading.Event()
        def blocked(ctx):entered.set();self.release.wait(3);return finding()
        with patch('sentinelaudit.services.audit_registry.load_checks',return_value=[check(blocked)]):
            self.api.start_audit();self.assertTrue(entered.wait(1));worker=self.api._audit_thread
            self.assertTrue(self.api.start_audit()['already_running']);self.assertIs(worker,self.api._audit_thread)
    def test_check_failure_is_unknown_with_actionable_guidance(self):
        result=run_checks([check(Mock(side_effect=PermissionError('denied')))],CheckContext(False))
        self.assertEqual(result.findings[0].status,FindingStatus.unknown)
        self.assertIn('permissions',result.findings[0].details['next_step'])
    def test_completed_export_and_cancel_are_distinct_ledger_events(self):
        self.complete();target=self.root/'report.xlsx'
        with patch('sentinelaudit.windows.pick_save_path',return_value=str(target)),patch('sentinelaudit.reporting.excel.build_excel_report',return_value=b'export'):
            self.assertEqual(self.api.export_excel()['saved_to'],str(target))
        with patch('sentinelaudit.windows.pick_save_path',return_value=None):
            self.assertIsNone(self.api.export_excel()['saved_to'])
        actions=[e['action'] for e in self.events()]
        self.assertIn('report_export_completed',actions);self.assertIn('report_export_cancelled',actions)
        self.assertEqual(len([e for e in self.events() if e.get('sha256')]),1)
    def test_export_build_failure_is_reported_and_logged(self):
        self.complete()
        with patch('sentinelaudit.windows.pick_save_path',return_value=str(self.root/'bad.xlsx')),patch('sentinelaudit.reporting.excel.build_excel_report',side_effect=PermissionError()):
            result=self.api.export_excel()
        self.assertIn('permissions',result['error']);self.assertFalse((self.root/'bad.xlsx').exists())
        self.assertEqual(self.events()[-1]['action'],'report_export_failed')
    def test_tampered_ledger_blocks_scan_and_preserves_evidence(self):
        self.complete();db=self.api._activity_ledger.connect()
        with db:db.execute("UPDATE ledger SET payload='{}' WHERE seq=1")
        db.close()
        with patch('sentinelaudit.services.audit_registry.load_checks',return_value=[check()]):
            self.assertFalse(self.api.start_audit()['ok'])
        self.assertIn('integrity',self.api.export_excel()['error'])
    def test_tail_deletion_detected_by_local_checkpoint(self):
        self.complete();db=self.api._activity_ledger.connect()
        with db:db.execute('DELETE FROM ledger WHERE seq=2')
        db.close()
        with self.assertRaisesRegex(ValueError,'truncated'):self.api._activity_ledger.verify()
    def test_privileged_scan_requires_login(self):
        with patch('sentinelaudit.windows.is_admin',return_value=True):
            self.assertIn('Session expired',self.api.start_audit()['error'])
        self.assertIsNone(self.api._audit_thread)
    def test_sync_queue_is_optional_bounded_and_idempotent(self):
        self.complete();report=self.api._last_report
        with self.assertRaisesRegex(ValueError,'Install'):queue_report(report,self.root/'absent')
        (self.root/'config.ini').write_text('[admin]\napi_key=fixture-credential\n')
        self.assertTrue(queue_report(report,self.root)['queued'])
        self.assertTrue(queue_report(report,self.root)['already_queued'])
        payload=(self.root/'posture'/(report['run_id']+'.json')).read_text()
        self.assertNotIn('credential',payload);self.assertNotIn('NEVER_SYNC',payload)
        for i in range(31):(self.root/'posture'/f'old-{i}.json').write_text('{}')
        second=build_posture_report(AuditResult(hardening_score=100,findings=[finding()]))
        with self.assertRaisesRegex(ValueError,'full'):queue_report(second,self.root)
        self.assertEqual(len(list((self.root/'posture').glob('*.json'))),32)
    def test_sync_keeps_existing_report_on_conflict(self):
        self.complete();report=self.api._last_report
        (self.root/'config.ini').write_text('[admin]\napi_key=fixture\n');queue_report(report,self.root)
        altered=dict(report,engine_version='other')
        with self.assertRaisesRegex(ValueError,'Conflicting'):queue_report(altered,self.root)
        self.assertEqual(json.loads((self.root/'posture'/(report['run_id']+'.json')).read_text()),report)
    def test_sync_requires_session_and_completed_scan(self):
        self.assertIn('Session expired',self.api.sync_last_audit()['error'])
        self.api._require_session=Mock(return_value=(True,None))
        self.assertIn('fresh audit',self.api.sync_last_audit()['error'])
    def test_serializer_has_stable_run_identity_and_allowlisted_fields(self):
        result=AuditResult(hardening_score=100,findings=[finding()]);first=build_posture_report(result)
        self.assertEqual(first,build_posture_report(result,first['run_id']))
        self.assertEqual(first['findings'][0]['observations'],{'domain_state':'ON'})
