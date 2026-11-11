import unittest
from unittest.mock import patch
from sentinelaudit.audit.base import CheckContext
from sentinelaudit.audit.checks.firewall import FirewallProfilesCheck
from sentinelaudit.audit.checks.bitlocker import BitLockerCheck
from sentinelaudit.audit.checks.tls_posture import TlsProtocolPostureCheck, _is_disabled, _is_enabled
from sentinelaudit.audit.engine import run_checks
from sentinelaudit.models import FindingStatus
from sentinelaudit.windows import CommandResult


class AccuracyTests(unittest.TestCase):
    def test_partial_firewall_never_passes(self):
        with patch('sentinelaudit.audit.checks.firewall.run_cmd', return_value=CommandResult('Domain Profile Settings\nState ON', '', 0)):
            finding = FirewallProfilesCheck().check(CheckContext(True))
            self.assertEqual(finding.status, FindingStatus.unknown)
            self.assertFalse(FirewallProfilesCheck().preview(CheckContext(True))['supported'])

    def test_tls_registry_precedence_and_server_unknown(self):
        self.assertFalse(_is_disabled({'Enabled': 1, 'DisabledByDefault': 1}))
        self.assertFalse(_is_enabled({'Enabled': 0, 'DisabledByDefault': 0}))
        self.assertIsNone(_is_disabled({'DisabledByDefault': 1}))
        states = [{'Enabled': 0}, {}, {'Enabled': 0}, {'Enabled': 0}, {'Enabled': 1}, {'Enabled': 1}]
        with patch('sentinelaudit.audit.checks.tls_posture._protocol_state', side_effect=states):
            self.assertEqual(TlsProtocolPostureCheck().check(CheckContext(True)).status, FindingStatus.unknown)

    def test_bitlocker_excludes_secret_fields_and_errors(self):
        with patch('sentinelaudit.audit.checks.bitlocker.run_cmd', return_value=CommandResult('{"protection":1,"volume":1,"protectors":["Tpm"],"RecoveryPassword":"SECRET"}', '', 0)) as cmd:
            finding = BitLockerCheck().check(CheckContext(True))
            self.assertEqual(finding.status, FindingStatus.pass_)
            self.assertNotIn('SECRET', finding.model_dump_json())
            self.assertNotIn('-protectors', str(cmd.call_args))
        with patch('sentinelaudit.audit.checks.bitlocker.run_cmd', return_value=CommandResult('SECRET', 'SECRET', 1)):
            finding = BitLockerCheck().check(CheckContext(True))
            self.assertEqual(finding.status, FindingStatus.unknown)
            self.assertNotIn('SECRET', finding.model_dump_json())

    def test_exception_reports_unknown_with_zero_coverage(self):
        with patch.object(BitLockerCheck, 'check', side_effect=RuntimeError('unavailable')):
            result = run_checks([BitLockerCheck()], CheckContext(False))
            self.assertEqual(result.unknown_count, 1)
            self.assertEqual(result.coverage_percent, 0)

    def test_password_fix_does_not_lower_stronger_policy(self):
        from sentinelaudit.audit.checks.password_policy import PasswordPolicyCheck
        with patch('sentinelaudit.audit.checks.password_policy._net_accounts_min_pw_len', return_value=20), patch.object(PasswordPolicyCheck, 'check') as check, patch('sentinelaudit.audit.checks.password_policy.run_cmd') as command:
            PasswordPolicyCheck().fix(CheckContext(True))
            command.assert_not_called()
            check.assert_called_once()
