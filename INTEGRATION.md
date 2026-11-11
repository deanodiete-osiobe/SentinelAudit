> Update: standalone completed scans can now be explicitly handed to the local enrolled Client. See [SCAN_AND_SYNC.md](SCAN_AND_SYNC.md) for this workflow and its limits. The existing scheduled-agent audit flow below remains available.

# SentinelAudit + System Agent integration candidate

See `docs/SENTINEL_INTEGRATION.md` in the accompanying System Agent package for deployment, protocol, limits and verification.

The standalone app remains local. Its checks, including the accuracy fixes in this package, are vendored into System Agent 2.2.0. The agent runs its own read-only checks under the service identity. The desktop app does not send reports or receive remote fixes. A local fix becomes visible centrally after a scheduled or requested agent audit. Service and interactive-user results can differ where a check depends on user context.

## Review changes

- Fixed two indentation defects that prevented `app/main.py` from compiling. The local HTTP thread no longer keeps the process alive after the UI exits.
- Removed raw BitLocker protector output; only protection/encryption state and protector types are selected before JSON serialization. Recovery passwords are not included.
- Incomplete firewall profile output is Unknown, not Pass; preview and rollback claims require all profiles.
- TLS evaluation includes client AND server registry states and respects explicit Enabled values. DisabledByDefault alone is insufficient to claim disabled; absent explicit settings remain Unknown.
- Password complexity and length use a temporary `secedit /export /areas SECURITYPOLICY` file rather than an unsupported registry assumption and localized net-accounts parsing. The file is removed after reading. Fixing minimum length no longer lowers an already stronger policy.
- Results expose assessment coverage and unknown count; the dashboard explains the score denominator.
- Developer debugging is opt-in via SENTINEL_DEBUG=1 for source runs.
- Updated frontend lockfile to address npm audit findings. Aligned Pydantic with the integrated engine.

This was a targeted source review and integration, not a complete penetration test or compliance certification. Remaining Windows checks include localized command parsing and context-sensitive policy reads. Validate the 19-check baseline on representative Windows editions, languages, domain policies and privilege levels. Reference labels do not certify CIS compliance.

Run `python tests/run_portable.py` for portable mocked unit tests; on Windows it uses real module imports but tests still mock OS operations. Build frontend with Node 22.12+: `npm ci`, then `npm run build`.
