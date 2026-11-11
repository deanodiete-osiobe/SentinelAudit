# Security Policy

## Secure Development Practices

- Never commit secrets, credentials, or tokens.
- Run `pip-audit` before releases.
- Run `npm audit --audit-level=high` before frontend releases.
- Use `bandit -r .` for Python SAST scanning.
- Use least-privilege filesystem permissions for local storage.

## Recommended Security Tooling

### Python
```bash
pip install bandit pip-audit
bandit -r .
pip-audit
```

### Frontend
```bash
npm audit --audit-level=high
```

## Reporting Vulnerabilities

Please report vulnerabilities privately to the project maintainer.