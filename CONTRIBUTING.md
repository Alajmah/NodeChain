# Contributing to NodeChain

Thank you for your interest in NodeChain. This project is **roadmap-controlled**:
development follows a frozen roadmap that determines sequencing and priority.

## Roadmap control

NodeChain is not a general-purpose open-source project that accepts unsolicited
feature work. The frozen roadmap governs what is built and in what order.

- **Bug reports** are welcome at any time.
- **Feature requests** may be submitted but do not imply acceptance or
  implementation commitment. The roadmap determines what is prioritized.
- **Unsolicited feature pull requests** may be declined or deferred until the
  relevant roadmap milestone is reached.
- **Bug-fix pull requests** aligned to an existing roadmap item or open issue
  are welcome and will be reviewed.

## How to contribute a bug fix

1. Check existing issues to avoid duplicates.
2. Open an issue describing the bug with a minimal reproduction.
3. Fork the repository and create a branch from `master`.
4. Keep changes bounded — one logical fix per pull request.
5. Ensure all CI checks pass (GitHub-hosted Linux and Windows).
6. Reference the issue number in your pull request.

## Development setup

```bash
git clone https://github.com/Alajmah/NodeChain.git
cd NodeChain
pip install -e ".[dev]"
```

Run the fast test suite:

```bash
python -m pytest tests/ -q --tb=short
```

## Code style

- Python 3.12+.
- Type hints are required on public APIs.
- `ruff` is the linter/formatter (configuration in `pyproject.toml`).
- Tests use `pytest`. New code must include tests.

## Pull request requirements

- Target `master`.
- All GitHub-hosted CI checks must pass.
- Publication Tree must pass on both Ubuntu and Windows.
- Keep the commit history clean and linear.
- Do not introduce secrets, credentials, or private infrastructure identifiers.

## License

By contributing, you agree that your contributions are licensed under the MIT
License, the same license that covers the project.
