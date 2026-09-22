# Contributing to omni-sec

Thank you for contributing to omni-sec!

## Responsible Security Guidelines

1. **Educational & Defensive Focus**: All tools, knowledge modules, and solver recipes must be designed for authorized CTF competitions, educational laboratories, and defensive application security review.
2. **Deterministic Code**: Solver scripts and tools should be reliable, well-tested, and maintain zero heavy dependencies.
3. **No Weaponized Payloads**: Do not commit exploits targeting unpatched zero-day vulnerabilities in live public systems.

## Contribution Workflow

1. Fork the repository & create a feature branch (`git checkout -b feature/new-crypto-attack`).
2. Add comprehensive unit tests in `tests/` for any new Python script or decoding algorithm.
3. Run unit tests locally before submitting:
   ```bash
   python -m pytest tests/ -v
   ```
4. Ensure all markdown files follow the clean documentation standard without unnecessary slop.
5. Submit a pull request.
