# Contributing

Bug hunters welcome. Every improvement here makes real hunts more effective.

## What We Most Need

| Contribution | Why It Matters |
|:---|:---|
| New scanner modules or detection techniques | Increases surface coverage |
| Payload additions to `skills/security-arsenal/SKILL.md` | Better bypass coverage |
| Methodology improvements backed by paid reports | Proven techniques only |
| Platform support (YesWeHack · Synack · HackenProof) | Wider program coverage |
| False positive fixes with regression tests | Community's top complaint |

## Before You Start

1. **Check open issues** — your idea may already be in progress
2. **One feature per PR** — keeps review fast and clean
3. **Test your changes** — run `pytest tests/` before opening the PR
4. **No theoretical bugs** — if it's a scanner addition, it must have a real PoC or real-world precedent

## Workflow

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/claude-bug-bounty.git
cd claude-bug-bounty

# 2. Create a branch
git checkout -b feat/your-contribution

# 3. Make your changes, run tests
pytest tests/

# 4. Commit
git commit -m "feat: short description of what and why"

# 5. Push and open PR
git push origin feat/your-contribution
```

## Commit Message Format

```
feat:  new capability
fix:   bug fix
docs:  documentation only
test:  adding or fixing tests
chore: maintenance (deps, CI, cleanup)
```

## PR Checklist

- [ ] Tests pass (`pytest tests/`)
- [ ] No hardcoded targets, API keys, or real domain names in code
- [ ] Scanner additions use `[CONFIRMED]` / `[POSSIBLE]` / `[INFORMATIONAL]` confidence states
- [ ] Methodology changes are backed by a real finding or public write-up

## Questions?

Open a [GitHub Discussion](https://github.com/shuvonsec/claude-bug-bounty/discussions) or reach out at [shuvonsec@gmail.com](mailto:shuvonsec@gmail.com).
