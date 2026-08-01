# Contributing

## Running things locally

```bash
pip install -r requirements.txt
PYTHONPATH=. python3 -m unittest discover -s tests -v
python3 cli.py policy validate policies/default.yaml
```

## Adding a rule type

New deterministic checks go in `guardrail/rules.py` as a
`check_*(request, policy) -> List[RuleMatch]` function, wired into
`GuardrailEngine.evaluate()` in `guardrail/engine.py`, with config parsed
in `guardrail/core/policy.py::Policy.from_dict`. Add a test in
`tests/test_rules.py` and, if you add fields to `policies/default.yaml`,
a corresponding test in `tests/test_default_policy.py`.

## Ground rules

- No statistical risk scoring, no mock data pretending to be live. Every
  check needs to be traceable to an explicit rule in a policy file — that
  is the entire premise of this project.
- Every new rule type needs a test against a real (non-mocked) code path.
- If you touch `policies/default.yaml`, run `guardrail policy validate`
  before opening a PR — CI will also catch it, but it's instant locally.
- Keep `guardrail/core/*` and `guardrail/rules.py` dependency-free
  (standard library only). PyYAML stays confined to policy loading.

## Reporting a bypass

If you find an action that should have been blocked/warned and wasn't,
please open an issue with the exact `agent_id`/`tool_name`/`arguments`
that got through — that's a real bug in the default policy or the engine,
not a feature request, and will be treated with priority.
