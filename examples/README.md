# Examples

## toolkit_integration.py

Self-contained integration demo. No MCP server needed.

```bash
pip install -e .
python examples/toolkit_integration.py
```

Runs 3 scenarios: L1 auto-approve, L2 sentinel warn, L3 human escalate.
Prints verdict, ring mapping, and SLI compliance for each.
