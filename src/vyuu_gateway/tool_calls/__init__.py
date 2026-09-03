"""Tool-call enforcement lifecycle.

The single tool-call entry point lives in `lifecycle.py`. There is no separate
"planner" path — identity validation, schema validation, policy evaluation,
and audit emission are all integrated into the lifecycle and must not be
bypassed.
"""
