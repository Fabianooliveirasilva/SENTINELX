"""AI security analyst (Phase 9): optional, advisory, evidence-bound.

* ``schemas``     — the structured output every analysis must match
* ``prompts``     — versioned system prompt and per-kind task prompts
* ``context``     — minimized, pseudonymized context built from the database
* ``validation``  — server-side checks of the model's claims against the context
* ``fallback``    — deterministic analyses used whenever the model is not
* ``providers``   — provider abstraction and the Anthropic implementation
"""
