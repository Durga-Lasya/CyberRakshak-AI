# Submission notes — CyberRakshak AI

## Problem
Voice-based social engineering can pressure people into sharing OTPs, PINs, passwords, approving UPI requests, installing remote-access software or disclosing sensitive data.

## Proposed solution
CyberRakshak AI transcribes a consented voice recording using Gnani Prisma and applies an explainable, multi-signal detector to identify risky conversational patterns. It can optionally use Evon for contextual explanation and Timbre to speak a warning.

## What is technically distinctive
- Multi-signal sequence scoring rather than a single keyword trigger
- Evidence snippets explain why the alert fired
- Separate deterministic scoring and optional LLM explanation
- Human-centred warning and independent-verification advice
- Reproducible evaluation code and explicit limitations

## Claims to avoid
Do not claim the software identifies the real caller, intercepts arbitrary cellular calls, guarantees scam detection, or has a particular real-world accuracy based only on the included synthetic data.

## Evidence to collect before final submission
- Screenshot of successful application launch
- Screenshot of Prisma transcription from an actual test audio clip
- Screenshot of Timbre output if your account has access
- Screenshot of Evon output if configured and verified
- Terminal output of `pytest -q`
- Evaluation metrics on a larger human-labelled test set
- Short public demo video with no personal information or API keys visible
