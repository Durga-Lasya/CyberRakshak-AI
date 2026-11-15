# CyberRakshak AI — competition submission package

A multilingual voice-scam / social-engineering decision-support prototype using Gnani speech services.

## What's included

- Streamlit UI with transcript and audio upload workflow
- Gnani Prisma STT adapter (SDK integration is isolated in `cyberrakshak/gnani_client.py`)
- Explainable rule-based threat scoring and multi-indicator sequence bonuses
- Optional Evon contextual analysis adapter using an OpenAI-compatible chat-completions contract
- Optional Timbre spoken warning adapter
- Session dashboard and CSV export
- Synthetic labelled evaluation set and metric computation (precision, recall, F1, accuracy, confusion matrix)
- Unit tests
- Explicit consent and privacy limitations

## Important: do not misrepresent readiness

This is a complete runnable **prototype package**, not a certified production security product. The live microphone UI captures browser audio but does not yet provide a verified end-to-end Prisma WebSocket stream-to-dashboard pipeline. The actual streaming SDK and account entitlement must be confirmed against your Gnani developer account before enabling that claim. Uploaded audio is the supported speech-to-text path in this package.

Evon is optional and disabled by default. Its base URL, model name and key are intentionally not invented. Fill them only from the API details provided in your Gnani account. The Evon result is advisory; it never reduces the deterministic risk score.

The built-in evaluation data is synthetic and very small. It exists to demonstrate reproducible metric calculation, not to substantiate real-world performance. Replace it with a larger, diverse, consented and human-labelled dataset before reporting performance.

The detector is a phrase-based multilingual heuristic, not a trained or calibrated classifier. Language selection for Prisma does not guarantee that every dialect or code-mixed utterance will be understood. A low score is not proof that a caller is genuine or a conversation is safe.

## Requirements

Python 3.10 or 3.11 recommended. Windows, macOS or Linux. A Gnani API key for STT/TTS features.

## Install — Windows PowerShell

```powershell
py -3.11 -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
```

Edit `.env` and add your key. Never commit or share it.

## Install — macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
```

## Run

```bash
streamlit run app.py
```

## Test

```bash
pytest -q
```

Then use the Evaluation tab to calculate metrics on the included synthetic set.

## Gnani configuration

The official SDK evolves. Check current install and method signatures against:
- https://github.com/Gnani-AI-Mintlify/Gnani-Vachana
- https://docs.gnani.ai/

If the installed SDK differs, change only `cyberrakshak/gnani_client.py`. Verify Prisma STT and Timbre TTS access in your account.

## Evon configuration

Set:
- `EVON_BASE_URL`: exact API base URL or `/chat/completions` endpoint supplied by Gnani
- `EVON_API_KEY`: secret key
- `EVON_MODEL`: exact Evon model identifier

The adapter expects an OpenAI-compatible Chat Completions JSON response. If Gnani documents a different interface, adapt `cyberrakshak/evon.py` to the official schema. Keep Evon disabled until verified.

## Submission checklist

1. Run the app and capture screenshots of actual working features.
2. Test STT with several short, consented recordings.
3. Verify Timbre separately if enabled.
4. Configure Evon only using official credentials and endpoint details.
5. Expand the dataset and report measured results honestly.
6. Include limitations, privacy notice and consent in the public demo.
7. Do not claim live cellular-call interception, caller identity verification, guaranteed scam detection or measured accuracy unless actually implemented and validated.

## Demo flow (2 minutes)

1. Introduce voice-based social engineering and the need for explainable warnings.
2. Paste the included sample scam transcript.
3. Show score, evidence and recommended action.
4. Compare with a benign transcript.
5. Show the dashboard and export.
6. Run the evaluation tab and explain the synthetic dataset limitation.
7. If your API is configured, upload a consented audio clip to demonstrate Prisma transcription and generate a Timbre warning.
8. Explain future live streaming and multilingual evaluation roadmap accurately.


## Multilingual threat detection upgrade

The explainable rules engine now includes prototype scam-language patterns for
English, Hindi, Kannada, Tamil, Telugu, Malayalam, Bengali, Marathi, Gujarati,
Punjabi, and common Hinglish / code-mixed phrases. It looks for credential/OTP
requests, institutional impersonation, urgency, payment instructions,
remote-access requests, suspicious links, secrecy pressure, KYC pretexts,
and refund/prize lures. Multiple independent indicators can trigger a
sequence bonus.

Speech recognition and threat-language detection are separate capabilities:
Prisma must first transcribe a language correctly; the local rules then look
for supported phrases in that transcript. Coverage is phrase-based and not
exhaustive, especially for dialects, transliteration variants, noisy audio,
and code-mixed speech. A low score is not evidence that a call is safe.
Treat scores as prototype risk indicators, not calibrated probabilities.

The included multilingual tests use synthetic example phrases. Run them with:

```bash
python -m pytest -q
```

The Streamlit theme configuration and app styles use the requested dark
background, light text and blue accents.


## Updated multilingual regression coverage

The rule engine includes native-script and common Roman-script/code-mixed
patterns for the configured languages. Additional regression tests cover the
Kannada, Malayalam and Gujarati code-mixed OTP/account-block examples observed
during live testing, alongside protective OTP warnings to reduce false
positives. All 11 language choices remain available in the speech selector;
Kannada has not been removed.

Run the regression suite with `python -m pytest -q`. Passing synthetic tests
checks only those exact examples. Before a public demo, test varied speakers,
accents, dialects, code-mixing and harmless conversations in each language.
The rules are not a substitute for a labelled field evaluation.
