# Live Prisma transcription fix

This is a replacement build of CyberRakshak AI with the Live monitor connected to
Gnani's documented Prisma v3.0 WebSocket STT API.

## Install/update

Activate the project's virtual environment, then run:

```bash
python -m pip install --upgrade -r requirements.txt
```

Make sure `.env` contains (local run):

```env
GNANI_API_KEY=your_real_gnani_api_key
```

For Streamlit Cloud / hosted deployment, open the app's **Settings → Secrets**
and add this TOML entry:

```toml
GNANI_API_KEY = "your_real_gnani_api_key"
```

The live tab reads from either local `.env` or Streamlit Secrets.

## Run locally

```bash
streamlit run app.py
```

Open the Live monitor tab, click START, allow microphone permission, speak a full
sentence for 3–5 seconds, then pause for 1–2 seconds. Prisma's voice activity
detection may emit a transcript at the end of a phrase, not word-by-word.

## If you still get no transcript

1. Read the Prisma connection status shown under the microphone control.
2. If it says the API key is missing, configure `.env` or hosted app Secrets.
3. If it says authentication/forbidden/model unavailable, check the key and
   confirm Prisma v3.0 streaming is included in your Gnani account.
4. If browser audio does not arrive, test on localhost or a secure HTTPS origin,
   allow microphone access, and select the correct microphone in the device menu.
5. Update the SDK with `python -m pip install --upgrade gnani-vachana`.

## What changed

- AudioProcessorBase now resamples microphone audio to 16 kHz, mono, signed PCM16.
- Audio bytes are framed into 1,024-byte packets.
- Packets are sent to `GnaniSTTStreamClient` at the real-time cadence produced by
  WebRTC capture.
- Prisma transcript events are stored in a thread-safe bridge.
- A Streamlit fragment refreshes the live text and threat assessment every second.

The streaming setup follows Gnani's current SDK README and Prisma v3 streaming
requirements. Prisma returns completed speech segments using voice activity
detection, so allow a short pause after speaking.

## Safety / limitations

The microphone is only the browser-selected input. It does not silently tap into
ordinary cellular calls or automatically capture the other caller. Use with
informed consent. This is a prototype decision-support tool, not a caller
identity verifier or guarantee of scam detection.
