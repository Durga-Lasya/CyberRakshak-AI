import os, tempfile
from pathlib import Path

class GnaniConfigError(RuntimeError):
    pass


class GnaniService:
    """
    Isolated adapter for Gnani SDK calls. SDK APIs can change between releases.
    Verify the installed version against the official README and account docs.
    """

    def __init__(self):
        self.key = os.getenv("GNANI_API_KEY", "").strip()
        if not self.key:
            raise GnaniConfigError("GNANI_API_KEY missing in .env.")

        try:
            from gnani.stt import GnaniSTTClient
            from gnani.tts import GnaniTTSClient

            self.stt = GnaniSTTClient(api_key=self.key)
            self.tts = GnaniTTSClient(api_key=self.key)
        except Exception as e:
            raise GnaniConfigError(
                f"Gnani SDK client could not initialise: {e}"
            ) from e

    def transcribe(self, data, filename, language):
        suffix = Path(filename).suffix or ".wav"

        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
            f.write(data)
            name = f.name

        try:
            # Prisma v3.0 is required when using the indic-auto language setting.
            result = self.stt.transcribe(
                name,
                language_code=language,
                model="prisma-v3.0",
            )

            if isinstance(result, dict):
                text = result.get("transcript") or result.get("text") or ""
            else:
                text = (
                    getattr(result, "transcript", None)
                    or getattr(result, "text", None)
                    or str(result)
                )

            if not str(text).strip():
                raise RuntimeError("Prisma returned no transcript.")

            return str(text).strip()

        except Exception as e:
            raise RuntimeError(f"Prisma transcription error: {e}") from e

        finally:
            try:
                os.remove(name)
            except OSError:
                pass

    def speak(self, text, language, voice):
        result = self.tts.synthesize(
            text,
            voice=voice,
            model="timbre-v2.5",
            language=language,
        )

        if isinstance(result, bytes):
            return result
        if isinstance(result, dict) and isinstance(result.get("audio"), bytes):
            return result["audio"]

        raise RuntimeError(
            "Unexpected Timbre response. Check the installed SDK's documented return type."
        )
