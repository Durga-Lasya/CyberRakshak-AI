"""Consent-based browser microphone capture connected to Gnani Prisma WebSocket STT."""
from __future__ import annotations

import asyncio
import os
import queue
import threading
import time
from collections import deque
from typing import Optional

import av
import numpy as np
from streamlit_webrtc import AudioProcessorBase


class LivePrismaBridge:
    """Thread-safe bridge between WebRTC audio callbacks and Gnani's async STT stream."""

    def __init__(self, language_code: str = "indic-auto", api_key: str = ""):
        self.language_code = language_code
        self.api_key = (api_key or os.getenv("GNANI_API_KEY", "")).strip()
        self._lock = threading.Lock()
        self._texts = deque(maxlen=40)
        self._status = "Waiting for microphone"
        self._error: Optional[str] = None
        self._dropped_frames = 0
        self._audio_queue = queue.Queue(maxsize=100)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._audio_queue = queue.Queue(maxsize=100)
            self._stop_event = threading.Event()
            self._error = None
            self._status = "Connecting to Gnani Prisma..."
            self._thread = threading.Thread(
                target=self._thread_main,
                name="cyberrakshak-prisma-stream",
                daemon=True,
            )
            self._thread.start()

    def stop(self):
        self._stop_event.set()
        try:
            self._audio_queue.put_nowait(None)
        except queue.Full:
            pass
        with self._lock:
            if self._status not in ("Error", "Disconnected"):
                self._status = "Stopping stream..."

    def offer_pcm_frame(self, frame_bytes: bytes):
        if self._stop_event.is_set():
            return
        if len(frame_bytes) != 1024:
            return
        try:
            self._audio_queue.put_nowait(frame_bytes)
        except queue.Full:
            # Keep latency bounded: discard the oldest frame rather than queueing
            # seconds of stale audio.
            try:
                self._audio_queue.get_nowait()
                self._audio_queue.put_nowait(frame_bytes)
                with self._lock:
                    self._dropped_frames += 1
            except (queue.Empty, queue.Full):
                pass

    def add_transcript(self, text: str, detected_language: Optional[str] = None):
        text = (text or "").strip()
        if not text:
            return
        with self._lock:
            self._texts.append({
                "text": text,
                "language": detected_language or self.language_code,
                "time": time.strftime("%H:%M:%S"),
            })
            self._status = "Connected · receiving transcripts"

    def clear_transcript(self):
        """Clear the visible risk-analysis window without interrupting the audio stream."""
        with self._lock:
            self._texts.clear()
            self._error = None
            self._status = "Connected · new analysis session" if self._thread and self._thread.is_alive() else self._status

    def set_status(self, status: str):
        with self._lock:
            self._status = status

    def set_error(self, message: str):
        with self._lock:
            self._error = str(message)
            self._status = "Error"

    def snapshot(self):
        with self._lock:
            segments = list(self._texts)
            return {
                "status": self._status,
                "error": self._error,
                "segments": segments,
                "transcript": " ".join(item["text"] for item in segments),
                "dropped_frames": self._dropped_frames,
            }

    def _thread_main(self):
        try:
            asyncio.run(self._async_stream())
        except Exception as exc:
            self.set_error(
                f"{type(exc).__name__}: {exc}. Check GNANI_API_KEY, Prisma streaming "
                "entitlement, network access and installed gnani-vachana version."
            )

    async def _async_stream(self):
        api_key = self.api_key or os.getenv("GNANI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError(
                "GNANI_API_KEY is missing. Add it to .env for local runs or Streamlit Secrets for deployment."
            )

        try:
            from gnani.stt import (
                GnaniSTTStreamClient,
                StreamTranscriptEvent,
                StreamErrorEvent,
                StreamConnectedEvent,
            )
        except ImportError as exc:
            raise RuntimeError(
                "Gnani streaming SDK is unavailable. Run: pip install --upgrade gnani-vachana"
            ) from exc

        async with GnaniSTTStreamClient(
            api_key=api_key,
            language_code=self.language_code,
            model="prisma-v3.0",
            sample_rate=16000,
            format="codemix",
        ) as stream:
            self.set_status("Connected to Gnani Prisma · speak now")

            async def send_audio():
                while not self._stop_event.is_set():
                    try:
                        packet = await asyncio.to_thread(
                            self._audio_queue.get, True, 0.4
                        )
                    except queue.Empty:
                        continue
                    if packet is None:
                        break
                    await stream.send_audio(packet)

            async def receive_events():
                async for event in stream:
                    if isinstance(event, StreamTranscriptEvent):
                        self.add_transcript(
                            event.text,
                            getattr(event, "detected_language_code", None),
                        )
                    elif isinstance(event, StreamErrorEvent):
                        self.set_error(event.message)
                    elif isinstance(event, StreamConnectedEvent):
                        self.set_status("Connected to Gnani Prisma · speak now")

            sender = asyncio.create_task(send_audio())
            receiver = asyncio.create_task(receive_events())
            try:
                while not self._stop_event.is_set():
                    if receiver.done():
                        error = receiver.exception()
                        if error:
                            raise error
                        break
                    await asyncio.sleep(0.1)
            finally:
                sender.cancel()
                receiver.cancel()
                await asyncio.gather(sender, receiver, return_exceptions=True)

        self.set_status("Disconnected")


class LiveAudioProcessor(AudioProcessorBase):
    """Convert WebRTC audio to 16 kHz mono PCM16 frames of exactly 1024 bytes."""

    def __init__(self, bridge: LivePrismaBridge):
        self.bridge = bridge
        self.bridge.start()
        self.resampler = av.AudioResampler(format="s16", layout="mono", rate=16000)
        self.byte_buffer = bytearray()

    def recv(self, frame: av.AudioFrame) -> av.AudioFrame:
        try:
            converted = self.resampler.resample(frame)
            if not isinstance(converted, list):
                converted = [converted]
            for pcm_frame in converted:
                if pcm_frame is None:
                    continue
                samples = pcm_frame.to_ndarray()
                pcm = np.asarray(samples, dtype=np.int16).reshape(-1).tobytes()
                self.byte_buffer.extend(pcm)
                while len(self.byte_buffer) >= 1024:
                    chunk = bytes(self.byte_buffer[:1024])
                    del self.byte_buffer[:1024]
                    self.bridge.offer_pcm_frame(chunk)
        except Exception as exc:
            self.bridge.set_error(f"Microphone audio conversion failed: {exc}")
        return frame

    def __del__(self):
        try:
            self.bridge.stop()
        except Exception:
            pass
