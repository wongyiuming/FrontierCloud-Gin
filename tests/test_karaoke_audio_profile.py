from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "static/media/karaoke.html").read_text(encoding="utf-8")
QUALITY = (ROOT / "static/js/karaoke-audio-quality.js").read_text(encoding="utf-8")
CORE = (ROOT / "static/js/karaoke.js").read_text(encoding="utf-8")


class KaraokeAudioProfileTests(unittest.TestCase):
    def test_karaoke_defaults_keep_recording_near_unity_and_monitor_loud(self):
        self.assertIn('id="voiceValue">30%</output>', HTML)
        self.assertRegex(HTML, r'id="voiceGain"[^>]*max="200"[^>]*value="100"')
        self.assertIn('id="monitorValue">150%</output>', HTML)
        self.assertRegex(HTML, r'id="monitorGain"[^>]*value="100"')
        self.assertRegex(HTML, r'id="monitor" type="checkbox" checked')
        self.assertNotRegex(HTML, r'id="aec" type="checkbox" checked')

    def test_quality_profile_turns_limiter_into_peak_guard(self):
        for statement in ("graph.limiter.threshold.value = -1;", "graph.limiter.knee.value = 0;",
                          "graph.limiter.ratio.value = 20;", "graph.limiter.attack.value = 0.002;",
                          "graph.limiter.release.value = 0.06;", "audioBitsPerSecond: 128000"):
            self.assertIn(statement, QUALITY)

    def test_karaoke_capture_keeps_browser_leveling_disabled(self):
        for statement in ("noiseSuppression: false", "autoGainControl: false", "channelCount: 1",
                          "echoCancellation: elements.aec.checked"):
            self.assertIn(statement, CORE)

    def test_quality_profile_exposes_actual_capture_and_input_meter(self):
        for statement in ('id="inputMeter"', 'id="captureSettings"'):
            self.assertIn(statement, HTML)
        for statement in ("getSettings?.()", "getFloatTimeDomainData",
                          "RMS ${dbfs(rms).toFixed(1)} dBFS", "接近削波"):
            self.assertIn(statement, QUALITY)

    def test_audio_quality_profile_loads_after_karaoke_core(self):
        self.assertLess(HTML.index("{{KARAOKE_JS_URL}}"), HTML.index("/static/js/karaoke-audio-quality.js"))
