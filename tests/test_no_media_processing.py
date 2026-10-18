"""Keep the removed conversion feature out of business and release surfaces."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RemovedMediaProcessingTests(unittest.TestCase):
    def test_optional_codec_and_controller_are_absent(self):
        for path in (
            "cmd/frontiercloud-processor/main.go",
            "cmd/frontiercloud-processing-controller/main.go",
            "internal/processing/tasks/store.go",
            "internal/httpapi/processing.go",
            "internal/node/processing.go",
            "ci/Dockerfile.processor",
            "compose.storage-direct-control.yaml",
            "compose.storage-processing-legacy.yaml",
            "static/js/processing-admin.js",
            "static/js/video-compatibility.js",
            "docs/media-processing.md",
        ):
            self.assertFalse((ROOT / path).exists(), path)

    def test_business_and_publication_have_no_processing_dependency(self):
        for name in (
            "Dockerfile", "ci/Dockerfile.web", "docker-compose.storage.yaml",
            ".github/workflows/publish-images.yml", "scripts/test-ci-source.sh",
            "static/media/admin.html", "static/js/admin-upload-integrity.js",
        ):
            text = (ROOT / name).read_text(encoding="utf-8")
            for token in ("processing-admin", "frontiercloud-processor", "processing-controller",
                          "video-compatibility", "PROCESSING_DEPLOYMENT", "missing_processor"):
                self.assertNotIn(token, text, (name, token))
