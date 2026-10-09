"""SHA write-once publishing; deterministic fast tests, no daemon or network."""
import unittest
from unittest.mock import Mock

from scripts.publish_native_image import publish
from scripts.registry_images import ManifestUnknown

SHA = 'a' * 40
PROOF = {'image': 'ghcr.io/fixture@sha256:' + 'b' * 64,
         'tag_digest': 'sha256:' + 'c' * 64, 'config_digest': 'sha256:' + 'd' * 64}


def plan(missing=False):
    return {'revision': SHA, 'components': {'web': {'missing': missing, **({} if missing else PROOF)}}}


class PublicationTests(unittest.TestCase):
    def test_same_sha_repeat_and_other_branch_reuse_exact_bytes_without_build(self):
        probe, build = Mock(return_value=PROOF), Mock()
        for branch in ('dev', 'dev-rerun', 'main-same-sha'):
            self.assertEqual(publish(SHA, 'web', plan(), probe, build), {'action': 'reused', **PROOF}, branch)
        build.assert_not_called()

    def test_missing_plan_another_serialized_publisher_already_filled_tag_reuses(self):
        build = Mock()
        self.assertEqual(publish(SHA, 'web', plan(True), Mock(return_value=PROOF), build)['action'], 'reused')
        build.assert_not_called()

    def test_verified_existing_drift_or_disappearance_never_rebuilds(self):
        for probe in (Mock(return_value={**PROOF, 'tag_digest': 'sha256:' + 'e' * 64}),
                      Mock(side_effect=ManifestUnknown())):
            build = Mock()
            with self.assertRaises(ValueError):
                publish(SHA, 'web', plan(), probe, build)
            build.assert_not_called()

    def test_only_missing_tag_builds_once_and_post_push_digest_must_match(self):
        build = Mock(return_value=PROOF['tag_digest'])
        probe = Mock(side_effect=[ManifestUnknown(), PROOF])
        self.assertEqual(publish(SHA, 'web', plan(True), probe, build), {'action': 'published', **PROOF})
        build.assert_called_once_with(SHA, 'web')
        with self.assertRaises(ValueError):
            publish(SHA, 'web', plan(True), Mock(side_effect=[ManifestUnknown(), PROOF]), Mock(return_value='sha256:' + 'f' * 64))

    def test_network_permission_corruption_errors_never_grant_build(self):
        for exception in (OSError(), ValueError()):
            build = Mock()
            with self.assertRaises(type(exception)):
                publish(SHA, 'web', plan(True), Mock(side_effect=exception), build)
            build.assert_not_called()

    def test_invalid_plan_and_builder_digest_fail_closed(self):
        for invalid in ({}, {'revision': 'b' * 40, 'components': {}},
                        {'revision': SHA, 'components': {'web': {'missing': 'true'}}}):
            build = Mock()
            with self.assertRaises(ValueError):
                publish(SHA, 'web', invalid, Mock(), build)
            build.assert_not_called()
        for digest in (None, 'sha256:bad'):
            with self.assertRaises(ValueError):
                publish(SHA, 'web', plan(True), Mock(side_effect=ManifestUnknown()), Mock(return_value=digest))
