# Retired release execution and replacement coverage

The online update controller, self-handoff, automatic rollback, peer release RPCs,
whole-fleet release manifest and signed CD receiver are removed. Their historical
audit evidence remains unchanged; it does not certify the current source.

Current coverage preserves:

- `internal/nativeacceptance`: independent real five-node control, resource
  migration, Range and encryption fixtures, without any update-controller image.
- `internal/operator`: explicit upgrade plans, backup verification, closed-fence
  preparation, interrupted-operation reconciliation and separate opening.
- `tests/operator_recovery_acceptance.py`: actual SQLite/MySQL backup, restore,
  upgrade, managed reads and injected preparation failure on isolated Docker.
- `internal/release`: reviewed exact-source discovery and Web/Nginx image proof.
- `internal/sitecontrol`: audited manual maintenance, native fence protection,
  cancellation and preservation of unknown legacy flag bytes.
- Certificate controller and native Storage role/TLS/route regressions.

External gates are selected explicitly. Report executed passes and skips separately;
a green unit run does not claim a real database/fleet/browser acceptance run.
