# Retired preproduction deployment

The owner decommissioned RN preproduction on 2026-10-11. There is no active
preproduction receiver, automatic update controller, signed CD notification or
default fleet deployment. Their executable entry points have been removed.

Validate changes in isolated development-host fixtures. Reviewed dev-to-main
promotion and public exact-SHA image publication do not deploy production.
Production changes use the explicit [operator upgrade workflow](operator-upgrade.md).
Historical evidence under `docs/audits` retains its original scope and dates.
