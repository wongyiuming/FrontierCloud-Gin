# EVOXT preproduction and CD

`ml.520mall.cc` is a separate business Master, not the production storage
identity. Use project `frontiercloud-staging`, data `/opt/frontiercloud-staging/data`,
an independent secrets volume, Redis and updater socket. Production storage
uses its own high-port project; never share state between these instances.

Bootstrap a reviewed fixed native revision and configure TLS, `STAGING_CD=true`,
`SERVER_NAME=ml.520mall.cc`, `RELEASE_BRANCH=main`, `RELEASE_SOURCE_BRANCH=dev`.
Keep the clean new-repository checkout at `/opt/frontiercloud-staging/repo`,
its environment outside source at `/opt/frontiercloud-staging/.env`, and the
initial full SHA at `/opt/frontiercloud-staging/current-revision`.
Link the checkout's ignored `.env` to the external environment so both Compose
interpolation and the application's `env_file` use the same staging settings.
Promote this fresh instance to Master before enabling CD.

CD is event-driven: a completed successful **dev push** run of `docker.yml`
triggers `.github/workflows/staging-cd.yml`. Failed/cancelled CI, main pushes,
PRs and foreign repositories cannot notify staging. The workflow must be present
on the default `main` branch to receive `workflow_run` events. It does not check
out triggering code or compile/deploy anything in GitHub; its timeout is one minute.

Install `staging-cd.sh` as `/opt/frontiercloud-staging/staging-cd.sh` and
`frontiercloud-staging-cd.service`, `frontiercloud-staging-cd.path` and
`frontiercloud-staging-trigger.service` into `/etc/systemd/system`.
Build `./cmd/staging-trigger` on the development host and install its binary at
`/usr/local/libexec/frontiercloud-staging-trigger`. Create a locked system user
`frontiercloud-staging-trigger`, with no shell, Docker group or sudo access.
Its systemd service has a 64 MiB memory limit and 10% CPU quota.

Generate a random signing secret of at least 32 bytes. Store the same value in
the repository's `STAGING_CD_SECRET` Actions secret and in
`/etc/frontiercloud-staging-trigger/secret` (root-owned, group-readable only by
the trigger account). Place the site's TLS certificate and private key in the
same restricted directory and maintain them through the certificate renewal hook.
Install `scripts/ops/staging-certificate-deploy.sh` as an executable Certbot
deploy hook on EVOXT only; set that domain's ACME webroot to
`/opt/frontiercloud-staging/certs/acme`, not the retired project directory.
The receiver uses HTTPS port **9443**, only authenticates wakeups, and can write
only its dedicated state directory. GitHub receives no SSH key, AdminKey or
Docker access. Never print the signing secret in logs.

After the first deployment and HTTPS smoke tests pass, enable the trigger service
and CD path unit. **Disable/remove the old CD timer; there is no five-minute
polling or scheduled fallback.** Valid HMAC-SHA256 events expire after five minutes;
durable receipts suppress duplicates and older runs. The path unit consumes a
queued event and starts the existing verified local controller. An event received
during an earlier deployment waits for that local updater to finish (bounded to
five minutes); this is not GitHub polling. Failed deployments require operator
attention, rather than repeatedly restarting the same failed update.

Inspect `journalctl -u frontiercloud-staging-trigger -u frontiercloud-staging-cd`
and GitHub's `Trigger preproduction CD` run. A 202 response acknowledges the
durably queued wakeup, not a completed deployment. Check updater status and the
live revision to confirm deployment completion. Rerun the notification workflow
after a delivery failure; rerun source CI for a fresh delivery after resolving a
deployment failure. No periodic job retries it silently.

`staging-release` is forbidden on production/storage. It verifies current
Master identity, the dedicated domain, a healthy idle updater, exact `dev` HEAD
and the newest successful `docker.yml` push for that same SHA. Pending, failed,
wrong-branch/event/commit CI, API errors and rate limits fail closed. The native
updater's immutable archive builds, maintenance, journals, self-handoff and
failed-deployment restore are reused. The staging updater selects `dev`; the
production updater still selects only `main`. Public production upgrade and
rollback actions are disabled on a CD-managed site to avoid competing writers.

CD does not add heavyweight jobs to GitHub CI, touch storage appliances or
automatically reopen a failed upgrade. Inspect the local journal after a
failure; preserve prior images and data for recovery. A successful source push
is preproduction eligibility, not production publication or full acceptance.
Production still requires a reviewed `dev -> main` PR and separate rollout.
