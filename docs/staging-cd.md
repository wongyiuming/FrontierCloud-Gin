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

CD is event-driven: `publish-images.yml` first verifies the newest successful
**dev push** `docker.yml` run for its exact SHA, then publishes all three public
runtime images. Complete publication emits the event consumed by the separate
default-`main` `staging-cd.yml` **workflow_run** notifier (three-minute hard limit,
150-second proof/delivery command). Original test CI remains capped at three minutes; separate
parallel compilation jobs are capped at ten minutes and run no acceptance tests.
Failed/cancelled CI or publication, main pushes, PRs and foreign repositories
cannot notify staging. The notifier checks out only the immutable
`github.workflow_sha` of its trusted main definition, sparsely including its two
proof scripts, with no persisted checkout credentials. It never checks out dev,
downloads candidate artifacts/caches, imports candidate code, pulls/executes
containers, or compiles/deploys anything. The candidate SHA is data only.
See [public image delivery](public-image-delivery.md).

The trusted script re-fetches the publisher's workflow/run/attempt identity and
all three successful component jobs, verifies the newest successful exact-SHA
source CI, and checks current dev HEAD. It then anonymously verifies each public
Web/Updater/Nginx manifest, configuration, digest and provenance through the
same image resolver used by deployment. After network proofs it rechecks HEAD
and both run identities. Pending/newer runs, private/missing packages, invalid
digests, rate limits and network errors fail closed: **no notification and no
local-build fallback**. The signed payload retains the original test CI run
identity, not the publisher's run identity.

## Secret boundary and first activation

Before enabling the new notifier, an authorized repository administrator must
create **`staging-cd-main`** under Settings -> Environments. Set Deployment
branches and tags to **Selected branches and tags**, with exactly one rule:
type **Branch**, name **`main`**. Do not add dev, wildcard, tag or unrestricted
rules. Store `STAGING_CD_SECRET` only as this Environment's secret. Remove any
repository secret with that name and ensure no organization secret with that
name is available to this repository. Merely referencing an Environment or
moving the script to main does not remove an existing repository-secret copy.
A dev author could otherwise add another workflow to read that copy.

These are external GitHub settings: source code/tests cannot create or certify
the branch restriction or secret relocation. Do not treat this source change
as activated until an administrator verifies them. Do not place the secret in
logs, job outputs, artifacts, `.env` committed to Git or publisher steps. GitHub
checks the Environment deployment rule against the notifier's default-main
`GITHUB_REF`, not the candidate's dev SHA. See GitHub's
[environment deployment rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

First activation has an intentional bootstrap boundary: `workflow_run` uses
the workflow file on the default branch, and a new dev-only definition cannot
run before it has been promoted. The historical main workflow listens only to
source CI and is unsafe with image-first CD; keep it **disabled** until the new
definition is merged. Never re-enable it to get the first staging deployment.

1. Run bounded development acceptance, push dev, pass its three-minute source
   CI, and successfully publish/prove all three exact-SHA public images.
2. With **explicit separate operator authorization**, perform the first staging
   bootstrap from a trusted operator path. Independently query real GitHub run
   identities/current dev HEAD and anonymous image proofs; preserve receiver
   HMAC, certificate, replay and updater gates. Do not spoof `GITHUB_REF`,
   `GITHUB_WORKFLOW_SHA`, events or a main environment to run a candidate script
   holding the signing secret. This document does not implement or authorize
   that one-time operator action by itself.
3. Verify actual staging deployment/acceptance. Open and merge the normal
   **dev -> main PR**; do not direct-write or prematurely merge main to escape
   the bootstrap boundary.
4. Verify the main-only Environment/secret settings, replace the old disabled
   main definition via that PR, and only then enable the trusted workflow.
   Rerun the newest exact-SHA publisher (or a later accepted dev publication)
   to emit its completion event. The main merge's publication never triggers
   staging CD. Subsequent accepted dev publications are fully event-driven.

See GitHub's [workflow_run semantics and untrusted-code warning](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run).
No five-minute polling, direct main write or repository-wide secret is a
bootstrap workaround.

Install `staging-cd.sh` as `/opt/frontiercloud-staging/staging-cd.sh` and
`staging_updater_state.py` beside it (an operator script, not a Python backend).
Install
`frontiercloud-staging-cd.service`, `frontiercloud-staging-cd.path` and
`frontiercloud-staging-trigger.service` into `/etc/systemd/system`.
Build `./cmd/staging-trigger` on the development host and install its binary at
`/usr/local/libexec/frontiercloud-staging-trigger`. Create a locked system user
`frontiercloud-staging-trigger`, with no shell, Docker group or sudo access.
Its systemd service has a 64 MiB memory limit and 10% CPU quota.

Generate a random signing secret of at least 32 bytes. Store the same value only
in the main-restricted `staging-cd-main` Environment's `STAGING_CD_SECRET` and in
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
55 minutes, covering its 45-minute build and eight-minute recovery deadlines).
The dedicated, label-verified control-volume journal remains available through
web/updater self-handoff; waiting does not depend on a container that is being
replaced. This is not GitHub polling. Failed deployments require operator
attention, rather than repeatedly restarting the same failed update.

Inspect `journalctl -u frontiercloud-staging-trigger -u frontiercloud-staging-cd`
and GitHub's separate `Trigger preproduction CD` workflow. A 202 response acknowledges the
durably queued wakeup, not a completed deployment. Check updater status and the
live revision to confirm deployment completion. Rerun the notification workflow
after a delivery failure; rerun source CI for a fresh delivery after resolving a
deployment failure; after a successful source rerun, rerun the publisher to
produce the image-ready event. No periodic job retries it silently.

`staging-release` is forbidden on production/storage. It verifies current
Master identity, the dedicated domain, a healthy idle updater, exact `dev` HEAD
and the newest successful `docker.yml` push for that same SHA. Pending, failed,
wrong-branch/event/commit CI, API errors and rate limits fail closed. The native
updater's verified public-image pulls (confirmed-absence immutable archive fallback), maintenance, journals, self-handoff and
failed-deployment restore are reused. The staging updater selects `dev`; the
production updater still selects only `main`. Public production upgrade and
rollback actions are disabled on a CD-managed site to avoid competing writers.

CD does not add heavyweight acceptance to GitHub CI, touch storage appliances or
automatically reopen a failed upgrade. Inspect the local journal after a
failure; preserve prior images and data for recovery. A successful source push
is preproduction eligibility, not production publication or full acceptance.
Production still requires a reviewed `dev -> main` PR and separate rollout.
