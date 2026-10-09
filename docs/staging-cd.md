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

CD is event-driven: a completed successful source `docker.yml` run starts the
default-main `publish-images.yml` through **workflow_run**. Its trusted plan
first proves the newest exact source push and current branch HEAD. Separate
component jobs without package-write credentials compile Go on GitHub, export OCI data and hand it
to isolated immutable-main publication jobs. Only after every public image is
verified does the independent `notify-staging` job in that same run sign a wakeup
(three-minute hard limit, 150-second proof/delivery command). Test CI still has
its three-minute limit; component compilation has its own ten-minute deadline
and runs no acceptance tests. Completed-source triggering avoids guessing how
long the independent test runner will spend queued.
Failed/cancelled CI or publication, main source pushes, PRs and foreign
repositories cannot notify staging. The notifier checks out only the immutable
`github.workflow_sha`, with sparse proof-script paths and no persisted checkout
credentials. It never checks out dev, downloads candidate artifacts/caches,
imports candidate code or pulls/runs containers. The source SHA is data only.
See [public image delivery](public-image-delivery.md).

The trusted script re-fetches this active publication run/attempt identity and
all three successful publisher jobs, independently revalidates the trusted
plan's newest successful exact-SHA source CI, and checks current dev HEAD.
It then anonymously verifies each public
Web/Updater/Nginx manifest, configuration, digest and provenance through the
same image resolver used by deployment. After network proofs it rechecks HEAD
and both run identities. Pending/newer source runs, private/missing packages, invalid
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

Image publication uses the automatic **`GITHUB_TOKEN`**, not a personal PAT.
Only the isolated immutable-main **publish** job has `packages: write`;
plan, compile and notify-staging do not. No publisher Environment is required.
For each public `frontiercloud-gin-web`, `frontiercloud-gin-updater` and
`frontiercloud-gin-nginx` package, grant **`FrontierCloud-Gin` Write** under
**Manage Actions access**. Keep public visibility and existing versions.
Public readers pull anonymously without credentials.

The accepted trust model includes repository workflow writers: they can add a
different workflow that explicitly requests package writes. Default token read
permissions and our job isolation do not prevent that capability or make SHA
tags intrinsically immutable. This choice does **not** grant those workflows
the CD signing secret; its main-only Environment remains mandatory. An old
publisher PAT secret/Environment may remain unreferenced, does not trigger a
deployment and is not consumed by the new publisher.
See GitHub's [package permission controls](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility)
and [container registry authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).

These are external GitHub settings: source code/tests cannot create or certify
the branch restriction or secret relocation. Do not treat this source change
as activated until an administrator verifies them. Do not place the secret in
logs, job outputs, artifacts, `.env` committed to Git or publisher steps. GitHub
checks the Environment deployment rule against the notifier's default-main
`GITHUB_REF`, not the candidate's dev SHA. See GitHub's
[environment deployment rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

First activation has an intentional bootstrap boundary: `workflow_run` uses
the publication file on the default branch, and a new dev-only definition cannot
run before it has been promoted. Both privileged jobs must remain main-only;
do not add a dev credentialed dispatch/push workaround as this release's bootstrap.
The historical main
`staging-cd.yml` signs immediately after source CI without image readiness;
keep that old workflow **disabled**, and remove its definition through normal
promotion. Never re-enable it to obtain the first staging deployment. The first
publication bootstrap is **not yet implemented or resolved**: using automatic
package tokens does not make a dev-only workflow file execute on default main.
The sequence below defines the required gates, not evidence of an active path.

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
4. Verify the main-only signing Environment, signing-secret relocation and each
   package's `FrontierCloud-Gin` Actions Write grant; install
   the trusted publication definition through that PR, leaving the removed old
   notifier disabled. A successful exact source CI rerun (or later accepted dev
   push) emits the publication event. Main-source publication does not notify
   staging; accepted dev publication completes its own signed-notification job.
   No polling timer, candidate credentialed workflow or premature main write is
   an acceptable activation shortcut.

See GitHub's [workflow_run semantics and untrusted-code warning](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#workflow_run).
No five-minute polling, direct main write or repository-wide CD signing secret is a
bootstrap workaround.

Install `scripts/ops/staging-cd.sh` as `/opt/frontiercloud-staging/staging-cd.sh` and
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
and GitHub's `Publish native images` / `notify-staging` job. A 202 response acknowledges the
durably queued wakeup, not a completed deployment. Check updater status and the
live revision to confirm deployment completion. After resolving a delivery or
deployment failure, rerun source CI to emit a fresh completed event and rebuild
the trusted plan. A single downstream-job rerun cannot reuse a plan from a
different publication attempt. Existing accepted image digests are reused, not
rebuilt or overwritten. No periodic job retries a failed deployment silently.

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
