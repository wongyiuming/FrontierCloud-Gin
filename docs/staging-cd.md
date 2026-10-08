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

Install the supplied `staging-cd.sh` as `/opt/frontiercloud-staging/staging-cd.sh`
and the service/timer into `/etc/systemd/system`. Enable the timer only after
the first deployment and private/public HTTPS smoke tests pass. No GitHub SSH
credential or new Actions secret is needed: the local controller checks the
public repository over HTTPS every five minutes and submits to its local socket.

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
