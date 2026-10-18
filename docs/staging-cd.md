# RN staging and retired CD

The external CD receiver, signed notification and online update controller are
retired. Publishing images does not deploy staging or production.

The owner retired RN preproduction on 2026-10-11, then on 2026-10-15 authorized
an isolated, manually started RN staging project alongside production Relay.
This does not reinstate the old deployment, receiver, credentials or identities.

## Current operating boundary

- Use independent Compose scope, data, identities, secrets, volumes and networks.
  Never mount or join the production cluster.
- Staging may temporarily use 80/443; production Relay communicates on 8443 but
  needs host port 80 for bounded HTTP-01 certificate issuance/renewal. Check port
  ownership and coordinate before starting; Relay's idle ports are not a lease.
- Stop staging services after acceptance and retain Compose/data for later use.
  Normally stopped staging is not an always-available release gate.
- Report actual source, inputs, results and skipped scopes. Permission to start,
  retained files and private development tests do not prove RN acceptance ran.

Development-host acceptance, exact-source CI, automatic review and authorized
dev-to-main promotion remain separate gates. Feature-specific staging acceptance
applies when required by the owner; report it unavailable or unexecuted honestly.
Production uses the [operator upgrade workflow](operator-upgrade.md) only with
separate authorization. Historical evidence retains its recorded dates/scope.
