# Native release image contract

A release contains public immutable Web and Nginx images from one reviewed main
revision. Each image proof binds its manifest/config digest, source revision,
Linux architecture and database generation. Web advertises release-manifest
contract version 1; Nginx carries the corresponding source and generation labels.

The Web image also contains the host-side `fc` binary and certificate controller.
There is no fleet release manifest, update daemon or peer release control API.
Existing deployments use explicit [operator upgrades](../../docs/operator-upgrade.md),
with a verified backup, retained identity, preparation behind maintenance and
separate opening. Fresh installation alone may resolve the verified `latest` alias.
