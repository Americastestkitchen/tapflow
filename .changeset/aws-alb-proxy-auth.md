---
"@tapflowio/relay": minor
"tapflow": minor
---

Relay: sign in through an AWS Application Load Balancer. With `proxyAuth` set in `tapflow.config.json`, a request signed by the configured ALB (`x-amzn-oidc-data`) starts a tapflow session for that email, creating the member on first sign-in, so a team behind SSO doesn't keep a second password. Off unless configured.
