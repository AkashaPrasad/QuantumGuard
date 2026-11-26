# Hosted deployment

The local quick start in the main README needs none of this. This directory puts the same image on the internet:
the API on AWS, the web console on Cloudflare, one public hostname.

```
browser ── TLS ──> Cloudflare Worker (static console + forwarder)        your hostname
                      │  /api/*, /healthz only, with the edge key
                      └─ TLS ──> API Gateway ── private VPC link ──> proxy :8080 ──> QuantumGuard container
                                                                      (one instance, no inbound port open to the internet)
```

The browser talks to one origin, so the console's Content-Security-Policy (`connect-src 'self'`) is the same as in
the container. Static responses get the same security headers the API sets: `deploy.sh` reads the policy out of
`backend/qg/app.py` and writes it into the asset store's `_headers` file.

## What it creates

| Where | What | Why |
|---|---|---|
| AWS | ECR repository | Holds the image; tags are immutable and scanned on push |
| AWS | One `t4g.small` instance, encrypted 16 GB disk | Runs the API container and a Caddy proxy with the compose file's hardening flags |
| AWS | Instance role | Pull its own image, read its own edge key, be managed through Systems Manager. No SSH key, no SSH port |
| AWS | Two security groups | Instance inbound: port 8080 from the gateway's private link only. Outbound: 443 only |
| AWS | SSM parameter (SecureString) | The edge key |
| AWS | API Gateway HTTP API, VPC link, service registry entry | The API's only public address; the gateway reaches the instance over the private link |
| Cloudflare | One Worker with static assets and a custom domain | Serves the console and forwards API calls |

Cost while it runs is roughly 13 USD a month (instance, public IPv4 address, disk). `deploy.sh destroy` removes
everything.

## The edge key

Terraform generates a 48-character random key. The instance reads it from the parameter store at start; the Worker
holds it as a secret. The proxy answers 403 to any request without it, so the API cannot be reached by going to the
gateway address directly, and only the Worker can state the client's address (used for rate limits and
source-scoped responses). The key is never in the repository. It is in the local Terraform state file, which
`.gitignore` excludes; keep that file private.

## Deploy

```bash
QG_DOMAIN=console.example.org AWS_REGION=eu-west-1 AWS_PROFILE=name deploy/deploy.sh all
```

Needs Docker, Terraform, the AWS CLI signed in, and `wrangler login` for the Cloudflare account that owns the
domain. The stages can be run one at a time: `image`, `aws`, `web`. The AWS stage takes about five minutes.

After the first deploy, seed the demonstration data and issue enrolment codes on the instance (Systems Manager
Session Manager or Run Command, as root):

```bash
docker exec quantumguard python -m qg.admin recovery-kit init --out /tmp/qg-demo/recovery-kit.json
docker exec -e QG_PASSPHRASE="$(od -An -tx1 -N16 /dev/urandom | tr -d ' \n')" quantumguard \
  python -m qg.client demo seed --server http://127.0.0.1:8080 --dir /tmp/qg-demo
docker exec -e QG_URL=http://127.0.0.1:8080 quantumguard python -m qg.scenarios revoke
docker exec quantumguard python -m qg.admin invite --all
```

To ship a new image: `deploy.sh image`, then on the instance `qg-up <repository>:<tag>`. Data and keys are in
Docker volumes and survive the restart.

## Limits of this setup

- **One instance, no backups.** The database and the server's keys live on one encrypted disk. Losing the instance
  loses the evidence log. A real deployment needs snapshots at least.
- **Plain HTTP for the last hop.** The gateway reaches the proxy over the VPC's private network without TLS. Requests
  are still authenticated end to end (session MAC) and file contents are encrypted before they leave the browser,
  but headers and metadata are readable to anyone who can observe that private network.
- **The gateway's limits apply**: 10 MB per request and 30 seconds per call. File chunks are 1 MiB, so uploads fit.
- **Two providers see request metadata.** Cloudflare and API Gateway both terminate TLS. Neither sees file keys or
  plaintext.
- **Zone-level Cloudflare features can rewrite pages.** Automatic analytics tried to add a third-party script; the
  console's policy blocked it. Static files are now sent with `Cache-Control: no-transform` so the edge leaves them alone.
- **The demo recovery kit** is written to the container's temporary file system and is gone after a restart.
- Whoever runs Terraform needs broad AWS rights (it creates a role). The instance itself gets only the three
  permissions listed above.
