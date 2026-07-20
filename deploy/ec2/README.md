# EC2 launch deployment

This is the lean production topology for the Vast-backed launch path. It runs
PostgreSQL, the control plane, lifecycle and settlement workers, and a public
TLS edge on one ARM EC2 host. The web application remains on Render.

The physical-node access gateway, Valkey, proof worker, and Prometheus are
intentionally excluded. Add them only when their corresponding capacity or
operational requirement exists.

Required local files are untracked:

- `.env`
- `secrets/vast-api-key`
- `secrets/tls/ca.crt`
- `secrets/tls/ca.key`

Validate before deployment:

```sh
docker compose --env-file deploy/ec2/.env \
  -f deploy/ec2/compose.yml config --quiet
```
