# Ship changes through the shared queue

Repository: `euforicio/dotlocal`. Candidate acceptance is configured. Activation still requires the shared identity, environment and branch protections.

Read the [shared shipping guide](https://github.com/euforicio/orion-infra/blob/main/docs/agent-shipping.md).
Use an operator-controlled coordinator checkout at `RIFT_SHIPPING_HOME`.

1. Follow this repository's required validation and review instructions. Work on a separate branch; capture the reviewed main base SHA. Never push main from the editing agent.
2. Enqueue the ready remote branch with `python3 "$RIFT_SHIPPING_HOME/scripts/shipping/submit.py" enqueue --repository euforicio/dotlocal --branch BRANCH --base FULL_BASE_SHA --review-url HTTPS_REVIEW_URL`. Enqueuing does not start Actions.
3. Request `submit.py prepare --repository euforicio/dotlocal --limit 5` at a shipping boundary. Wait for the full acceptance workflows on its combined candidate and independently review that final diff.
4. Use `submit.py ship --repository euforicio/dotlocal --batch FULL_MANIFEST_SHA --review-url HTTPS_COMBINED_REVIEW_URL` to check. Add `--land` only when landing is intended and authorized.
5. Watch the existing main safety and deployment runs. Preserve their gates. Receipts are audit evidence; they never authorize skipping CI.

If preparation/landing is blocked, retain the existing PR/release path. Resolve conflicts explicitly, revalidate changed candidates, and reconcile uncertain writes before retrying. Do not expose shipping credentials to candidate code.
