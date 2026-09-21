# EvilGum 0.1.0rc1 — disposable demonstration

This developer-beta bundle contains the source archive, wheel, dependency locks and a synthetic allow/deny/recovery demo. No customer account or IdP is needed for the demo. Use synthetic data only. Real deployment instructions are in PHASE1-OPERATIONS.md.

Supported route: Linux amd64 with Python 3.11 and Docker Engine. Internet access is needed for locked dependencies and container bases. Initial downloads include spaCy/DLP and can take several minutes. Windows users may run the Linux instructions inside Ubuntu WSL with Docker available there; native Windows/macOS installation is not claimed.

From the extracted bundle directory:

```sh
sha256sum -c SHA256SUMS.txt
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r locks/runtime-py311-linux.lock
python -m pip install --no-deps evilgum-0.1.0rc1-py3-none-any.whl
python -m pip check
evilgum --version
evilgum init-config --directory example-config
# Build the exact wheel into the container:
tar -xzf evilgum-0.1.0rc1.tar.gz
cd evilgum-0.1.0rc1
mkdir -p dist
cp ../evilgum-0.1.0rc1-py3-none-any.whl dist/
docker build --platform linux/amd64 -t evilgum:0.1.0rc1 .
EVILGUM_TEST_IMAGE=evilgum:0.1.0rc1 python scripts/verify_phase1.py
```

Expected result: seven PASS groups, ending in a report whose result is passed. The demo performs an allowed math call, redacts a synthetic card value, blocks a tainted sink, then verifies Redis loss, restart, backup/restore and audit integrity. It cleans up only its own UUID-named containers/networks/volumes. It leaves .phase1-runtime synthetic keys/reports locally; never reuse those keys in real deployment.

The demo is an automated operational walkthrough, not an interactive chat application. For your own workflow, follow the supported protocol and configure a trusted issuer, TLS, grants and approved pins. Do not expose the demo server publicly.

If using the published container instead, verify its immutable digest against RELEASE-EVIDENCE.json and set EVILGUM_TEST_IMAGE to that digest before running the same script. No Docker login should be required for a public image; anonymous pull verification is reported separately.

Send non-sensitive setup feedback through https://github.com/Iffi-crux/evilgum/issues. Security reports: info@faseel.app. Do not attach keys, tokens, personal data or unredacted audit logs.
