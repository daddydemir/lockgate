# SDK release checklist

The Go module and both SDK packages use the same version. Pushing a `v*` tag
runs `.github/workflows/publish.yml`.

1. Run `make sdk-test`.
2. Update the matching version in `sdk/javascript/package.json` and `sdk/python/setup.cfg`.
3. Ensure `web/static/examples/lockgate.mjs` matches `sdk/javascript/index.js` and `web/static/examples/lockgate.py` matches `sdk/python/src/lockgate_client/__init__.py`.
4. Commit the version change, create the matching tag (for example `v0.1.0`), and push the commit and tag.
5. GitHub Actions tests all three clients, publishes npm with the `NPM_TOKEN` repository secret, and publishes PyPI through the `release` environment's Trusted Publisher.
6. After the first npm release, configure npm Trusted Publishing for `publish.yml`, remove `NPM_TOKEN`, and update the npm job to use OIDC.
7. Verify the registry pages and clean installations before updating in-app documentation to published install commands.

Never put registry tokens in this repository, shell history, Docker images, or documentation.
