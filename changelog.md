# Changelog

## [0.1.0]

_21 Oct 2026_

### Added
- `.github/workflows/`: self-contained `semgrep.yml` (rules in `.semgrep/`), `pipeline.yml` (Docker image for amd64 + arm64 pushed to `ghcr.io/eu-digital-identity-wallet/eudi-srv-statuslist-py` on `main`, `branch-*` and `v*` tags; secret `GHCR_KEY`), `README.md` (workflows, secrets, one-time SonarCloud setup) and `.github/CODEOWNERS`, as in the issuer backend.
- `app/log_utils.py`: `safe()` escapes CR / LF and control characters and bounds request values written to the log.
- YAML configuration (`app/config.py`), read from `STATUS_LIST_CONFIG_PATH` (default `/etc/statuslist_config/config_statuslist.yaml`), with a `variables` section for `${name}` substitution, as in the issuer backend. Every key is described in `app/config_statuslist_example.yaml`; all but `api_key` and `countries` have defaults (the values that were hard-coded).
- `Dockerfile` (Python 3.13, non-root UID 10001, only `app/` copied), `.dockerignore` (no keys, configuration or tests) and `docker-compose.yml` (host port 5002, configuration and keys mounted read-only, list, backup and log directories mounted from the host), as in the issuer backend. See "Run with Docker" in `install.md`.
- Unit tests (`tests/`, 99% coverage of `app/`), `requirements-dev.txt`, `pytest.ini`, `pyproject.toml` (coverage, `fail_under = 80`) and `.env.test`; `sonar.yml` runs them with coverage, as in the issuer backend. Published lists are decoded strictly (`tests/strict.py`: no bytes after the CBOR item, JWT signature verified), and `tests/test_concurrency.py` runs concurrent takes, revocations, renewals and list rollovers, and two `flask run` processes on the same directories.
- `flask renew-lists`: renews (re-signs) every list at once and reports the lists it could not renew; exits with 1 if any. Run it after upgrading to repair lists damaged by earlier versions.
- `status_list_dir/state/<CC>/<doctype>/current.json`: the list new indices are taken from, so restarts and other processes keep using it; `.lock` files there serialize the changes. See "Serving the lists" in `install.md` (with a sample nginx configuration) for what may be published.
- `allowed_doctypes`: `wrprc` and `oauth-client-attestation+jwt` are allowed by default, next to `key-attestation+jwt`.
- `debug` (default `false`): Flask debug mode. Before, it was always on.
- `renewal.hours` (default `[0, 12]`): when the lists are re-signed; `status_list_ttl` (default 3600): the CWT time to live. Both were hard-coded.
- `logging.path`, `logging.log_level` (default `INFO`) and `logging.backup_count` (default 7). Every log record has CR / LF escaped and traceback lines indented; the Flask and Werkzeug logs go to the same file.

### Changed
- `gitleaks.yml`, `dependencycheck.yml` and `sonar.yml` no longer call the `eu-digital-identity-wallet/eudi-infra-ci` reusable workflows (which needed `DOJO_TOKEN`, `DOJO_URL` and `NVD_API_KEY`); they run the scans themselves, as in the issuer backend. `sonar.yml` needs `SONAR_TOKEN`; the others need no secrets.
- The gitleaks configuration moved from `security/gitleaks/gitleaks.toml` to `gitleaks/gitleaks.toml`.
- `app/config_service.py` (`ConfService`) is gone: the service URL, directories, list size, countries and allowed doctypes come from the YAML configuration. The `API_key` environment variable / `.env` file is replaced by `api_key`, and `python-dotenv` is no longer used.
- `countries.<CC>`: `private_key_path`, optional `private_key_password` and `certificate_path` (DER or PEM). Keys and certificates are loaded once at start-up, and a missing or unreadable one stops the service; before, they were read from disk for every list signed. In the example configuration `FC`, `EU` and `LU` lists are signed with the LU document signer.
- Dependencies upgraded to current releases: Flask 3.1.3, Werkzeug 3.1.9, flask-cors 6.0.5, flask-swagger-ui 5.34.0, PyJWT 2.15.1, cbor2 6.1.5, cryptography 50.0.2 (now pinned; it came in through `cwt`), PyYAML 6.0.3. The unused `requests`, `flask_api` and `cwt` are removed. `pip-audit` reports no known vulnerabilities; before, it reported advisories for cryptography, PyJWT, Werkzeug, cbor2, flask-cors, requests and Flask.
- The `token-status-list` package (an unmaintained 0.1.0 alpha written for draft-02) is replaced by `app/status_list.py`, which keeps only the parts the service uses: the status bits and the random index allocator. `full_list.json` keeps its format, so existing lists load unchanged. The JWT and CWT take `bits` from the list instead of always writing 1.
- `README.md` references [draft-ietf-oauth-status-list-12](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-12) instead of draft-02.
- Debug `print()` calls (which printed every certificate and status list response) are log records now.
- The lists are kept on disk only: every `/take`, `/set` and renewal reads the list, changes it and writes it back under a lock per country and doctype (`fcntl.flock` plus a thread lock), and every file is replaced atomically (temporary file + `os.replace`). Before, each process held its own in-memory copy of the current lists and rewrote the files in place, so several processes (or a restart) worked on diverging copies. Several containers or `flask run` processes may now serve the same `status_list_dir`; only one of them renews at a time (`state/renewal.lock`). A `/take` on an existing list only updates its `full_list.json`: the statuses do not change, so the published JWT / CWT are no longer re-signed on every `/take` (they are on `/set` and at every renewal).
- `/token_status_list/get` and `/set` errors are JSON (`{"error": ...}`) everywhere, including 404 and 500; an unknown list is 404.
- `token_status_list_size` is documented as a number of entries (it always was; the comment said bytes).

### Security
- `/token_status_list/take` logged the full request headers, `X-Api-Key` included. It now logs only the form payload, through `safe()`.
- The service refuses to start when `api_key` is missing, shorter than 32 characters or a known placeholder (`test`, `secret`, ...). `X-Api-Key` is compared in constant time.
- `/get` and `/set` joined the `uri` path to `status_list_dir` unchecked (`../` read other `full_list.json` files) and accepted any host. The `uri` must now be `<service_url>token_status_list|identifier_list/<CC>/<doctype>/<id>` with a configured country, an allowed doctype and a list id; otherwise 400.
- `/set` with `idx=-1` revoked the last entry of the list (another credential). Indices outside the list are rejected with 400 (before, 500 for those past the end).

### Fixed
- Concurrent `/set` requests (and `/set` during a `/take`) corrupted the published lists and lost revocations (upstream eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py#191): a shorter rewrite left the tail of the previous file behind, so the CWT had bytes after the COSE_Sign1 and the JWT an over-long signature, and a `/set` could read a half-written `full_list.json` (500, revocation lost). Writes are now atomic and serialized.
- After a `/set`, every later `/take` for that list but the first failed with a 500 (`identifier_list_cwt_format()` turned the in-memory identifiers into bytes) until a restart, and the issuer issued those credentials without a status; the failing write also left an empty `identifier_list.cwt`.
- When a list ran out of indices, every other in-memory list (all countries and doctypes) was dropped, and concurrent `/take` calls got 500s or an index of one list with the URI of another (two credentials on one entry). Only the full list is replaced now, and the index and URIs always belong to the same list.
- New lists shared one module-level identifier dict, and a new country entry replaced that country's other doctypes.
- A list that had handed out a single index was never renewed: its first `full_list.json` had no list URIs. The URIs are written with the list, and older lists get them back when loaded.
- Renewal copied `identifier_list.jwt`, which is never written, and stopped at the first identifier list, so the lists after it were not re-signed; one failing list no longer stops the others either.
- A second process (or a restart) rewrote a list from its own stale copy on the next `/take`, undoing the revocations made elsewhere; a restart also abandoned the free entries of the current lists.
- `/get` on an identifier list URI always answered 0, even for a revoked entry.
- `urn:eu.europa.ec.eudi:learning:credential:1` (learning credential SD-JWT) and `org.iso.7367.2.1.mVC` (mVC mdoc) were not allowed doctypes, so the issuer issued them without a status list entry.
- `install.md` cloned the issuer backend repository instead of this one.
- `urn:eu.europa.ec.eudi:tax:1` and `urn:eu.europa.ec.eudi:tax:1:1` were not allowed: a missing comma joined them into one doctype.
- `gitleaks/gitleaks.toml`: the `Env Var` rule had no `id`, so current gitleaks refused to load the config. The rule is now `env-var`.
- The index allocator trusted the stored `num_allocated`; a wrong value made `/take` loop forever on a full list, or start a new list while the current one still had free indices. It is now counted from the allocation map.
- A `full_list.json` whose list was not valid ZLIB raised an unhandled `zlib.error` instead of being reported as an unreadable list (`/get` and `/set` answer 500 `List unavailable`, renewal reports it as corrupt).
