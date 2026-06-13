# rsfuzzer

**Strategy-driven fuzzing for API authorization and business-logic bugs.**

rsfuzzer helps you test whether an API enforces access control consistently across roles, parameters, headers, and JSON payloads. It combines **endpoint discovery** (OpenAPI and traffic), **YAML test profiles**, and a **composable mutation engine** to generate variants—not static payload lists.

> **Status:** Early development (v0.1). APIs and report formats may change. Intended for authorized testing and local/lab environments only.

---

## Features

- **Multi-role authorization testing** — Define roles with headers/tokens and assert expected HTTP status codes per role.
- **Endpoint discovery** — Build a normalized catalog from OpenAPI specs and/or captured traffic (mitmproxy-friendly).
- **Differential testing** — Cartesian products of query, header, and body mutations from your profile YAML.
- **Mutation engine** — Pluggable strategies (prototype pollution, IDOR boundaries, injection, type confusion, header spoofing, and more).
- **Catalog fuzzing** — Drive the mutation engine against discovered endpoints with `--max` and `--mutate-parts`.
- **Structured JSON reports** — Checks, differential results, scan rows, and per-request mutation traces.

---

## Requirements

- Python **3.12+**
- [uv](https://docs.astral.sh/uv/) (recommended) or `pip`

---

## Installation

From a clone of this repository:

```bash
cd rsfuzzer
uv sync          # optional: create .venv and install deps
uv pip install -e .
```

Or run without a global install:

```bash
uv run rsfuzzer --help
```

---

## Quick start

### 1. Start a target API

The repo includes a deliberately vulnerable sample API for learning and regression tests:

```bash
cd ../api_examples
npm install && npm start
# → http://127.0.0.1:3000
```

### 2. Discover endpoints

```bash
cd rsfuzzer

uv run rsfuzzer discover \
  --openapi ../api_examples/openapi.json \
  --traffic ../api_examples/artifacts/flows.ndjson \
  --out artifacts/endpoints.json
```

### 3. Run authorization tests

```bash
uv run rsfuzzer test \
  --profile-file profiles/api_examples.yaml \
  --catalog artifacts/endpoints.json \
  --roles user_alice,user_bob \
  --out artifacts/test_report.json
```

Exit code **0** = all checks passed; **1** = at least one failure (often an authorization bypass worth investigating).

---

## How it works

```text
 OpenAPI / traffic          YAML profile              Mutation strategies
        │                         │                           │
        ▼                         ▼                           ▼
   ┌──────────┐            ┌─────────────┐            ┌─────────────────┐
   │ discover │──catalog──▶│    test     │◀──engine──│ permute_case    │
   └──────────┘            └─────────────┘            └─────────────────┘
                                  │
                                  ▼
                          JSON test report
```

Three layers of coverage:

| Layer | Config | What it fuzzes |
|-------|--------|----------------|
| **Checks** | `checks:` in profile | Fixed requests; expected status per role |
| **Differential** | `differential:` in profile | Manual mutation lists (query × header × body) |
| **Catalog scan** | CLI `--max`, `--mutate-parts` | Auto-generated variants per catalog endpoint × role |

---

## Profiles

Profiles are YAML files that describe the target, roles, fixtures, and expectations.

```yaml
base_url: http://127.0.0.1:3000

roles:
  user_alice:
    headers:
      x-user-id: u1
      x-role: user
  user_bob:
    headers:
      x-user-id: u2
      x-role: user

fixtures:
  path_params:
    id: "101"
  query_params:
    expand: items
  bodies:
    "/api/orders":
      total: 100
    "/api/orders/{id}/status":
      status: shipped

checks:
  - id: bob_cannot_read_alice_order
    method: GET
    path: /api/orders/{id}
    path_params:
      id: "101"
    expect:
      user_alice: 200
      user_bob: 403

differential:
  - id: get_order_mutation_surface
    method: GET
    path: /api/orders/{id}
    path_params:
      id: "101"
    query_mutations:
      - {}
      - { debug: "1" }
    header_mutations:
      - {}
      - { X-Trusted-Subject: u1 }
    expect:
      user_alice: 200
      user_bob: 403
```

See [`profiles/api_examples.yaml`](profiles/api_examples.yaml) for a complete example.

---

## CLI reference

### `rsfuzzer discover`

Build an endpoint catalog.

| Option | Description |
|--------|-------------|
| `--openapi PATH` | OpenAPI 3.x spec |
| `--traffic PATH` | Traffic capture (JSON or NDJSON) |
| `--out PATH` | Output catalog (default: `artifacts/endpoints.json`) |

At least one of `--openapi` or `--traffic` is required.

### `rsfuzzer test`

Run profile checks, differential cases, and optional catalog fuzzing.

| Option | Description |
|--------|-------------|
| `--profile-file PATH` | **Required.** YAML profile |
| `--catalog PATH` | Endpoint catalog from `discover` |
| `--roles A,B` | **Required.** Two role names for catalog scan |
| `--out PATH` | JSON report path |
| `--no-scan` | Skip catalog scan |
| `--scope PATTERN` | `fnmatch` filter on paths (default: `*`) |
| `--max N` | Mutation variants per endpoint × role (`0` = disabled) |
| `--mutate-parts LIST` | Comma-separated: `query`, `headers`, `body` |
| `--mutate-light` | Smaller strategy set (faster) |

**Catalog scan behavior:**

- **GET / HEAD** — Always scanned; supports `query` and `headers` mutation axes.
- **POST / PATCH / PUT** — Included when `body` is in `--mutate-parts`; JSON seeds from `fixtures.bodies`.
- `--max` is a **ceiling**; the engine may emit fewer variants depending on registered strategies.

### `rsfuzzer mutate`

Dry-run: print generated request variants as JSON lines (no HTTP).

```bash
uv run rsfuzzer mutate --method POST --path /api/orders --max 25 --parts body,query,headers
```

---

## Mutation strategies

Strategies live under [`src/rsfuzzer/mutations/strategies/`](src/rsfuzzer/mutations/strategies/) and are registered in [`registry.py`](src/rsfuzzer/mutations/registry.py).

| Strategy | Category |
|----------|----------|
| `PrototypePollutionStrategy` | `__proto__` / constructor key injection |
| `IdBoundaryStrategy` | Horizontal IDOR / neighbor IDs |
| `PrivilegeEscalationStrategy` | Role / admin attribute injection |
| `TypeConfusionStrategy` | Type coercion on JSON fields |
| `InjectionStrategy` | SQL / NoSQL / command / path patterns |
| `HeaderSpoofingStrategy` | Trust-boundary header tampering |
| `AuthSessionStrategy` | JWT / cookie manipulation |
| `ParameterPollutionStrategy` | Duplicate / conflicting parameters |
| `PathTraversalStrategy` | Traversal encodings in string fields |
| `DeserializationStrategy` | XXE-shaped XML and type metadata |
| `RateLimitBypassStrategy` | Forwarded-IP / bypass headers |
| `DeepJsonStrategy` | Deep nesting and self-reference shapes |
| `ResourceExhaustionStrategy` | Large arrays and strings |
| `UnicodeEncodingStrategy` | Encoding and homoglyph transforms |
| `HttpProtocolStrategy` | Protocol-level header edge cases |
| `BoundaryStrategy` | Numeric and string boundary values |
| `MultipartAbuseStrategy` | Multipart-related abuse patterns |

Add new strategies by implementing `mutate_body`, `mutate_query`, and `mutate_headers`, then register them in `default_strategies()`.

---

## Reports

Test output is written as JSON:

```json
{
  "checks": [ ... ],
  "differential": [ ... ],
  "check_failures": [ ... ],
  "scan": [
    {
      "method": "GET",
      "url": "http://127.0.0.1:3000/api/orders?debug=1",
      "role": "user_bob",
      "status_code": 200,
      "from_mutations": true,
      "mutation_traces": [ { "strategy_id": "...", "category": "...", "detail": {} } ]
    }
  ]
}
```

- **`check_failures`** — Requests where actual status ≠ expected (primary findings).
- **`scan`** — Catalog baseline and mutation-engine requests.
- **`mutation_traces`** — Audit trail for auto-generated variants.

Console summary example:

```text
[test] Checks: 6 total.
[test] Differential: 16 requests, 6 failed.
[test] Scan rows: 2100 (2090 mutation-engine).
```

---

## Example workflows

<details>
<summary><strong>Smoke test</strong> (profile only, no catalog scan)</summary>

```bash
uv run rsfuzzer test \
  --profile-file profiles/api_examples.yaml \
  --catalog artifacts/endpoints.json \
  --roles user_alice,user_bob \
  --no-scan \
  --out artifacts/test_report_smoke.json
```

</details>

<details>
<summary><strong>Catalog fuzz</strong> (query + headers on GET endpoints)</summary>

```bash
uv run rsfuzzer test \
  --profile-file profiles/api_examples.yaml \
  --catalog artifacts/endpoints.json \
  --roles user_alice,user_bob \
  --max 500 \
  --mutate-parts query,headers \
  --out artifacts/test_report_scan.json
```

</details>

<details>
<summary><strong>JSON body fuzz</strong> (POST / PATCH / PUT)</summary>

```bash
uv run rsfuzzer test \
  --profile-file profiles/api_examples.yaml \
  --catalog artifacts/endpoints.json \
  --roles user_alice,user_bob \
  --max 500 \
  --mutate-parts body \
  --out artifacts/test_report_body.json
```

</details>

<details>
<summary><strong>Full local run</strong> (checks + differential + all mutation axes)</summary>

```bash
uv run rsfuzzer test \
  --profile-file profiles/api_examples.yaml \
  --catalog artifacts/endpoints.json \
  --roles user_alice,user_bob \
  --max 500 \
  --mutate-parts body,query,headers \
  --out artifacts/test_report_full.json
```

Add `--mutate-light` for a faster, smaller strategy set.

</details>

> **Tip:** For copy-paste commands on Windows PowerShell, see [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

---

## Development

```bash
cd rsfuzzer
uv run pytest tests/ -q
uv pip install -e .
```

### Project layout

```text
rsfuzzer/
├── src/rsfuzzer/           # Package source
│   ├── cli.py              # CLI entrypoint
│   ├── discovery.py        # OpenAPI + traffic → catalog
│   ├── profiles.py         # YAML profile loader
│   ├── testing.py          # HTTP runner + catalog scan
│   └── mutations/          # Engine + strategies
├── profiles/               # Example YAML profiles
├── tests/
├── docs/                   # Design notes
└── artifacts/              # Generated catalogs & reports (gitignored)
```

Further design notes: [`docs/knowledge_base_analysis.md`](docs/knowledge_base_analysis.md).

---

## Roadmap

- [ ] Markdown / SARIF report generation (`rsfuzzer report`)
- [ ] Deeper mitmproxy integration
- [ ] Response heuristic–driven mutation depth (`expand_around_interest`)
- [ ] OpenAPI request-body schemas as mutation seeds

---

## Contributing

Contributions are welcome. Please open an issue before large changes. Run the test suite and keep new mutation strategies parametric (generators, not hard-coded CVE strings).

---

## Security

**Use only on systems you are authorized to test.** rsfuzzer sends intentionally malformed and adversarial requests. Do not point it at production without explicit permission.

---

## License

License not yet specified. See repository root for updates.
