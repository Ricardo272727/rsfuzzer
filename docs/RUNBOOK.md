# rsfuzzer runbook

Copy-paste commands for local testing against the sample API.  
Requires [uv](https://docs.astral.sh/uv/) and commands run from the `rsfuzzer/` directory.

---

## Terminal 1 — start the API

```powershell
cd ..\api_examples
npm install
npm start
```

Base URL: `http://127.0.0.1:3000`

| Header      | Values           |
|-------------|------------------|
| `x-user-id` | `u1`, `u2`, `a1` |
| `x-role`    | `user`, `admin`  |

Restart the server after heavy PATCH fuzzing (in-memory state drifts).

---

## Terminal 2 — discover + test

### Discover endpoints

```powershell
cd rsfuzzer

uv run rsfuzzer discover `
  --openapi ..\api_examples\openapi.json `
  --traffic ..\api_examples\artifacts\flows.ndjson `
  --out artifacts\endpoints.json
```

OpenAPI only:

```powershell
uv run rsfuzzer discover `
  --openapi ..\api_examples\openapi.json `
  --out artifacts\endpoints.json
```

---

## Test commands

Profile: `profiles/api_examples.yaml`  
Roles: `user_alice` (u1), `user_bob` (u2)

### Smoke (no catalog scan)

```powershell
uv run rsfuzzer test `
  --profile-file profiles\api_examples.yaml `
  --catalog artifacts\endpoints.json `
  --roles user_alice,user_bob `
  --no-scan `
  --out artifacts\test_report_smoke.json
```

### Standard

```powershell
uv run rsfuzzer test `
  --profile-file profiles\api_examples.yaml `
  --catalog artifacts\endpoints.json `
  --roles user_alice,user_bob `
  --out artifacts\test_report.json
```

### Catalog fuzz — query & headers

```powershell
uv run rsfuzzer test `
  --profile-file profiles\api_examples.yaml `
  --catalog artifacts\endpoints.json `
  --roles user_alice,user_bob `
  --max 500 `
  --mutate-parts query,headers `
  --out artifacts\test_report_scan.json
```

### Catalog fuzz — JSON body

```powershell
uv run rsfuzzer test `
  --profile-file profiles\api_examples.yaml `
  --catalog artifacts\endpoints.json `
  --roles user_alice,user_bob `
  --max 500 `
  --mutate-parts body `
  --out artifacts\test_report_body.json
```

### Full local fuzz

```powershell
uv run rsfuzzer test `
  --profile-file profiles\api_examples.yaml `
  --catalog artifacts\endpoints.json `
  --roles user_alice,user_bob `
  --scope "*" `
  --max 500 `
  --mutate-parts body,query,headers `
  --out artifacts\test_report_full.json
```

Faster:

```powershell
uv run rsfuzzer test `
  --profile-file profiles\api_examples.yaml `
  --catalog artifacts\endpoints.json `
  --roles user_alice,user_bob `
  --max 500 `
  --mutate-light `
  --mutate-parts body,query,headers `
  --out artifacts\test_report_full_light.json
```

---

## Mutate dry-run

```powershell
uv run rsfuzzer mutate --max 25 --light --parts body,query,headers
```

```powershell
uv run rsfuzzer mutate `
  --method PATCH `
  --path /api/orders/101/status `
  --max 50 `
  --parts body
```

---

## From monorepo root

```powershell
uv run --directory rsfuzzer rsfuzzer test `
  --profile-file profiles\api_examples.yaml `
  --catalog artifacts\endpoints.json `
  --roles user_alice,user_bob `
  --max 500 `
  --mutate-parts body,query,headers `
  --out artifacts\test_report_full.json
```

---

## Interpreting output

```text
[test] Checks: 6 total.
[test] Differential: 16 requests, 6 failed.
[test] Failed (checks + differential): 6.
[test] Scan rows: 2100 (2090 mutation-engine).
```

| Line | Meaning |
|------|---------|
| Checks | YAML `checks` block |
| Differential | YAML `differential` cartesian product |
| Scan rows | Catalog baseline + `--max` mutations |
| Failed | Status mismatch (often auth bypass) |

Report fields: `check_failures`, `scan`, `mutation_traces`.
