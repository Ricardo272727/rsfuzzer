# rsfuzzer

Repositorio de trabajo para desarrollar un fuzzer de logica de negocio/autorizacion para APIs e integrarlo con mitmproxy.

## Quick start

```powershell
cd rsfuzzer
uv run rsfuzzer --help
```

## Comandos iniciales

- `rsfuzzer discover` — catálogo de endpoints (OpenAPI y/o tráfico)
- `rsfuzzer test` — comprobaciones explícitas + escaneo GET del catálogo entre dos roles
- `rsfuzzer report` — pendiente

### Perfil y pruebas (`test`)

Perfil de ejemplo: `profiles/api_examples.yaml` (roles, fixtures, `checks`).

Con la API de ejemplo en marcha (`../api_examples`) y el catálogo generado:

```powershell
cd rsfuzzer
uv run rsfuzzer test `
  --profile-file profiles/api_examples.yaml `
  --catalog artifacts/endpoints.json `
  --roles user_alice,user_bob `
  --out artifacts/test_report.json
```

- `--no-scan` — solo ejecuta los `checks` del YAML (sin recorrer el catálogo GET).
- `--scope` — patrón `fnmatch` sobre el path del catálogo (por defecto `*`).

### Bloque `differential` (mutaciones)

En el YAML, `differential` define casos que recorren el **producto** de `query_mutations`, `header_mutations` y `body_mutations` (en métodos con cuerpo). En cada combinación se lanza la petición para **cada rol** en `expect` y se compara el status. Así se detectan bypass por query, cabeceras o campos extra sin escribir un check manual por variante.

Ver `profiles/api_examples.yaml` junto con la API vulnerable en `../api_examples`.

### Mutaciones de payload (`mutate`)

Motor basado en **estrategias** (`src/rsfuzzer/mutations/strategies/`): cada estrategia **genera** variantes (plantillas + parámetros + fábricas), no un dump fijo de strings.

```powershell
uv run rsfuzzer mutate --max 25 --light --parts body,query,headers
```

Análisis de **knowledge base** y grafo de ataque: `docs/knowledge_base_analysis.md`.

## Estructura

- `src/rsfuzzer/`: codigo del paquete
- `src/rsfuzzer/mutations/`: motor y estrategias de mutación
- `profiles/`: perfiles YAML de ejemplo
- `docs/`: notas de diseño (KB)
- `tests/`: pruebas
