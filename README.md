# rsfuzzer

Repositorio de trabajo para desarrollar un fuzzer de logica de negocio/autorizacion para APIs e integrarlo con mitmproxy.

## Quick start

Hay que ejecutar comandos **desde la carpeta `rsfuzzer/`** (donde está `pyproject.toml`), o bien fijar el directorio del proyecto con `uv`:

```powershell
cd rsfuzzer
uv run rsfuzzer --help
```

Desde la raíz del monorepo (`mitmproxy-development/`):

```powershell
uv run --directory rsfuzzer rsfuzzer --help
```

`uv run` resuelve dependencias y registra el entrypoint `rsfuzzer` definido en `pyproject.toml`; no hace falta `pip install` a mano. Si usas solo `python -m rsfuzzer.cli`, Python no verá el paquete a menos que instales en editable (`pip install -e .`) o añadas `src` a `PYTHONPATH`.

## Comandos iniciales

- `rsfuzzer discover` — catálogo de endpoints (OpenAPI y/o tráfico)
- `rsfuzzer test` — comprobaciones explícitas + escaneo GET del catálogo entre dos roles (opcionalmente `--max` para mutaciones del mismo motor que `mutate`)
- `rsfuzzer mutate` — imprime variantes del motor de estrategias (dry-run por stdout); mismo registry que el paso opcional de `test --max`
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
- `--max N` — con escaneo activo: por cada endpoint GET del catálogo y **cada rol**, hasta `N` peticiones extra generadas con `permute_case` (mismas estrategias que `mutate`). `0` (defecto) lo desactiva. Cabeceras/query del rol se fusionan con las de la variante.
- `--mutate-light` — conjunto de estrategias reducido cuando `--max` > 0.
- `--mutate-parts` — ej. `query,headers` o `body,query,headers` (por defecto `query,headers` en GET no se envía body salvo que lo incluyas y el método lo permita).

### Bloque `differential` (mutaciones)

En el YAML, `differential` define casos que recorren el **producto** de `query_mutations`, `header_mutations` y `body_mutations` (en métodos con cuerpo). En cada combinación se lanza la petición para **cada rol** en `expect` y se compara el status. Así se detectan bypass por query, cabeceras o campos extra sin escribir un check manual por variante.

Ver `profiles/api_examples.yaml` junto con la API vulnerable en `../api_examples`.

### Mutaciones de payload (`mutate`)

Mismo motor que `test --max`, pero sin HTTP: escribe JSON por stdout para depurar estrategias.

Comando aparte del `differential` del YAML: ese bloque sigue usando solo listas explícitas en el perfil.

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
