# Knowledge base para vectores de ataque: análisis de diseño

Este documento resume **cómo combinar conocimiento general y local** con el motor de mutaciones de `rsfuzzer`, y si tiene sentido un **grafo de ataque**.

## 1. Dos tipos de conocimiento

### 1.1 Conocimiento general (global)

Aplicable a **lenguaje, runtime, librería, framework o versión** sin mirar un target concreto.

- Ejemplos: plantillas de inyección parametrizadas por marcador, profundidad JSON típica que rompe parsers, claves de prototype pollution en entornos JavaScript, límites numéricos del lenguaje del servidor, patrones JWT débiles.
- En el código actual esto vive sobre todo en `mutations/strategies/*`: **generadores** y **fábricas** (p. ej. `injection_templates()`, `_named_templates()`, `_numeric_edge_factory()`), no listas fijas de CVE.

**Ventaja:** reutilizable, estable, fácil de testear unitariamente.

**Límite:** no sabe qué endpoints existen en tu API ni qué campos son sensibles.

### 1.2 Conocimiento local (por target / por sesión de test)

Derivado del **catálogo** (`discover`), del **tráfico**, del **OpenAPI**, o de respuestas observadas.

- Ejemplos: “este path acepta `expand`”, “este body tiene `ownerId`”, “solo usuarios con rol X llaman a `/api/admin/*`”, “tras un 500, el mensaje menciona una plantilla”.
- El motor ya tiene un gancho para segunda fase: `expand_around_interest(case, anchor, signals)` en `mutations/engine.py`, donde `signals` puede llevar `payload_hint`, `focus_key`, `category`, `status_code`, etc.

**Ventaja:** menos ruido, mutaciones alineadas con la superficie real.

**Límite:** hay que **ingerir y normalizar** contexto (merge OpenAPI + tráfico, correlación de roles, límites de rate).

## 2. ¿Una “knowledge base” como módulo?

Propuesta práctica en capas:

| Capa | Contenido | Formato sugerido |
|------|-----------|-------------------|
| **Catálogo de estrategias** | Clases en `mutations/strategies/` + registro en `registry.py` | Código + metadatos (`id`, `category`) |
| **Reglas parametrizadas** | Umbrales (profundidad JSON, tamaños, subconjuntos de plantillas) | YAML en `profiles/` o tabla en código |
| **Heurísticas de interés** | “Si status 500 y cuerpo contiene X → `deepen_injection`” | Funciones puras + tests |
| **KB externa versionada** | “Express 4.x + body-parser + merge profundo” | JSON/YAML versionado, o DB solo si crece mucho |

No hace falta una base de datos al inicio: **YAML + código** suele bastar hasta que el número de reglas explote.

## 3. ¿Grafo de ataque?

**Sí, es una buena idea** como *modelo mental* y como implementación **si** necesitas:

- prerequisitos explícitos (login → token → acción),
- estados (pedido en `draft` vs `paid`),
- ramas condicionales (“si bypass por header, entonces probar escritura”).

Nodos posibles: **rol**, **endpoint**, **mutación**, **observación** (status, tiempo, error).  
Aristas: **permite**, **refina**, **expande**.

Para el MVP actual de `rsfuzzer`, un grafo completo es opcional: el flujo **discover → test/differential → mutaciones con `expand_around_interest`** ya es un **árbol/plan lineal con ramas locales**. Un grafo explícito encaja cuando añadas **workflows multi-paso** (carritos, OAuth, refresh).

## 4. Integración con el motor de mutaciones

1. **Fase ancha:** `permute_case` / `MutationEngine.expand` recorre estrategias sobre body, query y headers.
2. **Fase estrecha:** un evaluador de respuestas (aún mínimo) rellena `signals` y llama a `expand_around_interest` para acercarse a un payload “interesante” (p. ej. `narrow_injection_around`).

Las heurísticas pueden empezar siendo reglas simples (`status in (500,502)`, `latency > T`, substring en body) y crecer hacia scoring o clasificadores.

## 5. Riesgos y buen uso

- Mutaciones de agotamiento de recursos y JSON profundos pueden **dañar entornos**; usar solo en staging y con límites (`max_variants`, `light=True`).
- Raw HTTP (chunked smuggling, CL.TE) requiere **cliente distinto de `urllib`**; las estrategias pueden generar intención aunque el runner actual solo envíe cabeceras compatibles.

## 6. Resumen

- **KB general** → estrategias generadoras en código (lo implementado).
- **KB local** → catálogo + señales de respuesta → segunda fase alrededor del payload.
- **Grafo de ataque** → recomendable cuando haya flujos de negocio y estados; para mutaciones puras, un **plan con expansión local** suele ser suficiente al principio.
