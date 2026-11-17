# RADAR SOC — Sprint 01: RADAR-IDENTITY-001

Detector **experimental y defensivo** de posible reutilización sospechosa de sesiones
autenticadas. Usa solo datos simulados. No predice ataques: detecta indicadores
precursores y los clasifica como **anomalía → sospecha → sospecha fuerte**.
"Compromiso confirmado" solo lo puede asignar un analista humano.

## Instalación (Windows 11 + VS Code, PowerShell)
```powershell
cd radar_soc
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .
```

## Ejecutar
```powershell
python -m radar_soc.cli --events data\scenarios\08_malicious_stealer_session_reuse.json --baseline data\baseline.json --output alerts.json
```

## Pruebas
```powershell
pytest -v
```

## Estructura
| Carpeta/archivo | Responsabilidad |
|---|---|
| `src/radar_soc/models.py` | Contratos de datos (Event, Signal, Finding, clasificaciones) |
| `src/radar_soc/normalizer.py` | Validación, rechazo de datos malos, redacción de secretos |
| `src/radar_soc/baseline.py` | Qué es "normal": dispositivos conocidos, redes corporativas |
| `src/radar_soc/correlation.py` | Agrupa por sesión y busca evidencia de endpoint |
| `src/radar_soc/detector.py` | Lógica de RADAR-IDENTITY-001 y generación de señales |
| `src/radar_soc/scoring.py` | Puntuación, clasificación y severidad |
| `src/radar_soc/alerts.py` | Alertas explicables, pseudonimización de sesión |
| `src/radar_soc/rules.py` | Metadatos de la regla (MITRE, falsos positivos, respuesta) |
| `src/radar_soc/cli.py` | Línea de comandos |
| `data/scenarios/` | 10 escenarios simulados (legítimos y maliciosos) |
| `tools/make_scenarios.py` | Regenera los escenarios |
| `tests/` | Pruebas Pytest |

## Limitaciones
- Infiere por contexto; no ve cookies, por lo que NO demuestra robo de cookies.
- Pesos y umbrales son heurísticos, sin calibrar con datos reales.
- Sin geolocalización por distancia ("viaje imposible").
- Sin Machine Learning: no se ha entrenado ni evaluado ningún modelo.
- Usuarios ausentes de la línea base tienen "0 dispositivos conocidos" (posibles falsos positivos).
- Análisis por lotes, no en streaming.
