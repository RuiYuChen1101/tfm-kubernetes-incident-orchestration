# TFM - Kubernetes Incident Orchestration with OSCAR, Kagent and OpenSRE

Trabajo Fin de Máster centrado en la monitorización y análisis automatizado de incidentes en Kubernetes mediante la integración de OSCAR, Prometheus, Loki, Kagent y OpenSRE.

## Objetivo

El sistema implementa un flujo de detección e investigación de incidencias en Kubernetes.

El coordinador detecta señales de riesgo, recopila evidencia inicial desde Kubernetes, Prometheus y Loki, construye casos de investigación y delega comprobaciones dinámicas de solo lectura a Kagent. Finalmente, OpenSRE analiza la evidencia recopilada y genera un informe del incidente.

## Arquitectura

```text
Prometheus / Loki / Kubernetes API
                |
                v
          Coordinator
                |
                v
             Kagent
                |
                v
             OpenSRE
                |
                v
        Incident Report
```

Componentes principales:

- Kubernetes / OSCAR
- Prometheus
- Loki
- Kagent
- OpenSRE
- Ollama
- Coordinator desarrollado en Python

## Estructura

- `coordinator/`: lógica principal de detección, recopilación y normalización de evidencia, integración con Kagent y OpenSRE.
- `manifests/`: manifiestos Kubernetes de los componentes utilizados.
- `scripts/`: scripts de instalación, construcción y ejecución.
- `scenarios/`: escenarios reproducibles utilizados para validar incidentes.
- `k8s/`: recursos Kubernetes y escenarios adicionales.
- `requirements.txt`: dependencias Python.

## Flujo de investigación

1. Detección de señales de riesgo.
2. Agrupación de señales por recurso afectado.
3. Recopilación de evidencia inicial.
4. Investigación adaptativa con Kagent mediante operaciones de solo lectura.
5. Normalización y preservación de evidencias.
6. Investigación final mediante OpenSRE.
7. Generación del informe del incidente.

## Validación

Se han utilizado distintos escenarios controlados para validar el funcionamiento del sistema, incluyendo:

- CrashLoopBackOff
- errores observados en logs
- riesgos relacionados con CPU y memoria
- ausencia de requests o limits
- incidencias de configuración de almacenamiento
- volúmenes montados en modo de solo lectura

El escenario `scenarios/worker-service` reproduce un contenedor que intenta escribir en `/data` mientras el volumen está montado con `readOnly: true`.

Este escenario ha permitido validar el flujo completo:

```text
Detection
→ Initial evidence
→ Kagent investigation
→ Evidence handoff
→ OpenSRE investigation
→ Incident report
```

## Estado actual

El flujo completo Coordinator → Kagent → OpenSRE ha sido validado manualmente.

La siguiente fase del proyecto consiste en desplegar el Coordinator dentro del clúster y automatizar su ejecución mediante Kubernetes Job/CronJob.

## Nota

Los resultados de ejecución, logs, entornos virtuales, modelos locales, repositorios externos y archivos temporales no se incluyen en este repositorio.
