# Guardian Agents

Local agent scaffold for the Software Supply Chain Guardian.

The supervisor runs deterministic ingestion and graph stages first, then specialist
analysis stages and a report stage. External intelligence integrations are
configured through agent coverage; no network or secret access is performed by
default.

## Run

```bash
python -m guardian.cli requirements.txt
```

Run against the supplied SBOM, dependency graph, and Grype report:

```bash
python -m guardian.cli \
  /home/pranaav/bosch/sbom.json \
  /home/pranaav/bosch/graph.json \
  /home/pranaav/bosch/grype-report.json \
  --output guardian-report.json
```

Groq inference is optional and remains disabled until an API key is provided:

```bash
export GROQ_API_KEY="provided-later"
export GROQ_MODEL="llama-3.3-70b-versatile"  # optional
python -m guardian.cli /home/pranaav/bosch/sbom.json /home/pranaav/bosch/graph.json /home/pranaav/bosch/grype-report.json
```

The key is read only by the Groq client. Never commit it or place it in a report.

Gemini can be used as an automatic fallback after Groq fails or is not configured:

```bash
GEMINI_API_KEY="provided-later"
GEMINI_MODEL="gemini-2.0-flash"  # optional
```
