# Detection as Code — Sigma → Elastic CI/CD

Sigma rules managed as code, validated and compiled to Kibana detection
rules on every push via GitHub Actions.

## Layout

```
rules/       Sigma rules by log source (windows/, ...)
tests/       Structural + conversion tests (pytest)
.github/     CI workflow: sigma check → pytest → convert → artifact upload
```

## Local workflow

```bash
make lint     # sigma check
make test     # pytest
make build    # compile to out/kibana-rules.ndjson
make deploy   # import into local Kibana (needs ELASTIC_PASSWORD env)
```

`deploy` example:

```bash
export ELASTIC_PASSWORD=<password from elastic-start-local/.env>
make build && make deploy
```

## Pipeline flow

push → `sigma check` → `pytest` → `sigma convert -f kibana` → artifact
`kibana-rules-<sha>` downloadable from the Actions run page.
