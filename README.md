# Detection as Code — Sigma → Elastic CI/CD

Sigma rules managed as code, validated and compiled to Kibana detection
rules on every push via GitHub Actions.

## Layout

```
rules/
  windows/     process, registry, service, LOLBin rules
  linux/       ssh, sudo, cron, reverse shell, auth file rules
  container/   kubernetes audit rules
  cloud/       AWS CloudTrail rules
  network/     zeek dns/http rules
tests/         structural + conversion tests (pytest)
.github/       CI: strict sigma check → pytest → convert → artifact
```

24 rules across 24 distinct MITRE ATT&CK techniques.

## Local workflow

```bash
make lint     # sigma check -E -i (fails on errors AND tagging issues)
make test     # pytest
make build    # compile to out/kibana-rules.ndjson (Kibana Detection Engine rules)
make deploy   # import into local Kibana (needs ELASTIC_PASSWORD env)
```

`deploy` example:

```bash
export ELASTIC_PASSWORD=<password from elastic-start-local/.env>
make build && make deploy
```

## Adding a rule

1. `rules/<source>/<name>.yml` — required fields: `title`, `id` (uuid4),
   `status`, `description`, `references`, `author`, `date`, `tags`,
   `logsource`, `detection`, `falsepositives`, `level`.
2. Tags must be current ATT&CK names (`sigma check` validates them against
   the live ATT&CK dataset — `attack.defense-evasion` and `attack.t1562.*`
   were retired in v19, now `attack.stealth` / `attack.defense-impairment`
   and `attack.t1685.*`).
3. Field names must survive the ECS pipelines used at build time:
   `ecs_windows`, `ecs_kubernetes`, `ecs_zeek_beats`.
4. `make lint && make test && make build`.

## Pipeline flow

push → `make lint` → `make test` → `make build`
(`sigma convert -t lucene -f siem_rule_ndjson`) → artifact
`kibana-rules-<sha>` downloadable from the Actions run page.

Each compiled rule carries ECS field mappings, an `index` pattern, severity,
risk score and MITRE `threat` entries, so `make deploy` can post the file
straight to `/api/detection_engine/rules/import`.

Deploy stays manual (`make deploy`) because the local Elastic stack binds
127.0.0.1; a self-hosted runner is needed for remote deploys.
