# ponytail: PATH first for CI, falls back to the sibling .venv for local runs
SIGMA ?= $(shell command -v sigma 2>/dev/null || echo ../.venv/bin/sigma)
PYTEST ?= $(shell command -v pytest 2>/dev/null || echo ../.venv/bin/pytest)

.PHONY: lint test build deploy clean

lint:
	$(SIGMA) check rules/

test:
	$(PYTEST) tests/ -q

build:
	mkdir -p out && $(SIGMA) convert -t lucene -p ecs_windows -p ecs_kubernetes -p ecs_zeek_beats -f kibana_ndjson rules/ > out/kibana-rules.ndjson
	@wc -l out/kibana-rules.ndjson

# ponytail: local-only because the stack binds 127.0.0.1; self-hosted runner needed for remote deploys
deploy:
	curl -sS -X POST "$${KIBANA_URL:-http://localhost:5601}/api/detection_engine/rules/import" \
		-u "elastic:$${ELASTIC_PASSWORD:?set ELASTIC_PASSWORD}" \
		-H 'kbn-xsrf: true' -H 'elastic-api-version: 2023-10-31' \
		--data-binary @out/kibana-rules.ndjson

clean:
	rm -rf out
