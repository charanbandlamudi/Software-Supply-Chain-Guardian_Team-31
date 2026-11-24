.PHONY: sandbox-down feeds demo hardening-test mirrors-up

sandbox-up:
	docker compose up -d

sandbox-down:
	docker compose down

test:
	cd guardian_v2 && .venv/bin/python -m pytest -q

hardening-test:
	PYTHONPATH=guardian_v2:agent:. python3 -m pytest -q tests guardian_v2/tests agent/tests

mirrors-up:
	docker compose up -d verdaccio pypi-mirror

seed-mirrors:
	python3 tools/seed_mirrors.py

demo-day1:
	cd guardian_v2/demo-app && PYTHONPATH=.. python3 ../run_guardian.py --config guardian.json --day1

demo-full:
	cd guardian_v2/demo-app && PYTHONPATH=.. python3 ../run_guardian.py --config guardian.json
