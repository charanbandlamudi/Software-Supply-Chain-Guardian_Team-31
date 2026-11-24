.PHONY: sandbox-down feeds demo

sandbox-up:
	docker compose up -d

sandbox-down:
	docker compose down

test:
	cd guardian_v2 && .venv/bin/python -m pytest -q

demo-day1:
	cd guardian_v2/demo-app && PYTHONPATH=.. python3 ../run_guardian.py --config guardian.json --day1

demo-full:
	cd guardian_v2/demo-app && PYTHONPATH=.. python3 ../run_guardian.py --config guardian.json
