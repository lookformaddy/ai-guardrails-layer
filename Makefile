.PHONY: install test demo serve clean

install:
	pip install -r requirements.txt
	pip install -e .

test:
	pytest -q

demo:
	python examples/run_demo.py

serve:
	guardrails serve --host 127.0.0.1 --port 8000

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -rf .pytest_cache *.egg-info build dist data
