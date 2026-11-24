"""Run the multi-agent Guardian on a project.

  python run_guardian.py --config demo.json                 # asks you at the approval gate
LLM keys (optional): ANTHROPIC_API_KEY, GROQ_API_KEY, GEMINI_API_KEY.
GITHUB_TOKEN (optional) enables the GHSA source.
"""
from __future__ import annotations

import argparse
import json
import os
import uuid

from langgraph.types import Command

from guardian_v2.orchestrator import build_orchestrator
from guardian_v2.providers import default_chain
from guardian_v2.checkpoints import SQLiteCheckpointStore


def ask_human(payload: dict) -> dict:
    print("\n" + "=" * 78 + "\nHUMAN APPROVAL GATE: " + payload["question"])
    for pid, p in payload["plans"].items():
        print(f"  [{p['action']:>22}] {p['component']}  {p.get('from') or ''} -> {p.get('to') or ''}"
              f"  (attempt {p.get('attempt')})\n{'':27}{(p.get('rationale') or '')[:110]}")
    ans = input("Approve all? [y]es / [n]o / [s]elect: ").strip().lower()
    name = input("Reviewer name: ").strip() or "anonymous"
    if ans.startswith("y"):
        return {"all": "approve", "reviewer": name}
    if ans.startswith("s"):
        return {"decisions": {pid: ("approve" if input(f"  approve {pid}? [y/n] ").lower().startswith("y")
                                    else "reject") for pid in payload["plans"]}, "reviewer": name}
    return {"all": "reject", "reviewer": name}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--llm-planner", action="store_true", help="let the LLM choose agents each turn")
    ap.add_argument("--day1", action="store_true", help="Day 1 checkpoint: discover + detect + evidence only")
    ap.add_argument("--checkpoint-db", default=None, help="SQLite path for durable agent snapshots")
    ap.add_argument("--resume-run", default=None, help="Existing run ID to restore from SQLite")
    args = ap.parse_args()

    inputs = json.load(open(args.config))
    base = os.path.dirname(os.path.abspath(args.config))
    for k in ("sbom", "python_graph", "python_manifest", "npm_lock", "npm_lock_baseline", "npm_manifest", "smoke_test", "out_dir"):
        if inputs.get(k):
            inputs[k] = os.path.join(base, inputs[k])
    for k in ("source_dirs", "dockerfiles", "workflows"):
        inputs[k] = [os.path.join(base, p) for p in inputs.get(k, [])]
    llm_call, providers = default_chain()
    app, catalog = build_orchestrator(
        context=inputs.pop("context", None), llm_call=llm_call, providers=providers,
        planner_llm=llm_call if (args.llm_planner and llm_call) else None,
        stage="day1" if args.day1 else "full")
    print(f"agents: {[a.name for a in catalog]}\nLLM providers: {providers or 'none (deterministic templates)'}")

    thread_id = args.resume_run or str(uuid.uuid4())
    cfg = {"configurable": {"thread_id": thread_id}, "recursion_limit": 200}
    checkpoint_store = SQLiteCheckpointStore(args.checkpoint_db) if args.checkpoint_db else None
    if checkpoint_store and args.resume_run:
        restored = checkpoint_store.load(args.resume_run)
        if restored:
            print(f"restored checkpoint: {args.resume_run}")
    if args.day1:
        inputs["stage"] = "day1"
    payload = {"run_id": cfg["configurable"]["thread_id"][:8], "inputs": inputs}
    if checkpoint_store and args.resume_run:
        restored = checkpoint_store.load(args.resume_run)
        if restored and isinstance(restored["state"], dict):
            payload = restored["state"]
            payload.setdefault("run_id", cfg["configurable"]["thread_id"][:8])
            payload.setdefault("inputs", inputs)
        else:
            print(f"checkpoint not found: {args.resume_run}")
    while True:
        for chunk in app.stream(payload, cfg, stream_mode="updates"):
            for node, delta in chunk.items():
                for m in (delta or {}).get("messages", []) if isinstance(delta, dict) else []:
                    to = ",".join(m["to"]) if isinstance(m["to"], list) else m["to"]
                    print(f"[turn {m['turn']:>2}] {m['from']:>13} -> {to:<40.40} {m['text'][:170]}")
        snap = app.get_state(cfg)
        if checkpoint_store:
            checkpoint_store.save(thread_id, snap.values)
        if not snap.next:
            break
        intr = snap.tasks[0].interrupts[0].value if snap.tasks and snap.tasks[0].interrupts else None
        if intr is None:
            break
        if checkpoint_store:
            checkpoint_store.save_interrupt(thread_id, intr)
        payload = Command(resume=ask_human(intr))
    out = app.get_state(cfg).values.get("report", {})
    print(f"\nreports written to {out.get('dir')}")


if __name__ == "__main__":
    main()
