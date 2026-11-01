"""UX-R1 model spend since T0, from the showcase portal's cost ledger (every model call the stack records).

    python -I ux_spend.py                 # total since T0, by kind and model, calls with no run, the dearest runs
    python -I ux_spend.py --since "2026-10-31 16:00:00+00"   # a batch window

Rows are priced per model in USD per million tokens (input, cached input, output), as the portal and the benchmark
price them; a model the table does not know (and a row with no model) is priced at the dearest price, so the figure can
only be too high. The providers' consoles stay the authority; calls a provider receives that the stack never records are
not seen here.
"""
import subprocess
import sys

T0 = "2026-10-31 15:24:00+00"
PRICES = {
    "gpt-6-luna": (0.10, 0.01, 0.50),
    "claude-sonnet-5-5": (2.00, 0.10, 10.00),
    "claude-haiku-5-5": (0.10, 0.01, 0.50),
    "gpt-6.1-sol": (2.00, 0.10, 10.00),
    "gpt-5-nano-2025-08-07": (0.05, 0.005, 0.40),
    "text-embedding-3-small": (0.02, 0.02, 0.0),
}
DEAREST = (2.00, 0.10, 10.00)
CONTAINER = "contexa-showcase-postgres-1"


def query(sql):
    out = subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "sh", "-c", 'psql -U "$POSTGRES_USER" -d showcase_portal -At -F "|"'],
        input=sql, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return [line.split("|") for line in out.splitlines() if line]


def usd(model, prompt, cached, completion):
    p = PRICES.get(model, DEAREST)
    return ((prompt - cached) * p[0] + cached * p[1] + completion * p[2]) / 1e6


def main():
    since = T0
    if "--since" in sys.argv:
        since = sys.argv[sys.argv.index("--since") + 1]
    rows = query(f"""
        select coalesce(run_id, ''), kind, coalesce(model, ''), coalesce(sum(prompt_tokens), 0),
               coalesce(sum(cached_prompt_tokens), 0), coalesce(sum(completion_tokens), 0), count(*)
          from cost_ledger where recorded_at >= '{since}'
         group by run_id, kind, model;""")
    total, by_model, no_run, by_run = 0.0, {}, 0.0, {}
    for run_id, kind, model, prompt, cached, completion, calls in rows:
        cost = usd(model, int(prompt), int(cached), int(completion))
        total += cost
        key = f"{kind} {model or '(none)'}"
        c, n = by_model.get(key, (0.0, 0))
        by_model[key] = (c + cost, n + int(calls))
        if run_id:
            by_run[run_id] = by_run.get(run_id, 0.0) + cost
        else:
            no_run += cost
    print(f"since {since}: ${total:.4f} over {len(by_run)} runs, ${no_run:.4f} in calls with no run")
    for key, (c, n) in sorted(by_model.items(), key=lambda kv: -kv[1][0]):
        print(f"  {key:40s} {n:6d} calls  ${c:.4f}")
    for run_id, c in sorted(by_run.items(), key=lambda kv: -kv[1])[:10]:
        print(f"  run {run_id}  ${c:.4f}")


if __name__ == "__main__":
    main()
