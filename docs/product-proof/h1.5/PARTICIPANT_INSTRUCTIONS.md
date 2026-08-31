# Participant Instructions — NodeChain Research Study

Welcome, and thank you for taking part. You are testing a real research tool as it exists today: a command-line product called NodeChain that runs governed research tasks, gathers sources, and produces a verifiable research memo.

There are no wrong answers and no way to fail. We are testing the product, not you. If something is confusing or frustrating, that is exactly the information we need — please say so as you go.

## What you need

- A terminal (this study uses the command line; you will type commands yourself).
- Roughly 60–90 minutes.

## The commands you may use

These are ALL the product commands for this study. Use any of them at any point:

```bash
# Start a live research run on your question
nodechain research run "<your question>" --profile live --workspace <workspace>

# See your runs and their status
nodechain research runs --workspace <workspace>

# Full view of one run: claims, sources, faults, recovery guidance
nodechain research inspect <run-id> --workspace <workspace>

# Readable research memo (what you would actually read)
nodechain research report <run-id> --workspace <workspace>

# Verify the terminal artifact is intact
nodechain research verify <run-id> --workspace <workspace>

# Compare two runs side by side
nodechain research compare <run-id-a> <run-id-b> --workspace <workspace>
```

## How the session runs

1. **Your own research task.** Bring a real question from your work or interests — something you actually want to know, answerable from public academic sources. We'll ask what a useful answer would look like for you and how you'd normally research it. Then you run the research yourself with the commands above and read the memo.
2. **Checking the evidence.** Pick one claim from your results and find out what backs it: the evidence, the sources, the citations, the confidence. We want to see how you investigate it using the tool.
3. **Run it again.** You'll run the same question a second time and compare the two runs.
4. **Two prepared scenarios.** We'll hand you two pre-made situations — one waiting for a human decision, one that hit a failure. For each: figure out what happened, what the system knows, and what the governed next action is.

## Ground rules

- Think out loud if you're comfortable — it helps us enormously.
- Ask the facilitator anything, but for scored tasks they may only note that they helped, not tell you where to look.
- Nothing you say will be attributed to you by name. Committed study evidence uses codes like `P01`.
- Your research question stays private unless you choose otherwise; committed results generalize task descriptions.

## After the session

You'll fill in a short survey (about 5 minutes) on trust, friction, value, and whether you'd use the tool again. Honest answers — especially negative ones — are the most useful thing you can give us.
