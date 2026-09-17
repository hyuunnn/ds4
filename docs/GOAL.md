# Goals

[README](../README.md) | [Agent sessions](../README.md#native-coding-agent)

`/goal` gives `ds4-agent` a session-scoped completion condition. While a goal
is active, the agent does not stop at the end of an assistant turn: the worker
keeps the turn alive until the model proves the condition and declares it met,
reports itself blocked on a user decision, or the user stops the goal.

## Commands

| Command | Action |
| --- | --- |
| `/goal <condition>` | Set or replace the active goal and start working on it |
| `/goal` | Show the active condition and how many checks have run |
| `/goal clear` | Stop and remove the active goal (`/goal off` also works) |

One goal is active at a time; setting a new goal replaces the old one and
resets its check counter. Setting a goal while the agent is idle submits the
condition as a turn immediately. Setting one while the agent is busy queues
the condition, so it is picked up at the next turn boundary or as the next
turn after the current one ends.

## How it runs

A goal is a condition owned by the harness, not a prompt the model can edit.
The loop works like this:

1. The model works normally — tool calls execute as usual.
2. When the assistant answers in plain text with no tool call, the worker
   first delivers any input typed while it was busy, then appends a synthetic
   user message (`[ds4-agent goal check N]` plus the condition) instead of
   returning to the prompt. The same session and live KV state continue, so
   each check costs only the nudge's tokens of prefill.
3. The model resolves the goal by calling the `goal` tool:
   - `met=true` — the condition is verified by evidence produced so far.
     Prints `Goal met: <reason>` and ends the loop.
   - `met=false` — the model is blocked on a decision only the user can make.
     Prints `Goal blocked: <reason>` and ends the loop.

The tool's verdict is recorded in the transcript before the loop exits, so the
declaration is auditable in history. Calling `goal` with no active goal, or
with a missing/invalid `met`, is a tool error the model can retry — it never
silently resolves anything.

The goal text is re-injected with every check, so it survives context
compaction even when the original condition scrolls out of the summarized
history.

## Stopping a goal

- `goal` tool verdict — `met` or `blocked`, as above.
- `/goal clear` — removes the goal; the current turn ends normally.
- Ctrl+C — interrupts generation. The goal stays active and re-engages on the
  next turn; the status line notes that it is still set.
- `/new` and `/switch` — reset goal state with the session.

There is no turn or token limit on a goal loop. Context pressure is handled by
automatic compaction; the practical bounds are the model's verdict and user
interrupts.

## Lifecycle notes

- Goals are runtime state. They are not written into saved sessions, so
  `/save` + `/switch` resumes the conversation but not the loop. Check
  messages do remain in the transcript as history.
- `/goal` in a non-interactive (`-p` or piped stdin) session is not parsed as
  a command — it reaches the model as plain text.
- The `goal` tool is visible to the model in every supported tool format
  (DSML, DSML4.1, GLM, Qwen), but calling it without an active goal is a no-op
  error.

## Writing a good condition

The model judges the goal from evidence it produced, not from intent. A
verifiable condition converges; a vague one can loop:

```text
/goal tests/hello.txt exists and contains the greeting
/goal make test_engine_correctness passes
/goal the remaining FIXME items in src/ are resolved or each has a written reason
```

Prefer conditions that name a checkable artifact: a file, a passing command,
a diff property. Avoid open-ended ones ("improve the code") — the model may
keep working without ever being able to call `met=true` defensibly, and the
loop only ends on a verdict or your interrupt.

## Watching a loop

- `goal ` appears as a tool prefix in the stream when the model calls it.
- Bare `/goal` shows the condition and `(N checks)` — the number of
  continuation nudges injected so far.
- If the model keeps narrating instead of calling the tool or working, that
  is a model-behavior issue, not a stuck loop: `/goal clear` always works,
  and regular input typed during the loop is delivered at the next boundary.
