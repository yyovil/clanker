# Agent sessions prompt

Clanker was built with Codex and Cursor, and their sessions in this repository are
recorded with [Entire](https://docs.entire.io/overview). About 1,400 checkpoints
covering 211 sessions are published in this repository as Git refs under
`refs/entire/checkpoints/`. They hold the prompts, agent responses, tool calls and
files behind the work.

Reading them needs only Git and the Entire CLI. No Entire account, login or
`entire enable` is required.

Paste this into your coding agent:

```text
Help me review the coding-agent sessions used to build Clanker
(https://github.com/yyovil/clanker). They are recorded with Entire and published
as Git refs under refs/entire/checkpoints/ in that repository.

1. Check for Git and the Entire CLI (`entire version`). If Entire is missing,
   install the stable channel for this OS from https://docs.entire.io/installation.md:
   macOS `brew install --cask entireio/tap/entire`, Linux
   `curl -fsSL https://entire.io/install.sh | bash`, Windows
   `irm https://entire.io/install.ps1 | iex`. Set ENTIRE_NO_AUTO_UPDATE=1.

2. Fetch the checkpoints into a fresh directory. The source checkout is not needed
   to read sessions, and the download is about 260 MB:
     git init clanker-sessions && cd clanker-sessions
     git remote add origin https://github.com/yyovil/clanker.git
     git fetch origin '+refs/entire/checkpoints/*:refs/entire/checkpoints/*'
   If the full repository is already cloned, run the same fetch inside it instead.

3. Build an index. List checkpoint IDs with
     git for-each-ref --format='%(refname:lstrip=-1)' refs/entire/checkpoints
   `entire checkpoint list` only shows checkpoints linked to the current branch,
   so do not rely on it. Most checkpoints were imported after the fact, one per
   turn, so Git commit dates are not when the work happened. Run
   `entire checkpoint explain <id> --short` for each ID to get its session ID,
   creation time and intent, then group checkpoints by session and order sessions
   by creation time. Some sessions appear twice, once captured live and once
   imported; treat them as one. Check `entire agent-help checkpoint explain` for
   the exact flags of the installed version.

4. Give me a short orientation: how many sessions, which days, which agents and
   models, and the main threads of work by area (Slack gateway, Kernel browser
   and vault, access management, benchmark runs, docs). Group by theme, not by
   checkpoint.

5. Then answer my questions about the development process. Read the relevant
   transcripts with `entire checkpoint explain <id> --full` before answering, cite
   the checkpoint IDs and dates you relied on, and quote the prompt or decision
   when it matters. Say when the sessions do not cover something rather than
   guessing. These sessions are read-only history: do not run `entire enable`,
   `entire login`, or anything that writes to the repository.
```

Questions worth asking:

- How was the work split between the developer and the agents, and where did the developer step in?
- Which approaches were tried and abandoned, and why?
- How were the benchmark tasks run and verified?
- How did credential handling and access sharing evolve?
