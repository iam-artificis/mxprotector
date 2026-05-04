# features-plans/

In-repo feature roadmaps. Each `*.md` here describes the **remaining
work** for one in-flight feature: what's shipped, what's blocked,
how to pick it up.

These files live in the repo (not in Claude Code's auto-memory) so
they:

  * version with the code they describe — when the code changes,
    the roadmap updates next to it in the same commit.
  * stay out of the auto-memory context budget — only loaded on
    demand by reading the path directly.
  * survive across machines / users — anyone cloning the repo gets
    the same roadmap.

The auto-memory `MEMORY.md` index keeps a one-line pointer per file
so future sessions can find them.
