# Session Tracking Workflow

This document defines how to use the session tracking workflow in Claude Code.

## Commands

### Start Session
When you say **"start session"**:
1. I acknowledge the session has started
2. I create a note to track all work via TodoWrite during the session
3. I check `/Users/aetomala/projects/code-sessions.md` for an existing entry with today's date
4. If an entry already exists for today, I ask: "I found an existing session entry for today. Would you like to: A) Append to the existing entry, or B) Create a new separate entry?"
5. I store your choice for when you end the session

### End Session
When you say **"end session [duration]"** (e.g., "end session 2h 30m" or "end session 1h 15m"):

1. **I generate a work summary** based on:
   - All TodoWrite items you completed during the session
   - Git commits made during the session
   - Focus on architecture, concepts, and patterns (NOT individual file names)

2. **Summary Format**:
   The summary will follow this exact template:
   ```
   ### [YYYY-MM-DD] - [Project Name]
   **Duration**: [your provided duration]

   **Project**: [repository name]

   **Project Overview**:
   [Brief 1-2 sentence description of what was accomplished]

   **Key Technical Accomplishments**:
   - [High-level accomplishment 1]
     - [Detailed implementation point]
     - [Detailed implementation point]
   - [High-level accomplishment 2]
     - [Detailed implementation point]

   **Technical Skills Demonstrated**:
   [Comma-separated list of technical concepts, patterns, tools]
   ```

3. **I append the summary** to `/Users/aetomala/projects/code-sessions.md`:
   - If file doesn't exist, I create it with header: `# Development Session Log`
   - If you chose "append" earlier, I add to the existing day's entry
   - If you chose "new entry", I create a separate dated section
   - The file is NOT tracked in git (see .gitignore)

4. **I create a git commit** with your session work:
   - Stage all changes: `git add -A`
   - Create commit summarizing the work
   - **NO "Co-Authored-By" line** in the commit message
   - Format: `[action] [summary of changes]`

5. **I ask about pushing**:
   - "Session logged to code-sessions.md and committed. Would you like me to push to remote?"
   - I'll push if you approve, or skip if you decline

## Summary Quality Guidelines

### What to Include ✅
- Architectural patterns used (dependency injection, factory, observer)
- Technologies and tools (JWT, OAuth, Redis, PostgreSQL, Ginkgo/Gomega)
- Testing strategies (mocking, BDD, integration tests)
- Core concepts (rate limiting, token rotation, claims validation)
- Design patterns and decisions

### What to Avoid ❌
- Specific file names like "service.go", "handler.ts", "auth.py"
- Line-by-line code changes
- Implementation details like "added a for loop"

### Examples

**Good Summary**: "Implemented JWT token service with rate limiting, custom claims support, and comprehensive BDD test coverage using Ginkgo/Gomega and gomock for dependency injection testing"

**Poor Summary**: "Modified service.go, service_test.go, and claims.go to add IssueAccessToken and IssueAccessTokenWithClaims methods"

## How This Persists Across Chat Sessions

This file (CLAUDE.md) ensures that the session tracking workflow continues to work even if you start a new chat. The instructions are stored here so every chat session knows what to do when you say "start session" or "end session [duration]".

## See Also
- Work log: `/Users/aetomala/projects/code-sessions.md` (created after first session)
- Local settings: `.claude/settings.local.json` (has git command permissions)
