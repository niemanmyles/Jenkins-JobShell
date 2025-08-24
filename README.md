# JenkinsShell 🛠️

A Python tool to interact with Jenkins servers via the REST API.  
Supports pulling and updating job configs, replacing `<command>` in Freestyle jobs, triggering builds, fetching console output, and an **interactive shell mode** (`--shell`) for running commands repeatedly through Jenkins.

---

## ✨ Features

- **Pull job config** (`--pull-config`)
- **Push/update config** (`--push-config`)
  - Replace the job’s `<command>` with `--command`
- **Trigger builds** (`--build`)
  - Auto-uses `<authToken>` if present
  - Normalizes Jenkins URLs (avoids `localhost:8080` issues)
  - Fetches and prints console output
- **Interactive shell** (`--shell`)
  - Provides a prompt (`jenkins$`)
  - Each command replaces `<command>`, updates the job, triggers a build, and prints logs
  - Exit with `exit`, `quit`, or `Ctrl+C`
