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

### 🚀 Usage

All modes require:
```
--url    Base URL of Jenkins server (e.g. http://10.10.11.132:8080)
--job    Jenkins job name
--user   Jenkins username
--token  Jenkins API token
--file   Path to config.xml (used for pull, push, or shell mode)
```

Pull Job Config
```
jenkinsshell --url http://10.10.11.132:8080 \
  --job TestJob --user ha1ks --token <api_token> \
  --pull-config --file config.xml
```

Push Job Config
```
jenkinsshell --url http://10.10.11.132:8080 \
  --job TestJob --user ha1ks --token <api_token> \
  --push-config --file config.xml
```

Replace <command> automatically before upload:
```
jenkinsshell --url http://10.10.11.132:8080 \
  --job TestJob --user ha1ks --token <api_token> \
  --push-config --file config.xml --command "whoami"
```
Push + Build
```
jenkinsshell --url http://10.10.11.132:8080 \
  --job TestJob --user ha1ks --token <api_token> \
  --push-config --file config.xml --command "ipconfig /all" --build
```
Build Only
```
jenkinsshell --url http://10.10.11.132:8080 \
  --job TestJob --user ha1ks --token <api_token> \
  --build
```

Interactive Shell
```
jenkinsshell --url http://10.10.11.132:8080 \
  --job TestJob --user ha1ks --token <api_token> \
  --file config.xml --shell
```

Example session:
```
jenkins$ whoami
========== JOB OUTPUT ==========
nt authority\system
================================
jenkins$ ipconfig
... output ...
jenkins$ exit
[*] Bye.
```

(written for the Object box on htb)
