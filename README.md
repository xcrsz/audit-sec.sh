# audit-sec.sh

Audit and summarize package vulnerabilities on GhostBSD and FreeBSD in a way that is easy to act on. The script refreshes VuXML, parses `pkg audit`, and prints practical suggestions. It can show a compact one line view or a detailed report with links to advisories. ([GitHub][1])

## Features

* Refreshes VuXML and runs `pkg audit`
* Brief mode for quick, readable summaries
* Detailed mode with CVEs and advisory links
* Highlights unmaintained or end of life packages
* Shows whether a package is automatic or manual and whether anything depends on it
* Prints next steps such as update, remove, or monitor ([GitHub][1])

## Requirements

* GhostBSD or FreeBSD with `pkg` available
* Network access to update VuXML when needed ([GitHub][1])

## Install

```sh
# From the repo root
chmod +x audit-sec.sh
sudo mv audit-sec.sh /usr/local/bin/audit-sec
```

Or fetch directly

```sh
fetch -o /usr/local/bin/audit-sec.sh \
  https://raw.githubusercontent.com/xcrsz/audit-sec.sh/main/audit-sec.sh
sudo chmod +x /usr/local/bin/audit-sec.sh
sudo mv /usr/local/bin/audit-sec.sh /usr/local/bin/audit-sec
```

## Usage

```sh
audit-sec [OPTIONS]
```

Options

* `--brief`
  Compact one line summaries that are easier to scan. Recommended default for daily use.

* `--unmaintained-only`
  Show only items that are unmaintained or end of life.

* `--top-reqs N`
  In detailed mode, include up to N reverse dependencies for each package. Default is 20.

* `-h` or `--help`
  Show the built in help. ([GitHub][1])

## Examples

```sh
# Quick daily check
audit-sec --brief

# Focus only on unmaintained items
audit-sec --brief --unmaintained-only

# Full technical report with more dependent packages listed
audit-sec --top-reqs 50
```

## What the output means

### Brief mode

Each vulnerable package prints a single line like

```
ungoogled-chromium-140.0.7339.207 | Update available | manual install | shared by 3 packages
 → Suggestion: Run: sudo pkg upgrade ungoogled-chromium
```

Fields

* package and version
* action status such as Update available, No updates available, Newer than repo
* install type such as manual or automatic
* how widely it is required such as not used by other packages or shared by N packages
  Then a suggestion line with the recommended next step. ([GitHub][1])

### Detailed mode

Includes name, origin, installed version, repo version, status, reason, CVEs if present, advisory URL, action, suggestion, and a short list of dependents. ([GitHub][1])

## Exit codes

* Returns zero when there are no vulnerable packages and exits after saying so
* In other cases it currently returns zero as well and relies on the printed report for guidance
  You can wrap it in your own checks if you want a nonzero exit for CI. ([GitHub][1])

## Tips

* After applying updates, run

  ```sh
  sudo pkg update && sudo pkg upgrade
  audit-sec --brief
  ```

  This ensures the report reflects the current state. The script already refreshes VuXML as part of its run. ([GitHub][1])

## Troubleshooting

* If `pkg audit` fails due to network issues, run it again when connectivity is restored
* If you see no CVEs listed, check the advisory link and the reason field for context, since some VuXML entries do not enumerate CVE IDs ([GitHub][1])

## Contributing

Issues and pull requests are welcome. Please keep the brief output clear and consistent, since many users will rely on it for daily checks. ([GitHub][2])

## License

BSD 2 Clause License. See the `LICENSE` file. ([GitHub][2])

---

[1]: https://github.com/xcrsz/audit-sec.sh/raw/main/audit-sec.sh "raw.githubusercontent.com"
[2]: https://github.com/xcrsz/audit-sec.sh "GitHub - xcrsz/audit-sec.sh"
