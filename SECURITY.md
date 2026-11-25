# Security policy

## Supported versions

There is no release yet. Once there is, only the latest release gets security fixes: a fix comes in a new release, not as a patch to an older one. Builds from `main` aren't supported.

## Reporting a vulnerability

Please report vulnerabilities privately, and don't open a public issue. Use GitHub's private vulnerability reporting: [report a vulnerability](https://github.com/hibiscus-ctrl/infra-ontology/security/advisories/new) (the repository's **Security → Report a vulnerability**), or email [contact@infraweaver.io](mailto:contact@infraweaver.io).

Include the affected version or commit, how to reproduce the issue, and its impact.

## What happens next

- **Acknowledgement** within 5 working days.
- **Assessment** within 10 working days of that: whether it is a vulnerability, how severe, and what a fix involves. You hear the outcome either way.
- **A fix** in a new release, aimed at within 90 days of the report, sooner for a severe one. You're kept up to date until it ships.
- **Disclosure**: a GitHub security advisory, with a CVE where one applies, once the fix is released. You can agree a different date with us. Reporters are credited in the advisory unless they ask not to be.

## Scope

The tool's red lines are security properties, so a break of one is a vulnerability. In scope, for example:

- A secret value, or an attribute value, reaching a snapshot, the logs or an answer.
- The tool writing to a cloud, a Terraform state or a backend, or holding, printing or sending anyone's credentials.
- A read-only query, or an MCP tool, changing a file, running a statement outside the restricted dialect, or exceeding its row cap.
- A network call to anything but a backend the user named, or any telemetry.
- The release artifacts: their signatures, checksums or provenance.

Not in scope: vulnerabilities in Terraform, OpenTofu, DuckDB or the clouds themselves (report those to their maintainers), and what someone does with the answers a snapshot gives.
