# Security Policy

## Supported versions

Only the latest released `1.x` line receives security fixes.

| Version | Supported |
| :--- | :--- |
| 1.1.x (latest release) | :white_check_mark: |
| 1.0.x | :x: |
| < 1.0 | :x: |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

* Preferred: use GitHub's private vulnerability reporting on
  <https://github.com/patropia/sbom-aggregator-maven-plugin/security/advisories/new>.
* Alternative: e-mail **patrick@patropia.nl** with the details.

Please include:

* the plugin version (`mvn help:evaluate -Dexpression=project.version` output or the version in your `pom.xml`),
* your Maven and Java versions (`mvn -v`),
* a description of the impact and the affected goal/parameter,
* a minimal reproduction (a `pom.xml` plus, if relevant, a trimmed SBOM input file).

You can expect an acknowledgement within 5 working days and a status update within 10 working days. Once a fix
is available we will publish a patched release and a GitHub security advisory, and credit the reporter unless
anonymity is requested.

## Scope

The plugin processes data that comes from outside the project being built: the CycloneDX SBOM artifacts that
dependencies publish, and the project's own base SBOM. This makes the following areas security-relevant:

* **Parsing of untrusted SBOM input** (JSON and XML). Malformed or hostile SBOMs must not be able to read local
  files, open network connections, exhaust memory, or execute code.
* **Supply-chain integrity** of the plugin's own dependencies. Vulnerabilities in those dependencies are tracked
  by Dependabot and CodeQL, which run on every pull request (see `.github/dependabot.yml` and
  `.github/workflows/codeql.yml`).
* **Credential handling during release**: signing and Central Portal credentials are only used by the
  `release` Maven profile and the tag-triggered workflow, never by the plugin itself.

Out of scope: vulnerabilities in Maven or the JDK itself, findings that require an already-compromised build
environment, and purely informational results about the *content* of a dependency's SBOM.

## Hardening

* Maven's own runtime, not the plugin, supplies the Maven core, plugin API and Maven Resolver classes; these are
  declared with `provided` scope so the plugin never shadows a patched Maven installation.
* Only CycloneDX spec versions `1.3` … `1.7` are accepted for output, and the output extension is restricted to
  `json` and `xml`.
