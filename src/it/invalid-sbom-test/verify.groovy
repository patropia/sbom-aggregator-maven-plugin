// The project's own SBOM is corrupt (no bomFormat/specVersion, truncated JSON) so the aggregation
// must fail. The error must be actionable and must not echo the file content.
File buildLog = new File(basedir, "build.log")
assert buildLog.exists() : "build.log should exist"

String log = buildLog.text

assert log.contains("SBOM") :
    "Expected an SBOM related failure message in the build log"

// Every invalid-input path must fail with a message that identifies the offending file.
assert log.contains("invalid-bom.json") :
    "Expected the failure message to name the invalid SBOM file"

// Content or parser messages must never be echoed back into the build log.
assert !log.contains("SECRET-TOKEN-123") :
    "The build log must not leak the content of the invalid SBOM"

assert !new File(basedir, "target/aggregated-bom.json").exists() :
    "No aggregated SBOM must be written when the project SBOM is invalid"

println("SUCCESS: invalid SBOM fails the build without leaking file content")
