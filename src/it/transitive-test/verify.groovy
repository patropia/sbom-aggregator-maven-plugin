import groovy.json.JsonSlurper

File targetDir = new File(basedir, "target")
File aggregatedBom = new File(targetDir, "aggregated-bom.json")
File buildLog = new File(basedir, "build.log")

assert aggregatedBom.exists() : "Aggregated SBOM file was not created"

def jsonSlurper = new JsonSlurper()
def bom = jsonSlurper.parse(aggregatedBom)

assert bom.bomFormat == "CycloneDX"
assert bom.specVersion == "1.5"

// Verify root component metadata
assert bom.metadata != null
assert bom.metadata.component.name == "transitive-test"

// Verify components include base component
boolean foundInternal = bom.components.any { it.name == "internal-component" }
assert foundInternal : "Missing internal component from base SBOM"

// Verify markers from lib-a and lib-b are present
boolean foundA = bom.components.any { it.name == "marker-from-lib-a" }
boolean foundB = bom.components.any { it.name == "marker-from-lib-b" }
assert foundA : "Missing marker-from-lib-a"
assert foundB : "Missing marker-from-lib-b"

// Verify placeholder for lib-c exists (missing SBOM)
boolean foundLibC = bom.components.any { it.purl == "pkg:maven/it.transitive/lib-c@1.0.0" }
assert foundLibC : "Missing placeholder component for it.transitive:lib-c:1.0.0"

// Verify excluded and test-scoped artifacts are absent
boolean foundX = bom.components.any { it.name == "marker-from-lib-x" }
assert !foundX : "Excluded artifact lib-x should not be present"

boolean foundXPurl = bom.components.any { it.purl?.contains("it.transitive.excluded") }
assert !foundXPurl : "Excluded group it.transitive.excluded must not appear in any purl"

boolean foundT = bom.components.any { it.name == "marker-from-lib-t" }
assert !foundT : "Test-scoped artifact lib-t should not be present"

boolean foundTPurl = bom.components.any { it.purl?.contains("/lib-t@") }
assert !foundTPurl : "Test-scoped artifact lib-t must not appear in any purl"

// The dependency graph must be populated, not empty
assert bom.dependencies : "bom.dependencies must not be empty"

// Check build.log for missing SBOM mention
assert buildLog.exists() : "build.log not found"
String logText = buildLog.text
assert logText.contains("MISSING SBOM") : "Missing SBOM log line not found in build.log"
assert logText.contains("it.transitive:lib-c:1.0.0") : "Missing SBOM log line not mentioning lib-c"

println("SUCCESS: Transitive test verified - markers and placeholders present as expected")
return true
