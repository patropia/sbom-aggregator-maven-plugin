import groovy.json.JsonSlurper

File targetDir = new File(basedir, "target")
File aggregatedBom = new File(targetDir, "aggregated-bom.json")

assert aggregatedBom.exists() : "Aggregated SBOM file was not created"

def bom = new JsonSlurper().parse(aggregatedBom)

assert bom.bomFormat == "CycloneDX"
assert bom.specVersion == "1.7"
assert bom.metadata?.component?.name == "transitive-disabled-test"

// Base SBOM component is kept
assert bom.components.any { it.name == "internal-component" } : "Missing internal component from base SBOM"

// The direct dependency lib-a is still aggregated
assert bom.components.any { it.name == "marker-from-lib-a" } : "Missing marker-from-lib-a (direct dependency)"

// With includeTransitive=false nothing from lib-b (transitive), lib-c (transitive) or lib-x must appear
assert !bom.components.any { it.name == "marker-from-lib-b" } : "Transitive marker-from-lib-b must not be present when includeTransitive=false"
assert !bom.components.any { it.purl?.contains("/lib-b@") } : "Transitive lib-b must not appear in any purl when includeTransitive=false"
assert !bom.components.any { it.purl == "pkg:maven/it.transitive/lib-c@1.0.0" } : "Transitive placeholder for lib-c must not be present when includeTransitive=false"
assert !bom.components.any { it.purl?.contains("it.transitive.excluded") } : "Excluded group must not appear in any purl"

// Test-scoped dependency lib-t is filtered out by the default scope filter
assert !bom.components.any { it.name == "marker-from-lib-t" } : "Test-scoped artifact lib-t should not be present"

// No transitive dependency should have produced a MISSING SBOM warning
File buildLog = new File(basedir, "build.log")
assert buildLog.exists() : "build.log not found"
assert !buildLog.text.contains("MISSING SBOM") : "No MISSING SBOM warning expected when only direct dependencies are collected"

println("SUCCESS: transitive resolution disabled - only direct dependency SBOMs were aggregated")
return true
