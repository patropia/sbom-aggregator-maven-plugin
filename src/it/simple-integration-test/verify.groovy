import groovy.json.JsonSlurper

File targetDir = new File(basedir, "target")
File aggregatedBom = new File(targetDir, "aggregated-bom.json")

// 1. Validate that the output file was created successfully
assert aggregatedBom.exists() : "Aggregated SBOM file was not created at " + aggregatedBom.absolutePath

// 2. Parse JSON and verify contents
def jsonSlurper = new JsonSlurper()
def bom = jsonSlurper.parse(aggregatedBom)

assert bom.bomFormat == "CycloneDX" : "Expected bomFormat to be CycloneDX"
assert bom.components != null : "Components list should not be null"

// Verify that the base component from base-bom.json is present in the aggregated output
boolean foundBaseComponent = bom.components.any { it.name == "base-test-component" }
assert foundBaseComponent : "Aggregated BOM missing the base project's component"

println("SUCCESS: Integration test verified aggregated SBOM successfully!")