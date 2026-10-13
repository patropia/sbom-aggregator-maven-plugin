import groovy.json.JsonSlurper

File targetDir = new File(basedir, "target")
File aggregatedBom = new File(targetDir, "aggregated-bom.json")

assert aggregatedBom.exists() : "Aggregated SBOM file was not created"

def jsonSlurper = new JsonSlurper()
def bom = jsonSlurper.parse(aggregatedBom)

// Verify the output uses the requested spec version
assert bom.specVersion == "1.6" : "Expected specVersion 1.6 but got ${bom.specVersion}"

assert bom.bomFormat == "CycloneDX"
assert bom.components != null

boolean foundComponent = bom.components.any { it.name == "spec-version-component" }
assert foundComponent : "Missing component from base SBOM"

println("SUCCESS: Spec version test verified - output correctly uses CycloneDX 1.6")
