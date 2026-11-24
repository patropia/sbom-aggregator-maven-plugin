import groovy.json.JsonSlurper

File targetDir = new File(basedir, "target")
File aggregatedBom = new File(targetDir, "aggregated-bom.json")

assert aggregatedBom.exists() : "Aggregated SBOM file was not created"

def jsonSlurper = new JsonSlurper()
def bom = jsonSlurper.parse(aggregatedBom)

assert bom.bomFormat == "CycloneDX"
assert bom.specVersion == "1.7"

// Verify root component metadata
assert bom.metadata != null
assert bom.metadata.component.name == "multi-dependency-test"

// Verify components include base component
boolean foundInternal = bom.components.any { it.name == "internal-component" }
assert foundInternal : "Missing internal component from base SBOM"

// Verify fallback components were created for dependencies without SBOMs
boolean foundCommonsIo = bom.components.any { 
    it.name == "commons-io" && it.version == "2.11.0" 
}
boolean foundCommonsLang = bom.components.any { 
    it.name == "commons-lang3" && it.version == "3.12.0" 
}

assert foundCommonsIo : "Missing fallback component for commons-io"
assert foundCommonsLang : "Missing fallback component for commons-lang3"

// Verify dependency tree exists
assert bom.dependencies != null
assert !bom.dependencies.isEmpty()

println("SUCCESS: Multi-dependency test verified - fallback components created for missing SBOMs")
