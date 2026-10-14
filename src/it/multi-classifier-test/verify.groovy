// Verify that the aggregated SBOM was created
def aggregatedBom = new File(basedir, "target/aggregated-bom.json")
assert aggregatedBom.exists() : "Aggregated SBOM file should exist"
assert aggregatedBom.length() > 0 : "Aggregated SBOM file should not be empty"

println "✓ Multi-classifier test passed: aggregated SBOM created successfully"
return true
