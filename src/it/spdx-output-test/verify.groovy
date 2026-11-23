import groovy.json.JsonSlurper

// generateSpdx=true must write an SPDX 2.3 JSON document next to the CycloneDX SBOM and attach it with
// classifier 'spdx'. A fixed outputTimestamp makes creationInfo.created reproducible.
File targetDir = new File(basedir, "target")
File cyclonedx = new File(targetDir, "aggregated-bom.json")
File spdxFile = new File(targetDir, "aggregated-bom.spdx.json")

assert cyclonedx.exists() : "The CycloneDX SBOM must still be written (${cyclonedx})"
assert spdxFile.exists() : "SPDX document was not created (${spdxFile})"

def doc = new JsonSlurper().parse(spdxFile)
assert doc.spdxVersion == "SPDX-2.3" : "Unexpected spdxVersion ${doc.spdxVersion}"
assert doc.dataLicense == "CC0-1.0" : "Unexpected dataLicense ${doc.dataLicense}"
assert doc.SPDXID == "SPDXRef-DOCUMENT" : "Unexpected SPDXID ${doc.SPDXID}"
assert doc.documentNamespace != null : "documentNamespace is required"
assert doc.creationInfo.created.startsWith("2024-01-01T00:00:00") :
    "created must come from outputTimestamp but was ${doc.creationInfo.created}"

assert doc.packages.size() == 3 : "Expected root + 2 components but got ${doc.packages*.name}"
doc.packages.each { p ->
    assert p.SPDXID != null && p.name != null : "Package without SPDXID/name: ${p}"
    assert p.downloadLocation != null : "Package ${p.name} has no downloadLocation"
    assert p.licenseDeclared != null : "Package ${p.name} has no licenseDeclared"
}

def describes = doc.relationships.findAll {
    it.spdxElementId == "SPDXRef-DOCUMENT" && it.relationshipType == "DESCRIBES"
}
assert describes.size() == 1 : "The document must DESCRIBE exactly one root package: ${doc.relationships}"
def root = doc.packages.find { it.SPDXID == describes[0].relatedSpdxElement }
assert root != null && root.name == "spdx-output-test" : "DESCRIBES must point at the root package, got ${root}"

String log = new File(basedir, "build.log").getText("UTF-8")
assert log.contains("SPDX 2.3 SBOM attached to project with classifier='spdx'") :
    "The SPDX document must be attached with classifier 'spdx'"

return true
