import groovy.xml.XmlSlurper

File targetDir = new File(basedir, "target")
File aggregatedBom = new File(targetDir, "aggregated-bom.xml")

assert aggregatedBom.exists() : "Aggregated XML SBOM file was not created"

def bom = new XmlSlurper().parse(aggregatedBom)

assert bom.@version == "1"
assert bom.metadata.component.name.text() == "xml-format-test"
assert bom.metadata.component.@type == "application"

// Verify component from base XML SBOM
def components = bom.components.component
boolean foundXmlComponent = components.any { it.name.text() == "xml-test-component" }
assert foundXmlComponent : "Missing xml-test-component from base XML SBOM"

println("SUCCESS: XML format test verified - XML parsing and output working correctly")
