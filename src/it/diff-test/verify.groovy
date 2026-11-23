import groovy.json.JsonSlurper

File jsonReport = new File(basedir, "target/sbom-diff.json")
File mdReport = new File(basedir, "target/sbom-diff.md")
assert jsonReport.isFile() : "JSON diff report was not created at " + jsonReport.absolutePath
assert mdReport.isFile() : "Markdown diff report was not created at " + mdReport.absolutePath

def report = new JsonSlurper().parse(jsonReport)
def added = report.components.added.collect { it.name } as Set
def removed = report.components.removed.collect { it.name } as Set
def changed = report.components.changed

assert added.contains("safe-component") : "safe-component must be reported as added: ${report.components.added}"
assert removed.contains("removed-component") : "removed-component must be reported as removed: ${report.components.removed}"
def upgraded = changed.find { it.name == "vulnerable-component" }
assert upgraded != null : "vulnerable-component must be reported as changed: ${changed}"
assert upgraded.change == "upgraded"
assert upgraded.baselineVersion == "0.9.0"
assert upgraded.currentVersion == "1.0.0"
assert report.vulnerabilities.new.collect { it.id } == ["CVE-2099-0001"]
assert report.summary.newVulnerabilities == 1

String md = mdReport.getText("UTF-8")
assert md.contains("# SBOM diff")
assert md.contains("CVE-2099-0001")
assert md.contains("removed-component")

File log = new File(basedir, "build.log")
assert log.text.contains("New vulnerabilities compared to the baseline SBOM: CVE-2099-0001")
println("SUCCESS: SBOM diff reports contain the expected changes")
