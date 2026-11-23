File log = new File(basedir, "build.log")
assert log.isFile()
String text = log.text
assert text.contains("New vulnerabilities compared to the baseline SBOM: CVE-2099-0001")
assert text.contains("failOnNewVulnerabilities=true")
// reports are written before the build fails so the failure can be investigated
assert new File(basedir, "target/sbom-diff.json").isFile()
println("SUCCESS: failOnNewVulnerabilities failed the build")
