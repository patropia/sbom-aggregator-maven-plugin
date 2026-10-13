// This test expects the build to FAIL because failOnMissingSbom=true
// and commons-io doesn't have an attached SBOM

File buildLog = new File(basedir, "build.log")
assert buildLog.exists() : "Build log should exist"

String logContent = buildLog.text

// Verify the failure message is present
assert logContent.contains("Build failed due to missing attached SBOMs") : 
    "Expected failure message about missing SBOMs not found in build log"

assert logContent.contains("commons-io:commons-io:2.11.0") : 
    "Expected missing dependency to be listed in failure message"

println("SUCCESS: Build correctly failed when failOnMissingSbom=true and SBOMs were missing")
