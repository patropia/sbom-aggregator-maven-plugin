// Verify test setup before build
def basedir = basedir as File
def sbomFile = new File(basedir, "src/sbom/base-bom.xml")

println "=========================================="
println "Pre-build setup for: ${basedir.name}"
println "Base directory: ${basedir.absolutePath}"
println "SBOM file path: ${sbomFile.absolutePath}"
println "SBOM file exists: ${sbomFile.exists()}"
println "=========================================="

return true
