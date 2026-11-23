// Verify test setup before build
def basedir = basedir as File
def sbomFile = new File(basedir, "src/sbom/base-bom.json")

println "=========================================="
println "Pre-build setup for: ${basedir.name}"
println "Base directory: ${basedir.absolutePath}"
println "SBOM file path: ${sbomFile.absolutePath}"
println "SBOM file exists: ${sbomFile.exists()}"

if (sbomFile.exists()) {
    println "SBOM file size: ${sbomFile.length()} bytes"
    println "SBOM file content preview:"
    println sbomFile.text.take(200)
} else {
    println "ERROR: SBOM file does not exist!"
    println "Parent directory exists: ${sbomFile.parentFile.exists()}"
    if (sbomFile.parentFile.exists()) {
        println "Parent directory contents: ${sbomFile.parentFile.list()}"
    }
}
println "=========================================="

return true
