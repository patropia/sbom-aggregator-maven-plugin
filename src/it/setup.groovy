// Setup script to ensure test directories exist
import java.nio.file.Files
import java.nio.file.Paths

def basedir = basedir as File
def sbomDir = new File(basedir, "src/sbom")

// Ensure the sbom directory exists
if (!sbomDir.exists()) {
    println "Creating SBOM directory: ${sbomDir.absolutePath}"
    sbomDir.mkdirs()
}

println "Setup complete for: ${basedir.name}"
return true
