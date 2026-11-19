import groovy.json.JsonSlurper

File targetDir = new File(basedir, "target")

def parse = { String fileName ->
    File f = new File(targetDir, fileName)
    assert f.exists() : "Aggregated SBOM file was not created: ${f.absolutePath}"
    return new JsonSlurper().parse(f)
}

def componentNames = { bom -> bom.components.collect { it.name } }

// ---------------------------------------------------------------- direct only
def direct = parse("transitive-direct.json")
assert direct.bomFormat == "CycloneDX"
assert direct.specVersion == "1.5"
assert direct.metadata.component.name == "transitive-dependency-test"

def directNames = componentNames(direct)
assert directNames.contains("internal-transitive-component") :
        "Missing base component from base SBOM, got ${directNames}"
assert directNames.contains("commons-text") :
        "Missing direct dependency commons-text, got ${directNames}"
assert !directNames.contains("commons-lang3") :
        "includeTransitive=false must not aggregate transitive dependency commons-lang3, got ${directNames}"

// ------------------------------------------------------------- with transitive
def all = parse("transitive-all.json")
def allNames = componentNames(all)
assert allNames.contains("commons-text") :
        "Missing direct dependency commons-text, got ${allNames}"
assert allNames.contains("commons-lang3") :
        "includeTransitive=true must aggregate transitive dependency commons-lang3, got ${allNames}"

def lang3 = all.components.find { it.name == "commons-lang3" }
assert lang3.version == "3.12.0" : "Unexpected commons-lang3 version: ${lang3.version}"

// no duplicates in the aggregated component list
assert allNames.size() == allNames.unique().size() :
        "Duplicate components in aggregated SBOM: ${allNames}"

// ------------------------------------------------------------------- excludes
def excluded = parse("transitive-excluded.json")
def excludedNames = componentNames(excluded)
assert excludedNames.contains("commons-text") :
        "Missing direct dependency commons-text, got ${excludedNames}"
assert !excludedNames.contains("commons-lang3") :
        "sbomAggregator.excludes must remove commons-lang3, got ${excludedNames}"

println("SUCCESS: Transitive dependency test verified - includeTransitive adds transitive dependencies, excludes removes them again")
return true
