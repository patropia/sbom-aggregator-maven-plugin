/*
 * Copyright 2026 Patrick Schulenberg
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package nl.patropia.maven.plugin;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.BomReference;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Composition;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.Property;
import org.cyclonedx.model.Service;
import org.cyclonedx.model.Tool;
import org.cyclonedx.model.metadata.ToolInformation;
import org.cyclonedx.model.vulnerability.Vulnerability;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.Locale;

import org.cyclonedx.model.Hash;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.OrganizationalEntity;

/**
 * Merges several CycloneDX {@link Bom}s into one aggregated BOM that describes the project
 * being built as its root component.
 *
 * <h2>Behaviour</h2>
 * <ul>
 *   <li><b>Root:</b> an {@code APPLICATION} component built from the supplied
 *       {@code groupId:artifactId:version}. Its {@code bom-ref} is its purl
 *       ({@code pkg:maven/groupId/artifactId@version}). The root is <em>only</em> placed in
 *       {@code metadata.component}, never in {@code components}.</li>
 *   <li><b>De-duplication:</b> a purl and a {@code group:name:version} key are global, so the same
 *       artifact found in two SBOMs is merged into one component. A {@code bom-ref} is only unique
 *       <em>within</em> a single SBOM, so bom-refs are tracked per input BOM and reused bom-ref
 *       strings in different SBOMs do not merge unrelated components.</li>
 *   <li><b>bom-refs:</b> a component keeps its own bom-ref unless another SBOM already used that
 *       string; in that case it gets its purl, failing which {@code name@version}. Every value in
 *       {@code dependencies[].ref} is one of these final bom-refs, the root purl, or a placeholder,
 *       so the graph never contains dangling references.</li>
 *   <li><b>Nested components:</b> nested components are hoisted to the top-level {@code components}
 *       list and removed from their parent, so every component is described exactly once. Their
 *       dependency entries are preserved.</li>
 *   <li><b>Root dependencies:</b> the root depends only on its direct dependencies: the
 *       {@code metadata.component} of every upstream SBOM plus one placeholder per missing
 *       dependency. When the project's own SBOM is among the inputs its children are used as the
 *       root's direct dependencies instead.</li>
 *   <li><b>Missing dependencies:</b> each {@link MissingDependency} without an upstream SBOM is
 *       emitted as a {@code LIBRARY} placeholder whose bom-ref and purl are
 *       {@code pkg:maven/groupId/artifactId@version}, and is wired as a child of the root.</li>
 *   <li><b>Dangling/self references:</b> references that cannot be resolved to a known component
 *       and self-loops are dropped.</li>
 *   <li><b>Document identity:</b> the aggregated BOM gets a fresh {@code urn:uuid} serial number, a
 *       {@code metadata.timestamp} and a {@code metadata.tools} entry describing this plugin. From
 *       spec 1.5 onwards the newer {@code tools.components} form is used, for 1.3 and 1.4 the
 *       legacy {@code tools[]} array.</li>
 *   <li><b>Placeholders:</b> every placeholder component carries the property
 *       {@code sbomAggregator:missingSbom=true}, so readers can tell that its data is incomplete.</li>
 * </ul>
 *
 * <h2>Side effects</h2>
 * The {@link Component} instances of the input BOMs are modified in place: their {@code bom-ref}
 * is set to the final merged reference and their nested component list is cleared.
 */
public final class SbomMerger {

    /** GroupId of this plugin, reported in {@code metadata.tools}. */
    public static final String PLUGIN_GROUP_ID = "nl.patropia.maven.plugin";

    /** ArtifactId of this plugin, reported in {@code metadata.tools}. */
    public static final String PLUGIN_ARTIFACT_ID = "sbom-aggregator-maven-plugin";

    /**
     * Property set on placeholder components (dependencies without an attached SBOM). Its value is
     * always {@code true}.
     */
    public static final String PROPERTY_MISSING_SBOM = "sbomAggregator:missingSbom";

    /** Spec minor version assumed when the requested spec version cannot be parsed. */
    private static final int FALLBACK_SPEC_MINOR = 3;

    /** First spec version that understands the {@code tools.components} form. */
    private static final int SPEC_MINOR_TOOLS_COMPONENTS = 5;

    /** First spec version that supports compositions. */
    private static final int SPEC_MINOR_COMPOSITIONS = 4;

    /** First spec version that supports the {@code vulnerabilities} section. */
    private static final int SPEC_MINOR_VULNERABILITIES = 4;

    /** Highest supported CycloneDX 1.x minor version. */
    private static final int MAX_SPEC_MINOR = 7;

    /** Lowest supported CycloneDX 1.x minor version. */
    private static final int MIN_SPEC_MINOR = 3;

    private SbomMerger() {
        // utility class
    }

    /**
     * A dependency of the project that has no attached SBOM. It is represented by a placeholder
     * component in the aggregated BOM.
     */
    public static final class MissingDependency {

        private final String groupId;
        private final String artifactId;
        private final String version;

        public MissingDependency(String groupId, String artifactId, String version) {
            this.groupId = groupId;
            this.artifactId = artifactId;
            this.version = version;
        }

        public String groupId() {
            return groupId;
        }

        public String artifactId() {
            return artifactId;
        }

        public String version() {
            return version;
        }

        public String getGroupId() {
            return groupId;
        }

        public String getArtifactId() {
            return artifactId;
        }

        public String getVersion() {
            return version;
        }

        /** @return the Maven coordinates as {@code groupId:artifactId:version}. */
        @Override
        public String toString() {
            return groupId + ":" + artifactId + ":" + version;
        }

        /** Parses {@code groupId:artifactId:version}; returns {@code null} when malformed. */
        public static MissingDependency parse(String coordinates) {
            if (coordinates == null) {
                return null;
            }
            String[] parts = coordinates.split(":");
            if (parts.length < 3 || parts[0].isEmpty() || parts[1].isEmpty() || parts[2].isEmpty()) {
                return null;
            }
            return new MissingDependency(parts[0], parts[1], parts[2]);
        }
    }

    /**
     * Merges the given BOMs into a single aggregated BOM.
     *
     * @param rootGroupId   groupId of the project being built
     * @param rootArtifactId artifactId of the project being built
     * @param rootVersion   version of the project being built
     * @param specVersion   targeted CycloneDX spec version, e.g. {@code 1.5}; when {@code null},
     *                      blank or unparsable the most conservative supported version is assumed
     *                      ({@code 1.3})
     * @param parsedBoms    upstream and project BOMs; may be {@code null}
     * @param missingDeps   dependencies without an attached SBOM; may be {@code null}
     * @return an aggregated BOM whose metadata component is the project
     */
    public static Bom merge(String rootGroupId,
                            String rootArtifactId,
                            String rootVersion,
                            String specVersion,
                            List<Bom> parsedBoms,
                            List<MissingDependency> missingDeps,
                            Instant outputTimestamp) {
        return merge(rootGroupId, rootArtifactId, rootVersion, specVersion, parsedBoms, missingDeps,
                outputTimestamp, true);
    }

    /**
     * Merges the given BOMs into a single aggregated BOM, optionally merging their
     * {@code vulnerabilities} sections.
     *
     * <p>When {@code includeVulnerabilities} is {@code true} and the targeted spec is 1.4 or newer,
     * the vulnerabilities of all input BOMs are merged: entries with the same {@code id} and
     * {@code source.name} are de-duplicated (their {@code affects} lists are unioned, ratings and
     * descriptions of the first occurrence are kept), every {@code affects[].ref} is rewritten to the
     * final bom-ref of the component it pointed at, references that resolve to nothing are dropped,
     * and a vulnerability left without any resolvable {@code affects} entry is dropped as well, because
     * it no longer describes anything in the aggregated BOM. The output is sorted by id, then source
     * name, and each {@code affects} list by ref.
     *
     * @see #merge(String, String, String, String, List, List, Instant)
     */
    public static Bom merge(String rootGroupId,
                            String rootArtifactId,
                            String rootVersion,
                            String specVersion,
                            List<Bom> parsedBoms,
                            List<MissingDependency> missingDeps,
                            Instant outputTimestamp,
                            boolean includeVulnerabilities) {
        Objects.requireNonNull(rootGroupId, "rootGroupId must not be null");
        Objects.requireNonNull(rootArtifactId, "rootArtifactId must not be null");
        Objects.requireNonNull(rootVersion, "rootVersion must not be null");

        List<Bom> boms = parsedBoms == null ? new ArrayList<>() : parsedBoms;
        List<MissingDependency> missing = missingDeps == null ? new ArrayList<>() : missingDeps;

        String rootRef = Purls.maven(rootGroupId, rootArtifactId, rootVersion, null, null);
        String rootGav = rootGroupId + ":" + rootArtifactId + ":" + rootVersion;
        int specMinor = specMinor(specVersion);

        Bom out = new Bom();

        Metadata metadata = new Metadata();
        if (outputTimestamp == null) {
            out.setSerialNumber("urn:uuid:" + UUID.randomUUID());
            metadata.setTimestamp(new Date());
        } else {
            metadata.setTimestamp(Date.from(outputTimestamp.truncatedTo(ChronoUnit.SECONDS)));
        }
        Component rootComponent = buildRoot(rootGroupId, rootArtifactId, rootVersion, rootRef);
        metadata.setComponent(rootComponent);
        addTooling(metadata, specMinor);
        out.setMetadata(metadata);

        State state = new State(rootRef, rootGav, rootComponent);

        // 1. collect and register components (project metadata component, components, nested ones)
        List<Map<String, String>> localMaps = new ArrayList<>();
        for (Bom bom : boms) {
            Map<String, String> localMap = new HashMap<>();
            localMaps.add(localMap);

            Component metaComponent = bom.getMetadata() == null ? null : bom.getMetadata().getComponent();
            if (metaComponent != null) {
                List<Component> flatMeta = flatten(metaComponent);
                for (Component component : flatMeta) {
                    state.register(component, localMap);
                }
            }
            if (bom.getComponents() != null) {
                List<Component> flat = new ArrayList<>();
                for (Component component : bom.getComponents()) {
                    flat.addAll(flatten(component));
                }
                for (Component component : flat) {
                    state.register(component, localMap);
                }
            }
            if (bom.getServices() != null) {
                List<Service> flatServices = new ArrayList<>();
                for (Service service : bom.getServices()) {
                    flatServices.addAll(flattenService(service));
                }
                for (Service service : flatServices) {
                    state.registerService(service, localMap);
                }
            }
        }

        // 2. placeholders for dependencies without an SBOM
        Set<String> placeholderRefs = new LinkedHashSet<>();
        for (MissingDependency missingDependency : missing) {
            String ref = state.registerPlaceholder(missingDependency);
            if (ref != null) {
                placeholderRefs.add(ref);
            }
        }

        // 3. translate each BOM's dependency graph through its own bom-ref map
        Map<String, Set<String>> graph = new LinkedHashMap<>();
        Set<String> ownBomChildren = new LinkedHashSet<>();
        Set<String> upstreamRoots = new LinkedHashSet<>();
        boolean sawOwnBom = false;

        for (int i = 0; i < boms.size(); i++) {
            Bom bom = boms.get(i);
            Map<String, String> localMap = localMaps.get(i);

            if (bom.getDependencies() != null) {
                for (Dependency dependency : bom.getDependencies()) {
                    String parent = state.resolve(dependency.getRef(), localMap);
                    if (parent == null) {
                        continue;
                    }
                    Set<String> children = graph.computeIfAbsent(parent, key -> new LinkedHashSet<>());
                    if (dependency.getDependencies() == null) {
                        continue;
                    }
                    for (Dependency child : dependency.getDependencies()) {
                        String childRef = state.resolve(child.getRef(), localMap);
                        if (childRef == null || childRef.equals(parent) || childRef.equals(rootRef)) {
                            continue;
                        }
                        children.add(childRef);
                    }
                }
            }

            Component metaComponent = bom.getMetadata() == null ? null : bom.getMetadata().getComponent();
            String metaRef = metaComponent == null ? null : state.resolve(metaComponent.getBomRef(), localMap);
            if (metaRef == null && metaComponent != null) {
                metaRef = state.resolve(metaComponent.getPurl(), localMap);
            }
            if (metaRef == null) {
                continue;
            }
            if (metaRef.equals(rootRef)) {
                sawOwnBom = true;
                ownBomChildren.addAll(graph.getOrDefault(rootRef, new LinkedHashSet<>()));
                enrichMetadata(out.getMetadata(), bom.getMetadata());
            } else {
                upstreamRoots.add(metaRef);
            }
        }

        // 4. wire the root to its direct dependencies only
        Set<String> rootChildren = new LinkedHashSet<>();
        if (sawOwnBom && !ownBomChildren.isEmpty()) {
            rootChildren.addAll(ownBomChildren);
        } else {
            rootChildren.addAll(upstreamRoots);
        }
        rootChildren.addAll(placeholderRefs);
        rootChildren.remove(rootRef);

        Set<String> rootEntry = new LinkedHashSet<>(rootChildren);
        graph.put(rootRef, rootEntry);

        // 5. emit dependencies: root first, then one entry per component/placeholder
        List<Dependency> dependencies = new ArrayList<>();
        List<String> orderedRefs = new ArrayList<>();
        orderedRefs.add(rootRef);
        orderedRefs.addAll(state.merged.keySet());
        orderedRefs.addAll(state.services.keySet());
        for (String ref : orderedRefs) {
            Dependency dependency = new Dependency(ref);
            Set<String> children = graph.get(ref);
            if (children != null && !children.isEmpty()) {
                List<Dependency> childDependencies = new ArrayList<>();
                for (String childRef : children) {
                    childDependencies.add(new Dependency(childRef));
                }
                dependency.setDependencies(childDependencies);
            }
            dependencies.add(dependency);
        }

        out.setComponents(new ArrayList<>(state.merged.values()));
        out.setDependencies(dependencies);
        if (!state.services.isEmpty()) {
            out.setServices(new ArrayList<>(state.services.values()));
        }
        if (specMinor >= SPEC_MINOR_COMPOSITIONS && !placeholderRefs.isEmpty()) {
            out.setCompositions(compositions(placeholderRefs, rootRef));
        }

        // 5. vulnerabilities, with affects[].ref translated through each BOM's own bom-ref map
        if (includeVulnerabilities && specMinor >= SPEC_MINOR_VULNERABILITIES) {
            List<Vulnerability> vulnerabilities = mergeVulnerabilities(boms, localMaps, state);
            if (!vulnerabilities.isEmpty()) {
                out.setVulnerabilities(vulnerabilities);
            }
        }

        // 6. reproducible document identity: a name-based UUID over the (stable) content of the BOM
        if (outputTimestamp != null) {
            out.setSerialNumber(deterministicSerial(rootRef, specVersion, outputTimestamp, state.merged.keySet()));
        }
        return out;
    }

    /**
     * Merges the vulnerabilities of all BOMs. See
     * {@link #merge(String, String, String, String, List, List, Instant, boolean)} for the rules.
     */
    private static List<Vulnerability> mergeVulnerabilities(List<Bom> boms,
                                                            List<Map<String, String>> localMaps,
                                                            State state) {
        Map<String, Vulnerability> byKey = new LinkedHashMap<>();
        Map<String, Map<String, Vulnerability.Affect>> affectsByKey = new HashMap<>();
        // bom-refs must be unique per document, so vulnerability refs are deduplicated against every ref already
        // taken by the root component, the components and the services
        Set<String> usedVulnerabilityRefs = new HashSet<>(state.usedRefs);
        usedVulnerabilityRefs.addAll(state.merged.keySet());
        usedVulnerabilityRefs.addAll(state.services.keySet());
        int anonymous = 0;
        for (int i = 0; i < boms.size(); i++) {
            List<Vulnerability> source = boms.get(i).getVulnerabilities();
            if (source == null) {
                continue;
            }
            Map<String, String> localMap = localMaps.get(i);
            for (Vulnerability vulnerability : source) {
                if (vulnerability == null) {
                    continue;
                }
                String key = isBlank(vulnerability.getId())
                        ? "\u0000anonymous-" + (anonymous++)
                        : vulnerability.getId() + "|" + sourceName(vulnerability);
                Vulnerability target = byKey.get(key);
                if (target == null) {
                    target = vulnerability;
                    target.setBomRef(uniqueVulnerabilityRef(target.getBomRef(), usedVulnerabilityRefs));
                    byKey.put(key, target);
                    affectsByKey.put(key, new LinkedHashMap<>());
                }
                Map<String, Vulnerability.Affect> affects = affectsByKey.get(key);
                if (vulnerability.getAffects() == null) {
                    continue;
                }
                for (Vulnerability.Affect affect : vulnerability.getAffects()) {
                    String ref = affect == null ? null : state.resolve(affect.getRef(), localMap);
                    if (ref == null) {
                        continue;
                    }
                    Vulnerability.Affect existing = affects.get(ref);
                    if (existing == null) {
                        Vulnerability.Affect copy = new Vulnerability.Affect();
                        copy.setRef(ref);
                        if (affect.getVersions() != null && !affect.getVersions().isEmpty()) {
                            copy.setVersions(new ArrayList<>(affect.getVersions()));
                        }
                        affects.put(ref, copy);
                    } else if (affect.getVersions() != null) {
                        if (existing.getVersions() == null) {
                            existing.setVersions(new ArrayList<>());
                        }
                        Set<String> seen = new HashSet<>();
                        for (Vulnerability.Version version : existing.getVersions()) {
                            seen.add(versionKey(version));
                        }
                        for (Vulnerability.Version version : affect.getVersions()) {
                            if (version != null && seen.add(versionKey(version))) {
                                existing.getVersions().add(version);
                            }
                        }
                    }
                }
            }
        }

        List<Vulnerability> result = new ArrayList<>();
        for (Map.Entry<String, Vulnerability> entry : byKey.entrySet()) {
            List<Vulnerability.Affect> affects = new ArrayList<>(affectsByKey.get(entry.getKey()).values());
            if (affects.isEmpty()) {
                continue;
            }
            affects.sort(Comparator.comparing(Vulnerability.Affect::getRef));
            Vulnerability vulnerability = entry.getValue();
            vulnerability.setAffects(affects);
            result.add(vulnerability);
        }
        result.sort(Comparator
                .comparing((Vulnerability v) -> v.getId() == null ? "" : v.getId())
                .thenComparing(SbomMerger::sourceName));
        return result;
    }

    /**
     * Returns a content-based key for a version entry. {@code Vulnerability.Version} does not implement
     * {@code equals}, so versions taken from different SBOMs are never equal by identity and have to be compared
     * field by field to keep the merged output free of repeated ranges.
     */
    private static String versionKey(Vulnerability.Version version) {
        if (version == null) {
            return "";
        }
        return (version.getVersion() == null ? "" : version.getVersion())
                + "|" + (version.getRange() == null ? "" : version.getRange())
                + "|" + (version.getStatus() == null ? "" : version.getStatus().name());
    }

    /**
     * Makes a vulnerability {@code bom-ref} unique within the merged document. Different SBOMs may use the same
     * bom-ref for different vulnerabilities; the first one keeps it and later ones get a {@code #n} suffix.
     */
    private static String uniqueVulnerabilityRef(String bomRef, Set<String> usedRefs) {
        if (isBlank(bomRef)) {
            return bomRef;
        }
        String unique = bomRef;
        int counter = 2;
        while (!usedRefs.add(unique)) {
            unique = bomRef + "#" + counter;
            counter++;
        }
        return unique;
    }

    private static String sourceName(Vulnerability vulnerability) {
        Vulnerability.Source source = vulnerability.getSource();
        return source == null || source.getName() == null ? "" : source.getName();
    }

    /**
     * Derives a stable {@code urn:uuid} serial number from the root coordinates, the targeted spec version, the
     * output timestamp and the sorted bom-refs of the merged components. Same inputs therefore yield the same serial
     * number, while a changed dependency set yields a different one.
     */
    static String deterministicSerial(String rootRef, String specVersion, Instant outputTimestamp,
                                      Set<String> componentRefs) {
        StringBuilder seed = new StringBuilder();
        seed.append(rootRef).append('|')
                .append(specVersion == null ? "" : specVersion.trim()).append('|')
                .append(outputTimestamp.truncatedTo(ChronoUnit.SECONDS).getEpochSecond()).append('\n');
        for (String ref : new java.util.TreeSet<>(componentRefs)) {
            seed.append(ref).append('\n');
        }
        return "urn:uuid:" + UUID.nameUUIDFromBytes(seed.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Returns the CycloneDX {@code 1.x} minor version of the given spec version. Unparsable values
     * fall back to the oldest supported version, so no unsupported construct is ever emitted.
     */
    static int specMinor(String specVersion) {
        if (isBlank(specVersion)) {
            return FALLBACK_SPEC_MINOR;
        }
        String trimmed = specVersion.trim();
        if (!trimmed.startsWith("1.")) {
            return FALLBACK_SPEC_MINOR;
        }
        try {
            int minor = Integer.parseInt(trimmed.substring(2));
            if (minor < MIN_SPEC_MINOR || minor > MAX_SPEC_MINOR) {
                return FALLBACK_SPEC_MINOR;
            }
            return minor;
        } catch (NumberFormatException e) {
            return FALLBACK_SPEC_MINOR;
        }
    }

    /** Records this plugin in {@code metadata.tools}, using the model the spec version supports. */
    static void addTooling(Metadata metadata, int specMinor) {
        String version = pluginVersion();
        if (specMinor >= SPEC_MINOR_TOOLS_COMPONENTS) {
            Component tool = new Component();
            tool.setType(Component.Type.APPLICATION);
            tool.setGroup(PLUGIN_GROUP_ID);
            tool.setName(PLUGIN_ARTIFACT_ID);
            tool.setVersion(version);
            List<Component> tools = new ArrayList<>();
            tools.add(tool);
            ToolInformation toolInformation = new ToolInformation();
            toolInformation.setComponents(tools);
            metadata.setToolChoice(toolInformation);
        } else {
            Tool tool = new Tool();
            tool.setVendor(PLUGIN_GROUP_ID);
            tool.setName(PLUGIN_ARTIFACT_ID);
            tool.setVersion(version);
            metadata.addTool(tool);
        }
    }

    /** @return the plugin version when running from a packaged jar, otherwise {@code unknown}. */
    static String pluginVersion() {
        Package pluginPackage = SbomMerger.class.getPackage();
        String version = pluginPackage == null ? null : pluginPackage.getImplementationVersion();
        return isBlank(version) ? "unknown" : version;
    }

    private static Component buildRoot(String groupId, String artifactId, String version, String purl) {
        Component root = new Component();
        root.setType(Component.Type.APPLICATION);
        root.setGroup(groupId);
        root.setName(artifactId);
        root.setVersion(version);
        root.setPurl(purl);
        root.setBomRef(purl);
        return root;
    }

    /**
     * Returns the component and all of its nested components as a flat list and clears the nested
     * lists so that every component is emitted exactly once.
     */
    private static List<Component> flatten(Component component) {
        List<Component> flat = new ArrayList<>();
        flat.add(component);
        List<Component> nested = component.getComponents();
        if (nested != null && !nested.isEmpty()) {
            component.setComponents(null);
            for (Component child : nested) {
                flat.addAll(flatten(child));
            }
        }
        return flat;
    }

    /**
     * Returns the service and all of its nested services as a flat list and clears the nested
     * lists so that every service is emitted exactly once.
     */
    private static List<Service> flattenService(Service service) {
        List<Service> flat = new ArrayList<>();
        flat.add(service);
        List<Service> nested = service.getServices();
        if (nested != null && !nested.isEmpty()) {
            service.setServices(null);
            for (Service child : nested) {
                flat.addAll(flattenService(child));
            }
        }
        return flat;
    }

    /**
     * Describes how complete the aggregated inventory is. Emitted from spec 1.4 onwards only, and only
     * when at least one dependency had no SBOM: the placeholder references are reported as
     * {@code UNKNOWN} (their dependency graph is unknown) and the root as {@code INCOMPLETE}.
     */
    static List<Composition> compositions(Set<String> placeholderRefs, String rootRef) {
        List<Composition> compositions = new ArrayList<>();
        Composition unknown = new Composition();
        unknown.setAggregate(Composition.Aggregate.UNKNOWN);
        List<BomReference> unknownDependencies = new ArrayList<>();
        for (String ref : placeholderRefs) {
            unknownDependencies.add(new BomReference(ref));
        }
        unknown.setDependencies(unknownDependencies);
        compositions.add(unknown);

        Composition incomplete = new Composition();
        incomplete.setAggregate(Composition.Aggregate.INCOMPLETE);
        List<BomReference> assemblies = new ArrayList<>();
        assemblies.add(new BomReference(rootRef));
        incomplete.setAssemblies(assemblies);
        compositions.add(incomplete);
        return compositions;
    }

    /**
     * Copies descriptive document metadata (licenses, supplier, manufacturer) from an input BOM that
     * describes the project itself, without overwriting values the aggregated BOM already has.
     */
    static void enrichMetadata(Metadata target, Metadata source) {
        if (target == null || source == null) {
            return;
        }
        if (target.getLicenses() == null && source.getLicenses() != null) {
            target.setLicenses(source.getLicenses());
        }
        if (target.getSupplier() == null && source.getSupplier() != null) {
            target.setSupplier(source.getSupplier());
        }
        if (target.getManufacturer() == null && source.getManufacturer() != null) {
            target.setManufacturer(source.getManufacturer());
        }
    }

    /**
     * Returns the union of two external reference lists, keeping the first occurrence of each
     * {@code type|url} pair so that the result is deterministic and free of duplicates.
     */
    static List<ExternalReference> unionExternalReferences(List<ExternalReference> first,
                                                           List<ExternalReference> second) {
        if (second == null || second.isEmpty()) {
            return first;
        }
        if (first == null || first.isEmpty()) {
            return new ArrayList<>(second);
        }
        Map<String, ExternalReference> seen = new LinkedHashMap<>();
        for (ExternalReference reference : first) {
            if (reference != null && reference.getType() != null && reference.getUrl() != null) {
                seen.put(reference.getType() + "|" + reference.getUrl(), reference);
            }
        }
        for (ExternalReference reference : second) {
            if (reference != null && reference.getType() != null && reference.getUrl() != null) {
                seen.putIfAbsent(reference.getType() + "|" + reference.getUrl(), reference);
            }
        }
        return new ArrayList<>(seen.values());
    }

    private static String gavOf(Component component) {
        if (component == null
                || component.getGroup() == null
                || component.getName() == null
                || component.getVersion() == null) {
            return null;
        }
        return component.getGroup() + ":" + component.getName() + ":" + component.getVersion();
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    /** Mutable merge state: global indexes plus the final bom-ref bookkeeping. */
    private static final class State {

        private final String rootRef;
        private final String rootGav;
        private final Map<String, Component> merged = new LinkedHashMap<>();
        private final Map<String, String> purlIndex = new HashMap<>();
        private final Map<String, String> gavIndex = new HashMap<>();
        private final Set<String> usedRefs = new HashSet<>();
        private final Map<String, Service> services = new LinkedHashMap<>();
        private final Map<String, String> serviceRefIndex = new HashMap<>();
        private final Map<String, String> serviceGavIndex = new HashMap<>();
        private final Component rootComponent;

        State(String rootRef, String rootGav, Component rootComponent) {
            this.rootRef = rootRef;
            this.rootGav = rootGav;
            this.rootComponent = rootComponent;
            usedRefs.add(rootRef);
            purlIndex.put(Purls.matchKey(rootRef), rootRef);
            gavIndex.put(rootGav, rootRef);
        }

        /** Registers a component and returns the final bom-ref it was mapped to. */
        String register(Component component, Map<String, String> localMap) {
            String purl = component.getPurl();
            if (isBlank(component.getGroup())) {
                // Scanners (Syft, Trivy) often omit the group for jars; the Maven purl namespace is the groupId.
                String groupId = Purls.mavenGroupId(purl);
                if (!isBlank(groupId)) {
                    component.setGroup(groupId);
                }
            }
            String purlKey = Purls.canonicalKey(purl);
            String gav = gavOf(component);
            String originalRef = component.getBomRef();

            String existing = null;
            if (purlKey != null) {
                existing = purlIndex.get(purlKey);
            }
            if (existing == null && gav != null) {
                existing = gavIndex.get(gav);
            }
            if (existing == null && !isBlank(originalRef)) {
                existing = purlIndex.get(Purls.matchKey(originalRef));
                if (existing == null) {
                    existing = gavIndex.get(originalRef);
                }
                if (existing == null && rootRef.equals(originalRef)) {
                    existing = rootRef;
                }
            }

            if (existing != null) {
                Component survivor = merged.get(existing);
                if (survivor != null) {
                    // Enrich the survivor with descriptive/fingerprint data from the candidate.
                    enrich(survivor, component);
                    index(survivor, existing);
                } else if (rootRef.equals(existing)) {
                    // The project's own metadata component: the root keeps its identity (group, name,
                    // version, purl, bom-ref), but picks up description, licenses, supplier, hashes
                    // and external references from the input BOM.
                    enrich(rootComponent, component);
                }
                if (!isBlank(originalRef)) {
                    localMap.put(originalRef, existing);
                }
                if (purlKey != null) {
                    localMap.putIfAbsent(purlKey, existing);
                }
                return existing;
            }

            String finalRef = chooseRef(component, purl);
            component.setBomRef(finalRef);
            merged.put(finalRef, component);
            usedRefs.add(finalRef);
            index(component, finalRef);
            if (!isBlank(originalRef)) {
                localMap.put(originalRef, finalRef);
            }
            if (purlKey != null) {
                localMap.putIfAbsent(purlKey, finalRef);
            }
            localMap.putIfAbsent(finalRef, finalRef);
            return finalRef;
        }

        /** Adds a placeholder component for a dependency without an SBOM and returns its bom-ref. */
        String registerPlaceholder(MissingDependency missingDependency) {
            if (missingDependency == null
                    || isBlank(missingDependency.getGroupId())
                    || isBlank(missingDependency.getArtifactId())
                    || isBlank(missingDependency.getVersion())) {
                return null;
            }
            String purl = Purls.maven(missingDependency.getGroupId(),
                    missingDependency.getArtifactId(),
                    missingDependency.getVersion(), null, null);
            String gav = missingDependency.toString();

            String existing = purlIndex.get(Purls.matchKey(purl));
            if (existing == null) {
                existing = gavIndex.get(gav);
            }
            if (existing != null) {
                return existing;
            }

            Component placeholder = new Component();
            placeholder.setType(Component.Type.LIBRARY);
            placeholder.setGroup(missingDependency.getGroupId());
            placeholder.setName(missingDependency.getArtifactId());
            placeholder.setVersion(missingDependency.getVersion());
            placeholder.setPurl(purl);
            placeholder.setBomRef(purl);
            List<Property> properties = new ArrayList<>();
            properties.add(new Property(PROPERTY_MISSING_SBOM, "true"));
            placeholder.setProperties(properties);

            merged.put(purl, placeholder);
            usedRefs.add(purl);
            index(placeholder, purl);
            return purl;
        }

        /**
         * Resolves a reference found in a BOM to the final bom-ref, or {@code null} when the
         * reference points at nothing.
         */
        String resolve(String reference, Map<String, String> localMap) {
            if (isBlank(reference)) {
                return null;
            }
            String resolved = localMap.get(reference);
            if (resolved != null) {
                return resolved;
            }
            String key = Purls.matchKey(reference);
            resolved = localMap.get(key);
            if (resolved != null) {
                return resolved;
            }
            resolved = purlIndex.get(key);
            if (resolved != null) {
                return resolved;
            }
            resolved = gavIndex.get(reference);
            if (resolved != null) {
                return resolved;
            }
            if (rootRef.equals(reference)) {
                return rootRef;
            }
            if (merged.containsKey(reference) || services.containsKey(reference)) {
                return reference;
            }
            return null;
        }

        /**
         * Registers a service and returns the final bom-ref it was mapped to. Services share the
         * bom-ref namespace with components, so a colliding reference is renamed.
         */
        String registerService(Service service, Map<String, String> localMap) {
            if (service == null) {
                return null;
            }
            String originalRef = service.getBomRef();
            String gav = serviceGavOf(service);

            String existing = null;
            if (!isBlank(originalRef)) {
                existing = serviceRefIndex.get(originalRef);
            }
            if (existing == null && gav != null) {
                existing = serviceGavIndex.get(gav);
            }
            if (existing != null) {
                Service survivor = services.get(existing);
                if (survivor != null) {
                    if (isBlank(survivor.getDescription()) && !isBlank(service.getDescription())) {
                        survivor.setDescription(service.getDescription());
                    }
                    survivor.setExternalReferences(unionExternalReferences(
                            survivor.getExternalReferences(), service.getExternalReferences()));
                }
                mapService(localMap, originalRef, existing, gav);
                return existing;
            }

            String finalRef = originalRef;
            if (isBlank(finalRef) || usedRefs.contains(finalRef)) {
                String base = isBlank(service.getName()) ? "service" : service.getName();
                if (!isBlank(service.getVersion())) {
                    base = base + "@" + service.getVersion();
                }
                finalRef = base;
                int counter = 2;
                while (usedRefs.contains(finalRef)) {
                    finalRef = base + "#" + counter;
                    counter++;
                }
            }
            service.setBomRef(finalRef);
            services.put(finalRef, service);
            usedRefs.add(finalRef);
            serviceRefIndex.put(finalRef, finalRef);
            if (gav != null) {
                serviceGavIndex.putIfAbsent(gav, finalRef);
            }
            mapService(localMap, originalRef, finalRef, gav);
            return finalRef;
        }

        private void mapService(Map<String, String> localMap, String originalRef, String finalRef, String gav) {
            if (localMap != null) {
                if (!isBlank(originalRef)) {
                    localMap.put(originalRef, finalRef);
                }
                if (gav != null) {
                    localMap.putIfAbsent(gav, finalRef);
                }
                localMap.putIfAbsent(finalRef, finalRef);
            }
            if (!isBlank(originalRef)) {
                serviceRefIndex.put(originalRef, finalRef);
            }
        }

        private static String serviceGavOf(Service service) {
            if (isBlank(service.getGroup()) || isBlank(service.getName()) || isBlank(service.getVersion())) {
                return null;
            }
            return service.getGroup() + ":" + service.getName() + ":" + service.getVersion();
        }

        private void index(Component component, String ref) {
            String purlKey = Purls.canonicalKey(component.getPurl());
            if (purlKey != null) {
                purlIndex.putIfAbsent(purlKey, ref);
            }
            String gav = gavOf(component);
            if (gav != null) {
                gavIndex.putIfAbsent(gav, ref);
            }
        }

        private String chooseRef(Component component, String purl) {
            String candidate = component.getBomRef();
            if (!isBlank(candidate) && !usedRefs.contains(candidate)) {
                return candidate;
            }
            if (!isBlank(purl) && !usedRefs.contains(purl)) {
                return purl;
            }
            String base = (isBlank(component.getName()) ? "component" : component.getName())
                    + (isBlank(component.getVersion()) ? "" : "@" + component.getVersion());
            String unique = base;
            int counter = 2;
            while (usedRefs.contains(unique)) {
                unique = base + "#" + counter;
                counter++;
            }
            return unique;
        }

        private boolean licenseChoiceEmpty(LicenseChoice lc) {
            if (lc == null) return true;
            List<License> list = lc.getLicenses();
            org.cyclonedx.model.license.Expression expr = lc.getExpression();
            return (list == null || list.isEmpty()) && (expr == null || isBlank(expr.getValue()));
        }

        private void enrich(Component survivor, Component candidate) {
            // For non-root components, fill missing identity fields from the candidate when absent.
            if (survivor != null && survivor != this.rootComponent) {
                if (isBlank(survivor.getGroup()) && candidate.getGroup() != null) {
                    survivor.setGroup(candidate.getGroup());
                }
                if (isBlank(survivor.getName()) && candidate.getName() != null) {
                    survivor.setName(candidate.getName());
                }
                if (isBlank(survivor.getVersion()) && candidate.getVersion() != null) {
                    survivor.setVersion(candidate.getVersion());
                }
                if (isBlank(survivor.getPurl()) && candidate.getPurl() != null) {
                    survivor.setPurl(candidate.getPurl());
                }
                if (survivor.getType() == null && candidate.getType() != null) {
                    survivor.setType(candidate.getType());
                }
            }

            // descriptive and fingerprint fields only
            if (survivor.getDescription() == null && candidate.getDescription() != null) {
                survivor.setDescription(candidate.getDescription());
            }

            // supplier: OrganizationalEntity
            if ((survivor.getSupplier() == null || isBlank(survivor.getSupplier().getName())) && candidate.getSupplier() != null) {
                survivor.setSupplier(candidate.getSupplier());
            }

            // author is a String
            if (survivor.getAuthor() == null && candidate.getAuthor() != null) {
                survivor.setAuthor(candidate.getAuthor());
            }

            // licenses: org.cyclonedx.model.LicenseChoice
            if (licenseChoiceEmpty(survivor.getLicenses())) {
                if (!licenseChoiceEmpty(candidate.getLicenses())) {
                    survivor.setLicenses(candidate.getLicenses());
                }
            } else {
                // survivor has licenses; do not merge or override
            }

            // union hashes by algorithm:value(lowercase)
            List<Hash> sHashes = survivor.getHashes();
            List<Hash> cHashes = candidate.getHashes();
            if ((sHashes == null || sHashes.isEmpty()) && (cHashes != null && !cHashes.isEmpty())) {
                survivor.setHashes(new ArrayList<>(cHashes));
            } else if (cHashes != null && !cHashes.isEmpty()) {
                Map<String, Hash> seen = new LinkedHashMap<>();
                if (sHashes != null) {
                    for (Hash h : sHashes) {
                        if (h != null && h.getAlgorithm() != null && h.getValue() != null) {
                            seen.put(h.getAlgorithm() + ":" + h.getValue().toLowerCase(Locale.ROOT), h);
                        }
                    }
                }
                for (Hash h : cHashes) {
                    if (h != null && h.getAlgorithm() != null && h.getValue() != null) {
                        seen.putIfAbsent(h.getAlgorithm() + ":" + h.getValue().toLowerCase(Locale.ROOT), h);
                    }
                }
                survivor.setHashes(new ArrayList<>(seen.values()));
            }

            // union externalReferences by type|url
            List<ExternalReference> sRefs = survivor.getExternalReferences();
            List<ExternalReference> cRefs = candidate.getExternalReferences();
            if ((sRefs == null || sRefs.isEmpty()) && (cRefs != null && !cRefs.isEmpty())) {
                survivor.setExternalReferences(new ArrayList<>(cRefs));
            } else if (cRefs != null && !cRefs.isEmpty()) {
                Map<String, ExternalReference> seen = new LinkedHashMap<>();
                if (sRefs != null) {
                    for (ExternalReference r : sRefs) {
                        if (r != null && r.getType() != null && r.getUrl() != null) {
                            seen.put(r.getType() + "|" + r.getUrl(), r);
                        }
                    }
                }
                for (ExternalReference r : cRefs) {
                    if (r != null && r.getType() != null && r.getUrl() != null) {
                        seen.putIfAbsent(r.getType() + "|" + r.getUrl(), r);
                    }
                }
                survivor.setExternalReferences(new ArrayList<>(seen.values()));
            }

            // do NOT merge properties to avoid overwriting the placeholder marker
        }
    }
}
