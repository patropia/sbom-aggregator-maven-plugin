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
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.vulnerability.Vulnerability;
import org.cyclonedx.model.vulnerability.Vulnerability.Affect;
import org.cyclonedx.model.vulnerability.Vulnerability.Source;
import org.cyclonedx.model.vulnerability.Vulnerability.Version;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
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
 * </ul>
 *
 * <h2>Side effects</h2>
 * The {@link Component} instances of the input BOMs are modified in place: their {@code bom-ref}
 * is set to the final merged reference and their nested component list is cleared.
 */
public final class SbomMerger {

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
     * @param parsedBoms    upstream and project BOMs; may be {@code null}
     * @param missingDeps   dependencies without an attached SBOM; may be {@code null}
     * @return an aggregated BOM whose metadata component is the project
     */
    public static Bom merge(String rootGroupId,
                            String rootArtifactId,
                            String rootVersion,
                            List<Bom> parsedBoms,
                            List<MissingDependency> missingDeps) {
        return merge(rootGroupId, rootArtifactId, rootVersion, parsedBoms, missingDeps, null);
    }

    /**
     * Merges the given BOMs like {@link #merge(String, String, String, List, List)} and, when
     * {@code timestamp} is not {@code null}, stamps the merged BOM's metadata with it so that the
     * generated document is reproducible.
     *
     * @param timestamp metadata timestamp to use; {@code null} keeps the library default ("now")
     * @return an aggregated BOM whose metadata component is the project
     */
    public static Bom merge(String rootGroupId,
                            String rootArtifactId,
                            String rootVersion,
                            List<Bom> parsedBoms,
                            List<MissingDependency> missingDeps,
                            Date timestamp) {
        Objects.requireNonNull(rootGroupId, "rootGroupId must not be null");
        Objects.requireNonNull(rootArtifactId, "rootArtifactId must not be null");
        Objects.requireNonNull(rootVersion, "rootVersion must not be null");

        List<Bom> boms = parsedBoms == null ? new ArrayList<>() : parsedBoms;
        List<MissingDependency> missing = missingDeps == null ? new ArrayList<>() : missingDeps;

        String rootRef = String.format("pkg:maven/%s/%s@%s", rootGroupId, rootArtifactId, rootVersion);
        String rootGav = rootGroupId + ":" + rootArtifactId + ":" + rootVersion;

        Bom out = new Bom();
        Metadata metadata = new Metadata();
        metadata.setComponent(buildRoot(rootGroupId, rootArtifactId, rootVersion, rootRef));
        if (timestamp != null) {
            metadata.setTimestamp(timestamp);
        }
        out.setMetadata(metadata);

        State state = new State(rootRef, rootGav);

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

        // 6. vulnerabilities: rewrite affects refs per input BOM, de-duplicate and merge
        Map<String, Vulnerability> vulns = new LinkedHashMap<>();
        int anonCounter = 0;
        for (int i = 0; i < boms.size(); i++) {
            Bom bom = boms.get(i);
            Map<String, String> localMap = localMaps.get(i);
            List<Vulnerability> in = bom.getVulnerabilities();
            if (in == null) {
                continue;
            }
            for (Vulnerability v : in) {
                // rewrite affects
                List<Affect> affects = v.getAffects();
                List<Affect> newAffects = new ArrayList<>();
                if (affects != null) {
                    Map<String, Affect> byRef = new LinkedHashMap<>();
                    for (Affect a : affects) {
                        String resolved = state.resolve(a.getRef(), localMap);
                        if (resolved == null) {
                            continue; // drop dangling affect
                        }
                        Affect existing = byRef.get(resolved);
                        if (existing == null) {
                            Affect copy = new Affect();
                            copy.setRef(resolved);
                            if (a.getVersions() != null) {
                                copy.setVersions(new ArrayList<>(a.getVersions()));
                            }
                            byRef.put(resolved, copy);
                        } else {
                            // merge versions
                            mergeVersions(existing, a.getVersions());
                        }
                    }
                    newAffects.addAll(byRef.values());
                }
                if ((affects != null && newAffects.isEmpty())) {
                    // originally had affects but none survived -> drop this vulnerability
                    continue;
                }

                // dedupe vulnerabilities by id|source
                String id = v.getId();
                Source src = v.getSource();
                String sourceKey = src == null ? "" : (src.getName() == null ? (src.getUrl() == null ? "" : src.getUrl()) : src.getName());
                String key;
                if (isBlank(id)) {
                    anonCounter++;
                    key = "\u0000anon#" + anonCounter;
                } else {
                    key = id + "|" + sourceKey;
                }
                Vulnerability keeper = vulns.get(key);
                if (keeper == null) {
                    // make a shallow copy to avoid mutating input objects
                    Vulnerability copy = new Vulnerability();
                    copy.setId(v.getId());
                    copy.setBomRef(v.getBomRef());
                    copy.setSource(v.getSource());
                    copy.setDescription(v.getDescription());
                    copy.setRecommendation(v.getRecommendation());
                    copy.setDetail(v.getDetail());
                    copy.setAnalysis(v.getAnalysis());
                    if (v.getRatings() != null) copy.setRatings(new ArrayList<>(v.getRatings()));
                    if (v.getCwes() != null) copy.setCwes(new ArrayList<>(v.getCwes()));
                    if (v.getAdvisories() != null) copy.setAdvisories(new ArrayList<>(v.getAdvisories()));
                    if (v.getReferences() != null) copy.setReferences(new ArrayList<>(v.getReferences()));
                    if (v.getProperties() != null) copy.setProperties(new ArrayList<>(v.getProperties()));
                    copy.setAffects(newAffects.isEmpty() ? null : newAffects);

                    // ensure unique bom-ref
                    String bomRef = copy.getBomRef();
                    if (!isBlank(bomRef) && state.usedRefs.contains(bomRef)) {
                        // rename
                        String base = isBlank(copy.getId()) ? "vuln" : copy.getId();
                        String unique = base;
                        int counter = 2;
                        while (state.usedRefs.contains(unique)) {
                            unique = base + "#" + counter;
                            counter++;
                        }
                        copy.setBomRef(unique);
                    }
                    if (!isBlank(copy.getBomRef())) {
                        state.usedRefs.add(copy.getBomRef());
                    }

                    vulns.put(key, copy);
                } else {
                    // merge into keeper
                    if (keeper.getAffects() == null && !newAffects.isEmpty()) {
                        keeper.setAffects(new ArrayList<>());
                    }
                    if (!newAffects.isEmpty()) {
                        Map<String, Affect> existingByRef = new LinkedHashMap<>();
                        List<Affect> keeperAffects = keeper.getAffects();
                        if (keeperAffects == null) keeperAffects = new ArrayList<>();
                        for (Affect a : keeperAffects) {
                            existingByRef.put(a.getRef(), a);
                        }
                        for (Affect a : newAffects) {
                            Affect ex = existingByRef.get(a.getRef());
                            if (ex == null) {
                                keeper.getAffects().add(a);
                            } else {
                                mergeVersions(ex, a.getVersions());
                            }
                        }
                    }

                    // merge lists: ratings, cwes, advisories, references, properties
                    if (v.getRatings() != null) {
                        if (keeper.getRatings() == null) keeper.setRatings(new ArrayList<>());
                        for (var r : v.getRatings()) if (!keeper.getRatings().contains(r)) keeper.getRatings().add(r);
                    }
                    if (v.getCwes() != null) {
                        if (keeper.getCwes() == null) keeper.setCwes(new ArrayList<>());
                        for (var c : v.getCwes()) if (!keeper.getCwes().contains(c)) keeper.getCwes().add(c);
                    }
                    if (v.getAdvisories() != null) {
                        if (keeper.getAdvisories() == null) keeper.setAdvisories(new ArrayList<>());
                        for (var a : v.getAdvisories()) if (!keeper.getAdvisories().contains(a)) keeper.getAdvisories().add(a);
                    }
                    if (v.getReferences() != null) {
                        if (keeper.getReferences() == null) keeper.setReferences(new ArrayList<>());
                        for (var ref : v.getReferences()) if (!keeper.getReferences().contains(ref)) keeper.getReferences().add(ref);
                    }
                    if (v.getProperties() != null) {
                        if (keeper.getProperties() == null) keeper.setProperties(new ArrayList<>());
                        for (var p : v.getProperties()) if (!keeper.getProperties().contains(p)) keeper.getProperties().add(p);
                    }

                    // fill scalar gaps
                    if (keeper.getAnalysis() == null) keeper.setAnalysis(v.getAnalysis());
                    if (keeper.getDescription() == null) keeper.setDescription(v.getDescription());
                    if (keeper.getDetail() == null) keeper.setDetail(v.getDetail());
                    if (keeper.getRecommendation() == null) keeper.setRecommendation(v.getRecommendation());
                }
            }
        }

        out.setVulnerabilities(vulns.isEmpty() ? null : new ArrayList<>(vulns.values()));


        return out;
    }

    /**
     * Returns a deterministic serial number for the merged BOM. The returned value is a URN UUID
     * generated from a canonical byte representation built from the root purl, the sorted list
     * of component identifiers (purl or bom-ref) with their versions, and the sorted list of
     * dependency edges. This avoids including timestamps or input ordering in the serial.
     *
     * @param merged aggregated BOM
     * @return serial number like "urn:uuid:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" or null if merged is null
     */
    public static String deterministicSerialNumber(Bom merged) {
        if (merged == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder();
        Metadata metadata = merged.getMetadata();
        if (metadata != null && metadata.getComponent() != null) {
            String rootPurl = metadata.getComponent().getPurl();
            if (rootPurl != null) {
                sb.append("root:").append(rootPurl).append('\n');
            }
        }
        List<String> compKeys = new ArrayList<>();
        if (merged.getComponents() != null) {
            for (Component c : merged.getComponents()) {
                String id = c.getPurl() != null ? c.getPurl() : c.getBomRef();
                if (id == null) id = "";
                String ver = c.getVersion() != null ? c.getVersion() : "";
                compKeys.add(id + "|" + ver);
            }
        }
        Collections.sort(compKeys);
        for (String k : compKeys) {
            sb.append("comp:").append(k).append('\n');
        }
        List<String> edges = new ArrayList<>();
        if (merged.getDependencies() != null) {
            for (Dependency d : merged.getDependencies()) {
                if (d.getDependencies() != null) {
                    for (Dependency child : d.getDependencies()) {
                        String parent = d.getRef() == null ? "" : d.getRef();
                        String childRef = child.getRef() == null ? "" : child.getRef();
                        edges.add(parent + "->" + childRef);
                    }
                }
            }
        }
        Collections.sort(edges);
        for (String e : edges) {
            sb.append("edge:").append(e).append('\n');
        }
        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        UUID uuid = UUID.nameUUIDFromBytes(bytes);
        return "urn:uuid:" + uuid.toString();
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

        State(String rootRef, String rootGav) {
            this.rootRef = rootRef;
            this.rootGav = rootGav;
            usedRefs.add(rootRef);
            purlIndex.put(rootRef, rootRef);
            gavIndex.put(rootGav, rootRef);
        }

        /** Registers a component and returns the final bom-ref it was mapped to. */
        String register(Component component, Map<String, String> localMap) {
            String purl = component.getPurl();
            String gav = gavOf(component);
            String originalRef = component.getBomRef();

            String existing = null;
            if (!isBlank(purl)) {
                existing = purlIndex.get(purl);
            }
            if (existing == null && gav != null) {
                existing = gavIndex.get(gav);
            }
            if (existing == null && !isBlank(originalRef)) {
                existing = purlIndex.get(originalRef);
                if (existing == null) {
                    existing = gavIndex.get(originalRef);
                }
                if (existing == null && rootRef.equals(originalRef)) {
                    existing = rootRef;
                }
            }

            if (existing != null) {
                if (!rootRef.equals(existing)) {
                    Component survivor = merged.get(existing);
                    if (survivor != null) {
                        enrich(survivor, component);
                        index(survivor, existing);
                    }
                }
                if (!isBlank(originalRef)) {
                    localMap.put(originalRef, existing);
                }
                if (!isBlank(purl)) {
                    localMap.putIfAbsent(purl, existing);
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
            if (!isBlank(purl)) {
                localMap.putIfAbsent(purl, finalRef);
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
            String purl = String.format("pkg:maven/%s/%s@%s",
                    missingDependency.getGroupId(),
                    missingDependency.getArtifactId(),
                    missingDependency.getVersion());
            String gav = missingDependency.toString();

            String existing = purlIndex.get(purl);
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
            resolved = purlIndex.get(reference);
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
            return merged.containsKey(reference) ? reference : null;
        }

        private void index(Component component, String ref) {
            String purl = component.getPurl();
            if (!isBlank(purl)) {
                purlIndex.putIfAbsent(purl, ref);
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

        private void enrich(Component survivor, Component candidate) {
            if (survivor.getGroup() == null) {
                survivor.setGroup(candidate.getGroup());
            }
            if (survivor.getName() == null) {
                survivor.setName(candidate.getName());
            }
            if (survivor.getVersion() == null) {
                survivor.setVersion(candidate.getVersion());
            }
            if (survivor.getPurl() == null) {
                survivor.setPurl(candidate.getPurl());
            }
            if (survivor.getType() == null) {
                survivor.setType(candidate.getType());
            }
        }
    }
}
