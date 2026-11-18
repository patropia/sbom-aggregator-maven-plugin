package nl.patropia.maven.plugin;

import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.Metadata;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

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
        return out;
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
