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

import nl.patropia.maven.plugin.SbomDiffReport.ChangeType;
import nl.patropia.maven.plugin.SbomDiffReport.ComponentChange;
import nl.patropia.maven.plugin.SbomDiffReport.VulnerabilityChange;
import org.apache.maven.artifact.versioning.ComparableVersion;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.vulnerability.Vulnerability;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * Computes the difference between two CycloneDX SBOMs (a baseline and a current one). Pure logic without Maven or
 * I/O dependencies, in the same style as {@link SbomMerger}.
 *
 * <p>Component matching:</p>
 * <ul>
 *   <li>Components are flattened (nested components included); the root component in {@code metadata.component}
 *   is not compared, because its version changes on every release.</li>
 *   <li>The identity key is the purl with its version removed (qualifiers and subpath kept, so different
 *   classifiers stay distinct). Without a purl the key is {@code group:name}; without a name the bom-ref is
 *   used. Components with none of these are ignored.</li>
 *   <li>When a key has exactly one version on each side and the versions differ, the component is reported as
 *   {@link ChangeType#UPGRADED}, {@link ChangeType#DOWNGRADED} (Maven version ordering) or
 *   {@link ChangeType#CHANGED} when one side has no version. When a key has several versions on either side,
 *   each version present on one side only is reported as added or removed.</li>
 * </ul>
 *
 * <p>Vulnerabilities are matched by {@code id} and {@code source.name}, the same key {@link SbomMerger} uses to
 * merge them. Vulnerabilities without an id are ignored.</p>
 *
 * <p>Component changes are sorted by {@code group:name}, then key, then version; vulnerabilities by id, then
 * source. All result lists are sorted, so the report is deterministic regardless of the input order.</p>
 */
final class SbomDiff {

    private static final Comparator<ComponentChange> BY_KEY_THEN_VERSION = Comparator
            .comparing(ComponentChange::getDisplayName)
            .thenComparing(ComponentChange::getKey)
            .thenComparing(c -> nullToEmpty(c.getBaselineVersion()))
            .thenComparing(c -> nullToEmpty(c.getCurrentVersion()));

    private static final Comparator<VulnerabilityChange> BY_ID_THEN_SOURCE = Comparator
            .comparing(VulnerabilityChange::getId)
            .thenComparing(VulnerabilityChange::getSource);

    /** Severity names from most to least severe; the first match among the ratings wins. */
    private static final List<Vulnerability.Rating.Severity> SEVERITY_ORDER = List.of(
            Vulnerability.Rating.Severity.CRITICAL,
            Vulnerability.Rating.Severity.HIGH,
            Vulnerability.Rating.Severity.MEDIUM,
            Vulnerability.Rating.Severity.LOW,
            Vulnerability.Rating.Severity.INFO,
            Vulnerability.Rating.Severity.NONE,
            Vulnerability.Rating.Severity.UNKNOWN);

    private SbomDiff() {
    }

    /**
     * Compares two SBOMs.
     *
     * @param baseline the older SBOM, must not be {@code null}
     * @param current  the newer SBOM, must not be {@code null}
     * @return the deterministic diff report
     */
    static SbomDiffReport diff(Bom baseline, Bom current) {
        Objects.requireNonNull(baseline, "baseline");
        Objects.requireNonNull(current, "current");

        Map<String, Entry> before = index(baseline);
        Map<String, Entry> after = index(current);

        List<ComponentChange> added = new ArrayList<>();
        List<ComponentChange> removed = new ArrayList<>();
        List<ComponentChange> changed = new ArrayList<>();
        int unchanged = 0;

        Set<String> keys = new TreeSet<>(before.keySet());
        keys.addAll(after.keySet());
        for (String key : keys) {
            Entry b = before.get(key);
            Entry a = after.get(key);
            if (b == null) {
                for (String v : a.versions) {
                    added.add(new ComponentChange(key, a.group, a.name, null, emptyToNull(v), ChangeType.ADDED));
                }
            } else if (a == null) {
                for (String v : b.versions) {
                    removed.add(new ComponentChange(key, b.group, b.name, emptyToNull(v), null, ChangeType.REMOVED));
                }
            } else if (b.versions.equals(a.versions)) {
                unchanged++;
            } else if (b.versions.size() == 1 && a.versions.size() == 1) {
                String bv = b.versions.first();
                String av = a.versions.first();
                changed.add(new ComponentChange(key, a.group, a.name, emptyToNull(bv), emptyToNull(av),
                        classify(bv, av)));
            } else {
                for (String v : a.versions) {
                    if (!b.versions.contains(v)) {
                        added.add(new ComponentChange(key, a.group, a.name, null, emptyToNull(v), ChangeType.ADDED));
                    }
                }
                for (String v : b.versions) {
                    if (!a.versions.contains(v)) {
                        removed.add(new ComponentChange(key, b.group, b.name, emptyToNull(v), null,
                                ChangeType.REMOVED));
                    }
                }
            }
        }
        added.sort(BY_KEY_THEN_VERSION);
        removed.sort(BY_KEY_THEN_VERSION);
        changed.sort(BY_KEY_THEN_VERSION);

        Map<String, VulnerabilityChange> vulnsBefore = vulnerabilities(baseline);
        Map<String, VulnerabilityChange> vulnsAfter = vulnerabilities(current);
        List<VulnerabilityChange> newVulns = new ArrayList<>();
        List<VulnerabilityChange> resolvedVulns = new ArrayList<>();
        for (Map.Entry<String, VulnerabilityChange> e : vulnsAfter.entrySet()) {
            if (!vulnsBefore.containsKey(e.getKey())) {
                newVulns.add(e.getValue());
            }
        }
        for (Map.Entry<String, VulnerabilityChange> e : vulnsBefore.entrySet()) {
            if (!vulnsAfter.containsKey(e.getKey())) {
                resolvedVulns.add(e.getValue());
            }
        }
        newVulns.sort(BY_ID_THEN_SOURCE);
        resolvedVulns.sort(BY_ID_THEN_SOURCE);

        return new SbomDiffReport(added, removed, changed, newVulns, resolvedVulns, unchanged);
    }

    /** Classifies a version change of a component present once on each side; inputs are never equal. */
    static ChangeType classify(String baselineVersion, String currentVersion) {
        if (baselineVersion.isEmpty() || currentVersion.isEmpty()) {
            return ChangeType.CHANGED;
        }
        int cmp = new ComparableVersion(currentVersion).compareTo(new ComparableVersion(baselineVersion));
        if (cmp > 0) {
            return ChangeType.UPGRADED;
        }
        if (cmp < 0) {
            return ChangeType.DOWNGRADED;
        }
        // equivalent per Maven ordering but textually different, e.g. "1.0" vs "1.0.0"
        return ChangeType.CHANGED;
    }

    /**
     * Identity key of a component: the purl without version, else {@code group:name}, else {@code ref:<bom-ref>}.
     * Returns {@code null} when the component cannot be identified.
     */
    static String identityKey(Component component) {
        String purl = trimToNull(component.getPurl());
        if (purl != null) {
            return stripPurlVersion(purl);
        }
        String name = trimToNull(component.getName());
        if (name != null) {
            String group = trimToNull(component.getGroup());
            return group == null ? name : group + ":" + name;
        }
        String ref = trimToNull(component.getBomRef());
        return ref == null ? null : "ref:" + ref;
    }

    /**
     * Removes the {@code @version} part of a purl while keeping qualifiers ({@code ?...}) and subpath
     * ({@code #...}). Purls without a version are returned unchanged.
     */
    static String stripPurlVersion(String purl) {
        int end = purl.length();
        int hash = purl.indexOf('#');
        if (hash >= 0) {
            end = hash;
        }
        int query = purl.indexOf('?');
        if (query >= 0 && query < end) {
            end = query;
        }
        int at = purl.lastIndexOf('@', end - 1);
        // an '@' before the last '/' belongs to the namespace (e.g. a percent-decoded npm scope), not the version
        int slash = purl.lastIndexOf('/', end - 1);
        if (at < 0 || at < slash) {
            return purl;
        }
        return purl.substring(0, at) + purl.substring(end);
    }

    /** Flattens all components (excluding the metadata root) into key -> versions. */
    private static Map<String, Entry> index(Bom bom) {
        Map<String, Entry> result = new HashMap<>();
        for (Component component : flatten(bom.getComponents())) {
            String key = identityKey(component);
            if (key == null) {
                continue;
            }
            Entry entry = result.computeIfAbsent(key, k -> new Entry());
            if (entry.name == null) {
                entry.group = trimToNull(component.getGroup());
                entry.name = trimToNull(component.getName());
            }
            entry.versions.add(nullToEmpty(trimToNull(component.getVersion())));
        }
        return result;
    }

    private static List<Component> flatten(List<Component> roots) {
        List<Component> result = new ArrayList<>();
        if (roots == null) {
            return result;
        }
        Deque<Component> stack = new ArrayDeque<>();
        for (int i = roots.size() - 1; i >= 0; i--) {
            if (roots.get(i) != null) {
                stack.push(roots.get(i));
            }
        }
        while (!stack.isEmpty()) {
            Component c = stack.pop();
            result.add(c);
            List<Component> children = c.getComponents();
            if (children != null) {
                for (int i = children.size() - 1; i >= 0; i--) {
                    if (children.get(i) != null) {
                        stack.push(children.get(i));
                    }
                }
            }
        }
        return result;
    }

    /** Collects the vulnerabilities of a BOM keyed by {@code id|source}. Later duplicates add their affects. */
    private static Map<String, VulnerabilityChange> vulnerabilities(Bom bom) {
        Map<String, VulnerabilityChange> result = new TreeMap<>();
        List<Vulnerability> list = bom.getVulnerabilities();
        if (list == null) {
            return result;
        }
        Map<String, String> refLabels = refLabels(bom);
        Map<String, Set<String>> affects = new HashMap<>();
        Map<String, Integer> severities = new HashMap<>();
        Map<String, String[]> idAndSource = new HashMap<>();
        for (Vulnerability v : list) {
            if (v == null || trimToNull(v.getId()) == null) {
                continue;
            }
            String source = v.getSource() == null || v.getSource().getName() == null ? "" : v.getSource().getName();
            String key = v.getId() + "|" + source;
            idAndSource.putIfAbsent(key, new String[] {v.getId(), source});
            Set<String> refs = affects.computeIfAbsent(key, k -> new TreeSet<>());
            if (v.getAffects() != null) {
                for (Vulnerability.Affect affect : v.getAffects()) {
                    if (affect != null && trimToNull(affect.getRef()) != null) {
                        refs.add(refLabels.getOrDefault(affect.getRef(), affect.getRef()));
                    }
                }
            }
            severities.merge(key, severityRank(v), Math::min);
        }
        for (Map.Entry<String, String[]> e : idAndSource.entrySet()) {
            String key = e.getKey();
            String severity = SEVERITY_ORDER.get(severities.get(key)).getSeverityName();
            result.put(key, new VulnerabilityChange(e.getValue()[0], e.getValue()[1], severity,
                    new ArrayList<>(affects.get(key))));
        }
        return result;
    }

    /** Index into {@link #SEVERITY_ORDER} of the highest rated severity; {@code unknown} without ratings. */
    private static int severityRank(Vulnerability v) {
        int best = SEVERITY_ORDER.size() - 1;
        if (v.getRatings() != null) {
            for (Vulnerability.Rating rating : v.getRatings()) {
                if (rating != null && rating.getSeverity() != null) {
                    int rank = SEVERITY_ORDER.indexOf(rating.getSeverity());
                    if (rank >= 0 && rank < best) {
                        best = rank;
                    }
                }
            }
        }
        return best;
    }

    /** Maps bom-refs (root included) to a readable label: purl, else {@code group:name@version}. */
    private static Map<String, String> refLabels(Bom bom) {
        Map<String, String> labels = new HashMap<>();
        List<Component> all = new ArrayList<>();
        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            all.add(bom.getMetadata().getComponent());
        }
        all.addAll(flatten(bom.getComponents()));
        for (Component c : all) {
            String ref = trimToNull(c.getBomRef());
            if (ref == null || labels.containsKey(ref)) {
                continue;
            }
            String label = trimToNull(c.getPurl());
            if (label == null && trimToNull(c.getName()) != null) {
                String group = trimToNull(c.getGroup());
                String version = trimToNull(c.getVersion());
                label = (group == null ? "" : group + ":") + c.getName().trim() + (version == null ? "" : "@" + version);
            }
            if (label != null) {
                labels.put(ref, label);
            }
        }
        return labels;
    }

    private static String trimToNull(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String emptyToNull(String s) {
        return s == null || s.isEmpty() ? null : s;
    }

    /** Aggregated view of all components sharing one identity key. */
    private static final class Entry {
        private String group;
        private String name;
        private final TreeSet<String> versions = new TreeSet<>();
    }
}
