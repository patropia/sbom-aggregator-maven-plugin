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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Immutable result of {@link SbomDiff#diff}. All lists are sorted deterministically, so two runs over the same input
 * produce the same report. The report holds plain strings only; rendering (JSON, Markdown) is left to the caller.
 */
final class SbomDiffReport {

    /** Kind of change of a single component between the baseline and the current SBOM. */
    enum ChangeType {
        /** Present in the current SBOM only. */
        ADDED,
        /** Present in the baseline SBOM only. */
        REMOVED,
        /** Present in both, the current version is higher. */
        UPGRADED,
        /** Present in both, the current version is lower. */
        DOWNGRADED,
        /** Present in both with different versions that cannot be ordered (e.g. one side has no version). */
        CHANGED
    }

    /** A component that was added, removed or changed version. */
    static final class ComponentChange {
        private final String key;
        private final String group;
        private final String name;
        private final String baselineVersion;
        private final String currentVersion;
        private final ChangeType type;

        ComponentChange(String key, String group, String name, String baselineVersion, String currentVersion,
                        ChangeType type) {
            this.key = Objects.requireNonNull(key, "key");
            this.group = group;
            this.name = name;
            this.baselineVersion = baselineVersion;
            this.currentVersion = currentVersion;
            this.type = Objects.requireNonNull(type, "type");
        }

        /** Identity used for matching: the purl without its version, else {@code group:name}. */
        String getKey() { return key; }

        String getGroup() { return group; }

        String getName() { return name; }

        /** Version in the baseline SBOM, {@code null} for {@link ChangeType#ADDED}. */
        String getBaselineVersion() { return baselineVersion; }

        /** Version in the current SBOM, {@code null} for {@link ChangeType#REMOVED}. */
        String getCurrentVersion() { return currentVersion; }

        ChangeType getType() { return type; }

        /** {@code group:name}, or just {@code name} when there is no group. */
        String getDisplayName() {
            String n = name == null ? key : name;
            return group == null || group.isEmpty() ? n : group + ":" + n;
        }

        @Override
        public String toString() {
            return type + " " + getDisplayName() + " " + baselineVersion + " -> " + currentVersion;
        }
    }

    /** A vulnerability that is new in, or no longer present in, the current SBOM. */
    static final class VulnerabilityChange {
        private final String id;
        private final String source;
        private final String severity;
        private final List<String> affects;

        VulnerabilityChange(String id, String source, String severity, List<String> affects) {
            this.id = Objects.requireNonNull(id, "id");
            this.source = source == null ? "" : source;
            this.severity = severity == null ? "unknown" : severity;
            this.affects = Collections.unmodifiableList(new ArrayList<>(affects));
        }

        String getId() { return id; }

        /** Source name (e.g. {@code NVD}), empty when the SBOM does not name one. */
        String getSource() { return source; }

        /** Highest severity among the ratings, lower case ({@code critical} ... {@code unknown}). */
        String getSeverity() { return severity; }

        /** Affected components, as purl or {@code group:name@version} where resolvable, else the raw ref. */
        List<String> getAffects() { return affects; }

        @Override
        public String toString() {
            return id + (source.isEmpty() ? "" : " (" + source + ")") + " " + severity + " " + affects;
        }
    }

    private final List<ComponentChange> added;
    private final List<ComponentChange> removed;
    private final List<ComponentChange> changed;
    private final List<VulnerabilityChange> newVulnerabilities;
    private final List<VulnerabilityChange> resolvedVulnerabilities;
    private final int unchangedCount;

    SbomDiffReport(List<ComponentChange> added, List<ComponentChange> removed, List<ComponentChange> changed,
                   List<VulnerabilityChange> newVulnerabilities, List<VulnerabilityChange> resolvedVulnerabilities,
                   int unchangedCount) {
        this.added = Collections.unmodifiableList(new ArrayList<>(added));
        this.removed = Collections.unmodifiableList(new ArrayList<>(removed));
        this.changed = Collections.unmodifiableList(new ArrayList<>(changed));
        this.newVulnerabilities = Collections.unmodifiableList(new ArrayList<>(newVulnerabilities));
        this.resolvedVulnerabilities = Collections.unmodifiableList(new ArrayList<>(resolvedVulnerabilities));
        this.unchangedCount = unchangedCount;
    }

    /** Components only in the current SBOM, sorted by {@code group:name}, key, then version. */
    List<ComponentChange> getAddedComponents() { return added; }

    /** Components only in the baseline SBOM, sorted by {@code group:name}, key, then version. */
    List<ComponentChange> getRemovedComponents() { return removed; }

    /** Components in both SBOMs with a different version, sorted by {@code group:name} then key. */
    List<ComponentChange> getChangedComponents() { return changed; }

    /** Vulnerabilities (by id and source) only in the current SBOM, sorted by id then source. */
    List<VulnerabilityChange> getNewVulnerabilities() { return newVulnerabilities; }

    /** Vulnerabilities (by id and source) only in the baseline SBOM, sorted by id then source. */
    List<VulnerabilityChange> getResolvedVulnerabilities() { return resolvedVulnerabilities; }

    /** Number of component identities present in both SBOMs with the same version(s). */
    int getUnchangedCount() { return unchangedCount; }

    /** True when any component or vulnerability differs. */
    boolean hasChanges() {
        return !added.isEmpty() || !removed.isEmpty() || !changed.isEmpty()
                || !newVulnerabilities.isEmpty() || !resolvedVulnerabilities.isEmpty();
    }
}
