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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.Dependency;
import org.cyclonedx.model.ExternalReference;
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.License;
import org.cyclonedx.model.LicenseChoice;
import org.cyclonedx.model.LicenseItem;
import org.cyclonedx.model.Metadata;
import org.cyclonedx.model.OrganizationalEntity;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Converts a CycloneDX {@link Bom} into an SPDX 2.3 JSON document.
 *
 * <p>Pure logic without Maven or I/O dependencies, in the same style as {@link SbomMerger} and
 * {@link SbomDiff}: the converter takes a parsed BOM and returns the SPDX document as a nested
 * {@code Map}, which {@link #toJson(Bom, Instant)} renders with Jackson.</p>
 *
 * <h2>Mapping</h2>
 * <ul>
 *   <li><b>Packages:</b> every component becomes an SPDX package, including nested components, which
 *       are hoisted to the flat {@code packages} list. The root component
 *       ({@code metadata.component}) becomes a package as well and is described by the document
 *       ({@code SPDXRef-DOCUMENT DESCRIBES <root>}).</li>
 *   <li><b>SPDX ids:</b> the {@code SPDXRef-*} ids are derived from the bom-ref, falling back to the
 *       purl, then {@code group:name@version}, then {@code name@version}. Every character outside
 *       {@code [A-Za-z0-9.-]} becomes {@code '-'}, so the id is always valid; clashes get a
 *       {@code -2}, {@code -3}, ... suffix in document order, so the result is deterministic.</li>
 *   <li><b>Relationships:</b> {@code metadata.component} is {@code DESCRIBES}d by the document, nested
 *       components add {@code CONTAINS}, and each CycloneDX dependency entry becomes
 *       {@code DEPENDS_ON}. An edge whose target carries the merger's
 *       {@code sbomAggregator:inferredDependency=true} property becomes {@code CONTAINS} instead: the merger
 *       only added it because a scanner found the component inside that artifact (for example an rpm inside
 *       a container image), which is containment rather than a declared dependency. Self loops and
 *       references to unknown components are dropped. CycloneDX {@code compositions} have no SPDX 2.3
 *       counterpart and are not represented.</li>
 *   <li><b>External references:</b> the purl becomes a {@code PACKAGE-MANAGER}/{@code purl} reference and
 *       the CPE a {@code SECURITY}/{@code cpe23Type} or {@code cpe22Type} reference. The
 *       {@code downloadLocation} uses a {@code distribution} (or {@code source-distribution}, then
 *       {@code website}) reference, else {@code NOASSERTION}.</li>
 *   <li><b>Checksums:</b> CycloneDX hashes are mapped to SPDX checksum algorithms where SPDX defines
 *       them ({@code SHA-256} becomes {@code SHA256}, ...). Hashes whose algorithm has no SPDX
 *       counterpart (for example Streebog) are dropped.</li>
 *   <li><b>Licenses:</b> the first {@code licenses} entry becomes {@code licenseDeclared}: an SPDX id or
 *       expression is copied, a license known only by name becomes {@code LicenseRef-<name>} and is
 *       listed under {@code hasExtractedLicensingInfos}. Without licensing information,
 *       {@code licenseDeclared} and {@code licenseConcluded} are {@code NOASSERTION}.</li>
 * </ul>
 *
 * <h2>Information loss</h2>
 * SPDX 2.3 has no place for CycloneDX vulnerabilities, services, compositions, pedigree or evidence:
 * they are not part of the generated document.
 *
 * <h2>Reproducibility</h2>
 * Passing a fixed {@link Instant} (Maven's {@code project.build.outputTimestamp}) produces a
 * byte-identical document: {@code creationInfo.created} and {@code documentNamespace} are both derived
 * from it (the namespace also hashes the generated packages and relationships) and nothing else in the
 * document varies between runs. When {@code created} is {@code null}
 * the BOM's {@code metadata.timestamp} is used, falling back to the current time.
 */
final class SpdxConverter {

    /** SPDX specification version of the generated document. */
    static final String SPDX_VERSION = "SPDX-2.3";

    /** SPDX data license of the generated document, as required by the specification. */
    static final String DATA_LICENSE = "CC0-1.0";

    /** SPDX id of the generated document. */
    static final String DOCUMENT_ID = "SPDXRef-DOCUMENT";

    /** SPDX value for "no assertion is made". */
    static final String NOASSERTION = "NOASSERTION";

    /** Creator entry describing this plugin. */
    static final String CREATOR = "Tool: " + SbomMerger.PLUGIN_ARTIFACT_ID;

    /** Comment recorded in {@code creationInfo} to explain the lossy mapping. */
    static final String CREATION_COMMENT =
            "Converted from a CycloneDX SBOM by " + SbomMerger.PLUGIN_ARTIFACT_ID
                    + "; CycloneDX vulnerabilities, services and compositions are not represented";

    /** Document name used when the BOM has neither a root component name nor a purl. */
    private static final String FALLBACK_NAME = "sbom";

    /** Prefix every SPDX element id must carry. */
    private static final String ID_PREFIX = "SPDXRef-";

    /** Namespace prefix for the generated document. */
    private static final String NAMESPACE_PREFIX = "https://spdx.org/spdxdocs/";

    private static final int NAMESPACE_HASH_LENGTH = 16;

    private static final DateTimeFormatter CREATED_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT).withZone(ZoneOffset.UTC);

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    private SpdxConverter() {
        // utility class
    }

    /**
     * Converts the BOM into an SPDX 2.3 JSON string, deriving the creation timestamp from the BOM.
     *
     * @param bom the parsed CycloneDX BOM
     * @return the SPDX document as indented JSON
     */
    static String toJson(Bom bom) {
        return toJson(bom, null);
    }

    /**
     * Converts the BOM into an SPDX 2.3 JSON string.
     *
     * @param bom     the parsed CycloneDX BOM
     * @param created fixed creation timestamp, or {@code null} to use the BOM's {@code metadata.timestamp}
     *                or the current time
     * @return the SPDX document as indented JSON
     */
    static String toJson(Bom bom, Instant created) {
        try {
            return MAPPER.writeValueAsString(toSpdx(bom, created));
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to render the SPDX JSON document: " + e.getMessage(), e);
        }
    }

    /**
     * Converts the BOM into a nested map following the SPDX 2.3 JSON schema key order.
     *
     * @param bom     the parsed CycloneDX BOM
     * @param created fixed creation timestamp, or {@code null} to use the BOM's {@code metadata.timestamp}
     *                or the current time
     * @return the SPDX document
     */
    static Map<String, Object> toSpdx(Bom bom, Instant created) {
        if (bom == null) {
            throw new IllegalArgumentException("bom must not be null");
        }
        Builder builder = new Builder();
        Component root = rootComponent(bom);
        String rootId = root == null ? null : builder.addComponent(root, null);

        if (bom.getComponents() != null) {
            for (Component component : bom.getComponents()) {
                if (component == null) {
                    continue;
                }
                if (root != null && component.getBomRef() != null
                        && component.getBomRef().equals(root.getBomRef())) {
                    // the BOM also lists its own root in components; it is already emitted
                    continue;
                }
                builder.addComponent(component, null);
            }
        }
        builder.addDependencies(bom.getDependencies(), rootId);

        String name = documentName(root);
        Instant timestamp = created != null ? created : bomTimestamp(bom);
        String createdValue = CREATED_FORMAT.format(timestamp);

        Map<String, Object> document = new LinkedHashMap<>();
        document.put("spdxVersion", SPDX_VERSION);
        document.put("dataLicense", DATA_LICENSE);
        document.put("SPDXID", DOCUMENT_ID);
        document.put("name", name);
        document.put("documentNamespace", documentNamespace(name, timestamp, builder.contentDigest()));
        Map<String, Object> creationInfo = new LinkedHashMap<>();
        creationInfo.put("created", createdValue);
        List<String> creators = new ArrayList<>();
        creators.add(CREATOR);
        creationInfo.put("creators", creators);
        creationInfo.put("comment", CREATION_COMMENT);
        document.put("creationInfo", creationInfo);
        if (!builder.packages.isEmpty()) {
            document.put("packages", builder.packages);
        }
        if (!builder.relationships.isEmpty()) {
            document.put("relationships", builder.relationships);
        }
        if (!builder.extractedLicenses.isEmpty()) {
            List<Map<String, Object>> infos = new ArrayList<>();
            for (Map.Entry<String, String> entry : builder.extractedLicenses.entrySet()) {
                Map<String, Object> info = new LinkedHashMap<>();
                info.put("licenseId", entry.getKey());
                info.put("name", entry.getValue());
                info.put("extractedText", NOASSERTION);
                infos.add(info);
            }
            document.put("hasExtractedLicensingInfos", infos);
        }
        return document;
    }

    // ------------------------------------------------------------------ document identity

    private static Component rootComponent(Bom bom) {
        Metadata metadata = bom.getMetadata();
        return metadata == null ? null : metadata.getComponent();
    }

    private static String documentName(Component root) {
        if (root == null) {
            return FALLBACK_NAME;
        }
        String name = trimToNull(root.getName());
        if (name == null) {
            name = trimToNull(root.getPurl());
        }
        if (name == null) {
            return FALLBACK_NAME;
        }
        String version = trimToNull(root.getVersion());
        return version == null ? name : name + "-" + version;
    }

    private static Instant bomTimestamp(Bom bom) {
        Metadata metadata = bom.getMetadata();
        if (metadata != null) {
            Date timestamp = metadata.getTimestamp();
            if (timestamp != null) {
                return timestamp.toInstant();
            }
        }
        return Instant.now();
    }

    /**
     * Builds a deterministic {@code documentNamespace} from the document name, the creation timestamp and a digest
     * of the generated packages and relationships. Reprocessing the same BOM creates the same namespace, while two
     * documents that only share a name and a timestamp do not, which SPDX requires (the namespace is the unique
     * identifier of a document).
     *
     * @param name          document name
     * @param created       creation timestamp
     * @param contentDigest digest over the emitted packages and relationships
     * @return the document namespace
     */
    static String documentNamespace(String name, Instant created, String contentDigest) {
        String seed = name + "|" + created.getEpochSecond() + "|" + contentDigest;
        String digest = sha256Hex(seed);
        return NAMESPACE_PREFIX + slug(name) + "-" + digest.substring(0, NAMESPACE_HASH_LENGTH);
    }

    private static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format(Locale.ROOT, "%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available", e);
        }
    }

    /** Makes a value safe for a URI path segment of the document namespace. */
    static String slug(String value) {
        String slug = sanitize(value);
        return slug.isEmpty() ? FALLBACK_NAME : slug;
    }

    // ------------------------------------------------------------------ packages

    /** Builds the SPDX document body: packages, relationships and extracted licensing information. */
    private static final class Builder {

        private final List<Map<String, Object>> packages = new ArrayList<>();
        private final List<Map<String, Object>> relationships = new ArrayList<>();
        private final Set<String> relationshipKeys = new LinkedHashSet<>();
        private final Map<String, String> idsByReference = new LinkedHashMap<>();
        /** SPDX ids of components the merger linked by inference ({@code sbomAggregator:inferredDependency}). */
        private final Set<String> inferredIds = new HashSet<>();
        private final Set<String> emitted = new LinkedHashSet<>();
        private final Map<String, String> extractedLicenses = new TreeMap<>();
        private final Set<String> usedIds = new LinkedHashSet<>();

        Builder() {
            // reserve the document id so no package can take it
            usedIds.add(DOCUMENT_ID);
        }

        /**
         * @return a stable digest over the emitted package content and relationships, used to make the document
         *         namespace unique per document without giving up reproducibility
         */
        String contentDigest() {
            StringBuilder sb = new StringBuilder();
            for (Map<String, Object> pkg : packages) {
                try {
                    // hash the whole package payload: two components can share a bom-ref and still differ in
                    // version, checksums, supplier or licences
                    sb.append(MAPPER.writeValueAsString(pkg));
                } catch (JsonProcessingException e) {
                    throw new IllegalStateException(
                            "Failed to compute the SPDX content digest: " + e.getMessage(), e);
                }
                sb.append('\n');
            }
            for (Map<String, Object> relationship : relationships) {
                sb.append(relationship.get("spdxElementId")).append('>')
                        .append(relationship.get("relationshipType")).append('>')
                        .append(relationship.get("relatedSpdxElement")).append('\n');
            }
            return sha256Hex(sb.toString());
        }

        /**
         * Emits a package for the component and recurses into its nested components.
         *
         * @return the SPDX id of the component, or {@code null} when it has no usable identity
         */
        String addComponent(Component component, String parentId) {
            String bomRef = trimToNull(component.getBomRef());
            if (bomRef != null && !emitted.add(bomRef)) {
                String existing = idsByReference.get(bomRef);
                if (existing != null && parentId != null) {
                    relationship(parentId, "CONTAINS", existing);
                }
                return existing;
            }
            String id = allocateId(preferredId(component, bomRef));
            if (bomRef != null) {
                idsByReference.put(bomRef, id);
            }
            String purl = trimToNull(component.getPurl());
            if (purl != null) {
                idsByReference.putIfAbsent(purl, id);
            }
            packages.add(packageFor(component, id));
            if (isInferred(component)) {
                inferredIds.add(id);
            }
            if (parentId != null) {
                relationship(parentId, "CONTAINS", id);
            }
            if (component.getComponents() != null) {
                for (Component nested : component.getComponents()) {
                    if (nested != null) {
                        addComponent(nested, id);
                    }
                }
            }
            return id;
        }

        void addDependencies(List<Dependency> dependencies, String rootId) {
            if (rootId != null) {
                relationship(DOCUMENT_ID, "DESCRIBES", rootId);
            }
            if (dependencies == null) {
                return;
            }
            for (Dependency dependency : dependencies) {
                if (dependency == null) {
                    continue;
                }
                String from = idsByReference.get(trimToNull(dependency.getRef()));
                if (from == null || dependency.getDependencies() == null) {
                    continue;
                }
                for (Dependency child : dependency.getDependencies()) {
                    if (child == null) {
                        continue;
                    }
                    String to = idsByReference.get(trimToNull(child.getRef()));
                    if (to == null || to.equals(from)) {
                        continue;
                    }
                    // an inferred link only says "found inside the scanned artifact", so it is containment
                    relationship(from, inferredIds.contains(to) ? "CONTAINS" : "DEPENDS_ON", to);
                }
            }
        }

        private static boolean isInferred(Component component) {
            if (component.getProperties() == null) {
                return false;
            }
            for (org.cyclonedx.model.Property property : component.getProperties()) {
                if (property != null && SbomMerger.PROPERTY_INFERRED_DEPENDENCY.equals(property.getName())
                        && "true".equalsIgnoreCase(trimToNull(property.getValue()))) {
                    return true;
                }
            }
            return false;
        }

        private void relationship(String from, String type, String to) {
            if (relationshipKeys.add(from + "|" + type + "|" + to)) {
                Map<String, Object> relationship = new LinkedHashMap<>();
                relationship.put("spdxElementId", from);
                relationship.put("relationshipType", type);
                relationship.put("relatedSpdxElement", to);
                relationships.add(relationship);
            }
        }

        private Map<String, Object> packageFor(Component component, String id) {
            Map<String, Object> pkg = new LinkedHashMap<>();
            pkg.put("SPDXID", id);
            String name = trimToNull(component.getName());
            if (name == null) {
                name = trimToNull(component.getPurl());
            }
            pkg.put("name", name == null ? FALLBACK_NAME : name);
            String version = trimToNull(component.getVersion());
            if (version != null) {
                pkg.put("versionInfo", version);
            }
            OrganizationalEntity supplier = component.getSupplier();
            String supplierName = supplier == null ? null : trimToNull(supplier.getName());
            if (supplierName != null) {
                pkg.put("supplier", "Organization: " + supplierName);
            }
            pkg.put("downloadLocation", downloadLocation(component));
            pkg.put("filesAnalyzed", Boolean.FALSE);
            List<Map<String, Object>> checksums = checksums(component);
            if (!checksums.isEmpty()) {
                pkg.put("checksums", checksums);
            }
            pkg.put("licenseConcluded", NOASSERTION);
            pkg.put("licenseDeclared", licenseDeclared(component));
            String copyright = trimToNull(component.getCopyright());
            pkg.put("copyrightText", copyright == null ? NOASSERTION : copyright);
            List<Map<String, Object>> externalRefs = externalReferences(component);
            if (!externalRefs.isEmpty()) {
                pkg.put("externalRefs", externalRefs);
            }
            return pkg;
        }

        private String preferredId(Component component, String bomRef) {
            if (bomRef != null) {
                return bomRef;
            }
            String purl = trimToNull(component.getPurl());
            if (purl != null) {
                return purl;
            }
            String name = trimToNull(component.getName());
            String group = trimToNull(component.getGroup());
            String version = trimToNull(component.getVersion());
            StringBuilder sb = new StringBuilder();
            if (group != null) {
                sb.append(group).append('/');
            }
            if (name != null) {
                sb.append(name);
            }
            if (version != null) {
                sb.append('@').append(version);
            }
            return sb.toString();
        }

        private String allocateId(String raw) {
            String base = sanitize(raw);
            if (base.isEmpty()) {
                base = FALLBACK_NAME;
            }
            String candidate = base;
            int suffix = 2;
            while (!usedIds.add(ID_PREFIX + candidate)) {
                candidate = base + "-" + suffix++;
            }
            return ID_PREFIX + candidate;
        }

        private String licenseDeclared(Component component) {
            LicenseChoice choice = component.getLicenses() != null
                    ? component.getLicenses() : component.getLicenseChoice();
            if (choice == null) {
                return NOASSERTION;
            }
            Set<String> values = new LinkedHashSet<>();
            if (choice.getItems() != null) {
                for (LicenseItem item : choice.getItems()) {
                    if (item == null) {
                        continue;
                    }
                    if (item.getExpression() != null) {
                        addLicenseValue(values, item.getExpression().getValue());
                    } else if (item.getLicense() != null) {
                        addLicense(values, item.getLicense());
                    }
                }
            }
            if (values.isEmpty() && choice.getExpression() != null) {
                addLicenseValue(values, choice.getExpression().getValue());
            }
            if (values.isEmpty() && choice.getLicenses() != null) {
                for (License license : choice.getLicenses()) {
                    if (license != null) {
                        addLicense(values, license);
                    }
                }
            }
            if (values.isEmpty()) {
                return NOASSERTION;
            }
            if (values.size() == 1) {
                return values.iterator().next();
            }
            // Combining values with AND must not change the meaning of a compound expression: SPDX evaluates AND
            // before OR, so "MIT OR Apache-2.0 AND BSD-3-Clause" would be read as "MIT OR (Apache-2.0 AND
            // BSD-3-Clause)". Bracketing every value that contains an operator or whitespace keeps the meaning.
            StringBuilder sb = new StringBuilder();
            for (String value : values) {
                if (sb.length() > 0) {
                    sb.append(" AND ");
                }
                sb.append(isCompound(value) ? "(" + value + ")" : value);
            }
            return sb.toString();
        }

        /**
         * @param value a licence id, reference or expression
         * @return {@code true} when the value contains an operator (so it must be bracketed before it is joined
         *         with {@code AND} by {@link #licenseDeclared(Component)})
         */
        private static boolean isCompound(String value) {
            for (int i = 0; i < value.length(); i++) {
                if (Character.isWhitespace(value.charAt(i)) || value.charAt(i) == '(' || value.charAt(i) == ')') {
                    return true;
                }
            }
            return false;
        }

        private void addLicense(Set<String> values, License license) {
            String id = trimToNull(license.getId());
            if (id != null) {
                values.add(id);
                return;
            }
            String name = trimToNull(license.getName());
            if (name == null) {
                return;
            }
            values.add(licenseRefFor(name));
        }

        /**
         * Maps a licence name to a {@code LicenseRef-*} id. Distinct names that sanitise to the same id (for example
         * {@code MIT License} and {@code MIT/License}) get a numeric suffix instead of silently sharing the first
         * name; the same name always maps to the same id.
         *
         * @param name the licence name
         * @return the extracted {@code LicenseRef-*} id of the name
         */
        private String licenseRefFor(String name) {
            String base = "LicenseRef-" + slug(name);
            String candidate = base;
            int suffix = 2;
            while (true) {
                String existing = extractedLicenses.get(candidate);
                if (existing == null) {
                    extractedLicenses.put(candidate, name);
                    return candidate;
                }
                if (existing.equals(name)) {
                    return candidate;
                }
                candidate = base + "-" + suffix++;
            }
        }

        private void addLicenseValue(Set<String> values, String value) {
            String trimmed = trimToNull(value);
            if (trimmed != null) {
                values.add(trimmed);
            }
        }
    }

    // ------------------------------------------------------------------ component fields

    private static List<Map<String, Object>> checksums(Component component) {
        List<Map<String, Object>> checksums = new ArrayList<>();
        if (component.getHashes() == null) {
            return checksums;
        }
        Set<String> seen = new LinkedHashSet<>();
        for (Hash hash : component.getHashes()) {
            if (hash == null) {
                continue;
            }
            String algorithm = spdxAlgorithm(hash.getAlgorithm());
            String value = trimToNull(hash.getValue());
            if (algorithm == null || value == null || !seen.add(algorithm)) {
                continue;
            }
            Map<String, Object> checksum = new LinkedHashMap<>();
            checksum.put("algorithm", algorithm);
            checksum.put("checksumValue", value);
            checksums.add(checksum);
        }
        return checksums;
    }

    /**
     * Maps a CycloneDX hash algorithm to the SPDX checksum algorithm name.
     *
     * @return the SPDX algorithm, or {@code null} when SPDX 2.3 defines no equivalent
     */
    static String spdxAlgorithm(String algorithm) {
        String value = trimToNull(algorithm);
        if (value == null) {
            return null;
        }
        switch (value.toUpperCase(Locale.ROOT)) {
            case "MD5":
                return "MD5";
            case "SHA-1":
            case "SHA1":
                return "SHA1";
            case "SHA-256":
            case "SHA256":
                return "SHA256";
            case "SHA-384":
            case "SHA384":
                return "SHA384";
            case "SHA-512":
            case "SHA512":
                return "SHA512";
            case "SHA3-256":
                return "SHA3-256";
            case "SHA3-384":
                return "SHA3-384";
            case "SHA3-512":
                return "SHA3-512";
            case "BLAKE2B-256":
                return "BLAKE2b-256";
            case "BLAKE2B-384":
                return "BLAKE2b-384";
            case "BLAKE2B-512":
                return "BLAKE2b-512";
            case "BLAKE3":
                return "BLAKE3";
            default:
                return null;
        }
    }

    private static List<Map<String, Object>> externalReferences(Component component) {
        List<Map<String, Object>> refs = new ArrayList<>();
        String purl = trimToNull(component.getPurl());
        if (purl != null) {
            refs.add(reference("PACKAGE-MANAGER", "purl", purl));
        }
        String cpe = trimToNull(component.getCpe());
        if (cpe != null) {
            refs.add(reference("SECURITY", cpe.startsWith("cpe:/") ? "cpe22Type" : "cpe23Type", cpe));
        }
        return refs;
    }

    private static Map<String, Object> reference(String category, String type, String locator) {
        Map<String, Object> ref = new LinkedHashMap<>();
        ref.put("referenceCategory", category);
        ref.put("referenceType", type);
        ref.put("referenceLocator", locator);
        return ref;
    }

    private static String downloadLocation(Component component) {
        String located = externalReferenceUrl(component, ExternalReference.Type.DISTRIBUTION);
        if (located == null) {
            located = externalReferenceUrl(component, ExternalReference.Type.SOURCE_DISTRIBUTION);
        }
        if (located == null) {
            located = externalReferenceUrl(component, ExternalReference.Type.WEBSITE);
        }
        return located == null ? NOASSERTION : located;
    }

    private static String externalReferenceUrl(Component component, ExternalReference.Type type) {
        if (component.getExternalReferences() == null) {
            return null;
        }
        for (ExternalReference reference : component.getExternalReferences()) {
            if (reference != null && reference.getType() == type) {
                String url = trimToNull(reference.getUrl());
                if (url != null) {
                    return url;
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ helpers

    /**
     * Reduces a value to the characters SPDX allows in an element id ({@code [A-Za-z0-9.-]}); every other
     * character becomes {@code '-'} and runs of {@code '-'} are collapsed.
     */
    static String sanitize(String value) {
        String trimmed = value == null ? "" : value.trim();
        StringBuilder sb = new StringBuilder(trimmed.length());
        boolean lastDash = false;
        for (int i = 0; i < trimmed.length(); i++) {
            char ch = trimmed.charAt(i);
            boolean allowed = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
            if (allowed) {
                sb.append(ch);
                lastDash = false;
            } else if (ch == '.' && sb.length() > 0 && !lastDash) {
                sb.append(ch);
            } else if (!lastDash && sb.length() > 0) {
                sb.append('-');
                lastDash = true;
            }
        }
        // drop a trailing separator so ids never end with '-'
        while (sb.length() > 0 && (sb.charAt(sb.length() - 1) == '-' || sb.charAt(sb.length() - 1) == '.')) {
            sb.setLength(sb.length() - 1);
        }
        return sb.toString();
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
