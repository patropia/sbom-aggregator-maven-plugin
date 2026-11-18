package nl.patropia.maven.plugin;

import org.apache.maven.model.Dependency;
import org.apache.maven.plugin.MojoExecutionException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Utility to normalise and filter Maven dependencies by scope.
 */
public final class DependencyScopeFilter {

    private DependencyScopeFilter() { /* utility */ }

    public static final Set<String> ALLOWED_SCOPES;
    static {
        Set<String> s = new java.util.LinkedHashSet<>();
        s.add("compile");
        s.add("provided");
        s.add("runtime");
        s.add("test");
        s.add("system");
        ALLOWED_SCOPES = Collections.unmodifiableSet(s);
    }

    /**
     * Normalises a list of scope strings: trims, lower-cases and drops blanks. Throws
     * MojoExecutionException if an unknown scope is present.
     */
    public static List<String> normaliseScopes(List<String> scopes) throws MojoExecutionException {
        if (scopes == null || scopes.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> out = new ArrayList<>();
        for (String s : scopes) {
            if (s == null) continue;
            String n = s.trim().toLowerCase(Locale.ROOT);
            if (n.isEmpty()) continue;
            if (!ALLOWED_SCOPES.contains(n)) {
                throw new MojoExecutionException("Unknown scope '" + s + "'. Allowed scopes: " + ALLOWED_SCOPES);
            }
            out.add(n);
        }
        return out;
    }

    /**
     * Filters the given list of dependencies according to includeScopes and excludeTestScope.
     * - A null or blank dependency scope is treated as 'compile'.
     * - If includeScopes is non-empty, only dependencies with a scope in that set are kept.
     *   includeScopes is a list of normalised scopes (lower-case).
     * - Otherwise, if excludeTestScope is true, dependencies with scope 'test' are removed.
     * The original order of dependencies is preserved.
     */
    public static List<Dependency> filter(List<Dependency> deps, List<String> includeScopes, boolean excludeTestScope) {
        if (deps == null || deps.isEmpty()) {
            return Collections.emptyList();
        }
        Set<String> include = new java.util.LinkedHashSet<>();
        if (includeScopes != null) {
            for (String s : includeScopes) {
                if (s != null && !s.isEmpty()) include.add(s);
            }
        }
        List<Dependency> out = new ArrayList<>();
        for (Dependency d : deps) {
            String scope = d.getScope();
            if (scope == null || scope.trim().isEmpty()) {
                scope = "compile";
            } else {
                scope = scope.trim().toLowerCase(Locale.ROOT);
            }
            // If include set is non-empty, only keep included scopes
            if (!include.isEmpty()) {
                if (include.contains(scope)) {
                    out.add(d);
                }
            } else {
                if (excludeTestScope && "test".equals(scope)) {
                    // skip
                } else {
                    out.add(d);
                }
            }
        }
        return out;
    }
}
