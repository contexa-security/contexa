package io.contexa.showcase.business.work;

import io.contexa.showcase.business.company.CompanyBlueprint;
import org.springframework.http.server.PathContainer;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The one role-based access policy of the business API. Control B enforces it with Spring Security, control D
 * seeds the same table into the engine's policy store, and the parity test compares both (P1-BE-02). Anything
 * under {@code /api/} that no rule names is denied in every control.
 */
public final class RbacPolicy {

    public record Rule(BusinessOperation operation, String method, String pattern, Set<String> roles) {

        public boolean allows(String roleKey) {
            return roles.contains(roleKey);
        }
    }

    private static final Set<String> ALL_ROLES = Set.of(CompanyBlueprint.ROLE_ENGINEER, CompanyBlueprint.ROLE_SALES,
            CompanyBlueprint.ROLE_PM, CompanyBlueprint.ROLE_PARTNER, CompanyBlueprint.ROLE_FINANCE,
            CompanyBlueprint.ROLE_ADMIN);

    private static final Set<String> DESIGN_READERS = Set.of(CompanyBlueprint.ROLE_ENGINEER, CompanyBlueprint.ROLE_PM,
            CompanyBlueprint.ROLE_PARTNER, CompanyBlueprint.ROLE_ADMIN);

    private static final Set<String> DESIGN_EXPORTERS = Set.of(CompanyBlueprint.ROLE_ENGINEER,
            CompanyBlueprint.ROLE_PM, CompanyBlueprint.ROLE_ADMIN);

    private static final Set<String> CUSTOMER_READERS = Set.of(CompanyBlueprint.ROLE_SALES, CompanyBlueprint.ROLE_PM,
            CompanyBlueprint.ROLE_FINANCE, CompanyBlueprint.ROLE_ADMIN);

    /** Ordered from the most specific pattern; the first matching rule decides. */
    public static final List<Rule> RULES = List.of(
            new Rule(BusinessOperation.DOCUMENT_DOWNLOAD, "GET", "/api/documents/*/download", DESIGN_READERS),
            new Rule(BusinessOperation.EXPORT_STREAM, "GET", "/api/projects/*/exports/stream", DESIGN_EXPORTERS),
            new Rule(BusinessOperation.EXPORT_ASYNC, "POST", "/api/projects/*/exports/async", DESIGN_EXPORTERS),
            new Rule(BusinessOperation.EXPORT, "POST", "/api/projects/*/exports", DESIGN_EXPORTERS),
            new Rule(BusinessOperation.DOCUMENT_READ, "GET", "/api/documents/*", DESIGN_READERS),
            new Rule(BusinessOperation.CUSTOMER_READ, "GET", "/api/customers/*", CUSTOMER_READERS),
            new Rule(BusinessOperation.ROLE_GRANT, "POST", "/api/admin/role-grants", Set.of(CompanyBlueprint.ROLE_ADMIN)),
            new Rule(BusinessOperation.PROJECT_LIST, "GET", "/api/projects", ALL_ROLES));

    /** Prefix of the business API; requests below it that match no rule are denied. */
    public static final String API_PREFIX = "/api/";

    private static final PathPatternParser PARSER = new PathPatternParser();

    private RbacPolicy() {
    }

    public static Optional<Rule> match(String method, String path) {
        PathContainer container = PathContainer.parsePath(path);
        for (Rule rule : RULES) {
            if (rule.method().equalsIgnoreCase(method) && pattern(rule).matches(container)) {
                return Optional.of(rule);
            }
        }
        return Optional.empty();
    }

    private static PathPattern pattern(Rule rule) {
        return PARSER.parse(rule.pattern());
    }
}
