package io.contexa.showcase.business.work;

import io.contexa.showcase.business.company.CompanyBlueprint;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * The role-by-endpoint table both RBAC parity tests check (P1-BE-02): control B's Spring Security chain and control
 * D's engine policies must each give exactly the expected static decision for every case. The expectation comes from
 * {@link RbacPolicy} alone, so the two controls agree with each other when both tests pass.
 */
public final class RbacParityCases {

    public record Case(String roleKey, String method, String path, boolean allowed) {
    }

    /** One request per business endpoint plus one request no rule names. */
    static final List<String[]> REQUESTS = List.of(
            new String[]{"GET", "/api/projects"},
            new String[]{"GET", "/api/documents/HX-310-DWG-00001"},
            new String[]{"GET", "/api/documents/HX-310-DWG-00001/download"},
            new String[]{"POST", "/api/projects/HX-310/exports"},
            new String[]{"GET", "/api/projects/HX-310/exports/stream"},
            new String[]{"GET", "/api/customers/CUS-0001"},
            new String[]{"POST", "/api/admin/role-grants"},
            new String[]{"DELETE", "/api/documents/HX-310-DWG-00001"});

    static final List<String> ROLES = List.of(CompanyBlueprint.ROLE_ENGINEER, CompanyBlueprint.ROLE_SALES,
            CompanyBlueprint.ROLE_PM, CompanyBlueprint.ROLE_PARTNER, CompanyBlueprint.ROLE_FINANCE,
            CompanyBlueprint.ROLE_ADMIN);

    private RbacParityCases() {
    }

    public static List<Case> all() {
        List<Case> cases = new ArrayList<>();
        for (String role : ROLES) {
            for (String[] request : REQUESTS) {
                Optional<RbacPolicy.Rule> rule = RbacPolicy.match(request[0], request[1]);
                cases.add(new Case(role, request[0], request[1], rule.map(r -> r.allows(role)).orElse(false)));
            }
        }
        return List.copyOf(cases);
    }
}
