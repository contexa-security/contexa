package io.contexa.showcase.workload.plain.security;

import io.contexa.showcase.business.work.BusinessOperation;
import io.contexa.showcase.business.work.BusinessRequest;
import io.contexa.showcase.business.work.RbacPolicy;
import io.contexa.showcase.business.work.WorkDatabase;
import io.contexa.showcase.workload.plain.rules.ContextLookupRules;
import io.contexa.showcase.workload.plain.rules.RequestFacts;
import io.contexa.showcase.workload.plain.rules.RuleDecision;
import io.contexa.showcase.workload.plain.rules.ThresholdRules;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Authorization of the business API in a plain control: the shared role-based policy (control B), plus the
 * threshold rules (C1) or the context lookup rules (C2). Every decision is recorded with the facts it used, and a
 * denial is described in the 403 body by {@link JsonSecurityResponses}.
 */
public class ControlAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    /** Request attribute holding the {@link RuleDecision} of a denied request. */
    public static final String DENIAL_ATTRIBUTE = ControlAuthorizationManager.class.getName() + ".denial";

    private final String control;
    private final ThresholdRules thresholdRules;
    private final ContextLookupRules contextLookupRules;
    private final DecisionRecorder recorder;
    private final WorkDatabase database;
    private final Clock clock;

    public ControlAuthorizationManager(String control, ThresholdRules thresholdRules,
                                       ContextLookupRules contextLookupRules, DecisionRecorder recorder,
                                       WorkDatabase database, Clock clock) {
        this.control = control;
        this.thresholdRules = thresholdRules;
        this.contextLookupRules = contextLookupRules;
        this.recorder = recorder;
        this.database = database;
        this.clock = clock;
    }

    @Override
    public AuthorizationDecision check(Supplier<Authentication> authentication, RequestAuthorizationContext context) {
        HttpServletRequest request = context.getRequest();
        Authentication user = authentication.get();
        if (user == null || !user.isAuthenticated() || user.getName() == null) {
            return new AuthorizationDecision(false);
        }
        String path = request.getRequestURI();
        BusinessRequest business = BusinessRequest.of(request, user.getName(), control, clock);
        Optional<RbacPolicy.Rule> rule = RbacPolicy.match(request.getMethod(), path);
        String role = role(user);
        Map<String, Object> rbacFacts = new LinkedHashMap<>();
        rbacFacts.put("role", role);
        rbacFacts.put("method", request.getMethod());
        rbacFacts.put("path", path);
        if (rule.isEmpty()) {
            // Recorded as UNKNOWN: no role rule names it, so it is no known operation (survey L1).
            return decide(request, business, "UNKNOWN",
                    RuleDecision.deny("RBAC-NO-RULE", "No role rule names this request", rbacFacts));
        }
        BusinessOperation operation = rule.get().operation();
        if (!rule.get().allows(role)) {
            return decide(request, business, operation.name(), RuleDecision.deny("RBAC",
                    "Role " + role + " may not perform " + operation, rbacFacts));
        }
        RuleDecision decision = switch (control) {
            case "C1" -> thresholdRules.evaluate(facts(request, business, operation));
            case "C2" -> contextLookupRules.evaluate(facts(request, business, operation));
            default -> RuleDecision.allow("RBAC", "Role " + role + " holds " + operation, rbacFacts);
        };
        return decide(request, business, operation.name(), decision);
    }

    private AuthorizationDecision decide(HttpServletRequest request, BusinessRequest business, String operation,
                                         RuleDecision decision) {
        recorder.record(business, operation, decision);
        if (!decision.allowed()) {
            request.setAttribute(DENIAL_ATTRIBUTE, decision);
        }
        return new AuthorizationDecision(decision.allowed());
    }

    private RequestFacts facts(HttpServletRequest request, BusinessRequest business, BusinessOperation operation) {
        List<String> segments = List.of(request.getRequestURI().split("/"));
        String target = operation == BusinessOperation.ROLE_GRANT ? request.getParameter("grantee")
                : segments.size() > 3 ? segments.get(3) : null;
        String project = switch (operation) {
            case EXPORT, EXPORT_STREAM, EXPORT_ASYNC -> target;
            case DOCUMENT_READ, DOCUMENT_DOWNLOAD ->
                    lookupProject("select project_key from document where document_key = :key", target);
            case CUSTOMER_READ -> lookupProject("select project_key from customer where customer_key = :key", target);
            case ROLE_GRANT -> request.getParameter("project");
            case PROJECT_LIST -> null;
        };
        // A missing or invalid item count stays unknown (null); it is never filled in (survey L2).
        Integer items = null;
        String itemsParameter = request.getParameter("items");
        if (itemsParameter != null) {
            try {
                int parsed = Integer.parseInt(itemsParameter.trim());
                items = parsed > 0 ? parsed : null;
            } catch (NumberFormatException e) {
                items = null;
            }
        }
        String claimedTicket = request.getParameter("claimedTicket");
        return new RequestFacts(operation, business.username(), target, project, items, business.companyTime(),
                claimedTicket == null || claimedTicket.isBlank() ? null : claimedTicket.trim(),
                request.getRemoteAddr());
    }

    private String lookupProject(String sql, String key) {
        if (key == null) {
            return null;
        }
        return database.jdbc().queryForList(sql, new MapSqlParameterSource("key", key), String.class)
                .stream().findFirst().orElse(null);
    }

    private static String role(Authentication user) {
        for (GrantedAuthority authority : user.getAuthorities()) {
            String name = authority.getAuthority();
            if (name != null && name.startsWith("ROLE_")) {
                return name.substring("ROLE_".length());
            }
        }
        return "NONE";
    }
}
