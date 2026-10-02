package io.contexa.demo.comparison.attestation.service.impl;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.attestation.dto.AttestationPair;
import io.contexa.demo.comparison.attestation.service.AttestationPairQuery;
import io.contexa.demo.comparison.attestation.source.ArmAttestationQuery;
import io.contexa.demo.comparison.preparation.dto.PreparationBlocker;
import io.contexa.demo.comparison.preparation.dto.PreparedComparison;
import io.contexa.demo.comparison.preparation.service.ComparisonPreparationService;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

@Service
@Profile("portal")
public class StoredAttestationPairQuery implements AttestationPairQuery {

    private final ComparisonPreparationService preparations;
    private final List<ArmAttestationQuery> sources;

    public StoredAttestationPairQuery(ComparisonPreparationService preparations, List<ArmAttestationQuery> sources) {
        this.preparations = preparations;
        this.sources = sources;
    }

    @Override
    public AttestationPair inspect(UUID visitorId, UUID preparationId, UUID baselineId, UUID contexaId) {
        PreparedComparison prepared = preparations.find(visitorId, preparationId);
        List<ArmAttestation> captured = new ArrayList<>();
        List<PreparationBlocker> blockers = new ArrayList<>();
        Instant now = Instant.now();
        for (ArmAttestationQuery source : sources) {
            UUID id = "baseline".equals(source.arm()) ? baselineId : contexaId;
            if (id == null) {
                blockers.add(new PreparationBlocker(source.arm(), "authenticated-sessions", "NOT_OBSERVED"));
                continue;
            }
            ArmAttestation attestation = source.find(visitorId, preparationId, id);
            if (attestation == null || !attestation.workspaceId().equals(prepared.workspaceId())) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND);
            }
            captured.add(attestation);
            inspectArm(prepared, attestation, now, blockers);
        }
        captured.sort((first, second) -> first.arm().compareTo(second.arm()));
        if (captured.size() == 2) {
            inspectPair(captured.get(0), captured.get(1), blockers);
        } else {
            blockers.add(new PreparationBlocker("comparison", "authenticated-sessions", "NOT_OBSERVED"));
        }
        return new AttestationPair(preparationId, now, List.copyOf(captured), List.copyOf(blockers),
                blockers.isEmpty(), "CUSTOMER_READ_PAIR".equals(prepared.snapshot().requestPlan().kind())
                        ? "INITIAL_SESSION_CUSTOMER_CONFIGURATION_ONLY" : "INITIAL_SESSION_DOCUMENT_CONFIGURATION_ONLY");
    }

    private void inspectArm(PreparedComparison prepared, ArmAttestation attestation, Instant now,
            List<PreparationBlocker> blockers) {
        var snapshot = attestation.snapshot();
        var identity = snapshot.identity();
        String arm = attestation.arm();
        if (attestation.capturedAt().isAfter(now)
                || Duration.between(attestation.capturedAt(), now).compareTo(Duration.ofMinutes(2)) > 0) {
            blockers.add(new PreparationBlocker(arm, "authenticated-sessions", "STALE"));
        }
        if (!identity.authenticated() || !identity.sessionPresent()
                || !Objects.equals(identity.username(), prepared.snapshot().requestPlan().requestedAccount())) {
            blockers.add(new PreparationBlocker(arm, "authenticated-sessions", "NOT_MATCHED"));
        }
        String state = identity.authenticationProgress().state();
        boolean settled = Set.of("AUTHENTICATED", "NO_ACTIVE_MFA").contains(state)
                || ("MFA_FLOW_FINISHED".equals(state)
                && Set.of("MFA_SUCCESSFUL", "MFA_NOT_REQUIRED")
                .contains(identity.authenticationProgress().mfaState()));
        if (!settled) {
            blockers.add(new PreparationBlocker(arm, "authentication-progress", "NOT_READY"));
        }
        if (identity.accountAuthorities() == null || identity.accountAuthorities().isEmpty()) {
            blockers.add(new PreparationBlocker(arm, "account-permissions", "NOT_OBSERVED"));
        }
        if (!"CAPTURED".equals(snapshot.resource().state())) {
            blockers.add(new PreparationBlocker(arm, "business-resources", snapshot.resource().state()));
        }
        var original = prepared.snapshot().resources().stream()
                .filter(value -> arm.equals(value.arm())).findFirst().orElse(null);
        if (original == null || original.sourceSha256() == null
                || !original.sourceSha256().equals(snapshot.resource().sourceSha256())) {
            blockers.add(new PreparationBlocker(arm, "business-resources", "CHANGED"));
        }
        if (!"CAPTURED".equals(snapshot.environment().artifactState())) {
            blockers.add(new PreparationBlocker(arm, "application-version", "NOT_OBSERVED"));
        }
        if ("UNAVAILABLE".equals(snapshot.history().state())) {
            blockers.add(new PreparationBlocker(arm, "history", "UNAVAILABLE"));
        }
        if ("contexa".equals(arm)) {
            var nativeConfiguration = snapshot.environment().nativeConfiguration();
            if (nativeConfiguration == null || !"CAPTURED".equals(nativeConfiguration.state())) {
                blockers.add(new PreparationBlocker(arm, "model-configuration", "NOT_OBSERVED"));
            }
            var inventory = snapshot.environment().ragInventory();
            if (inventory == null || !"CAPTURED".equals(inventory.state())) {
                blockers.add(new PreparationBlocker(arm, "search-inventory", "NOT_OBSERVED"));
            }
            var history = snapshot.history().contextHistory();
            if (history == null || !"API_RETURNS_OBSERVED".equals(history.state())) {
                blockers.add(new PreparationBlocker(arm, "context-history", "NOT_OBSERVED"));
            }
            var roleScope = history == null ? null : history.roleScopeHistory();
            if (roleScope == null || !Set.of("API_RETURN_OBSERVED", "NO_STORED_SCOPE_RETURNED")
                    .contains(roleScope.state())) {
                blockers.add(new PreparationBlocker(arm, "role-scope-history",
                        roleScope == null ? "NOT_OBSERVED" : roleScope.state()));
            }
        }
    }

    private void inspectPair(ArmAttestation first, ArmAttestation second, List<PreparationBlocker> blockers) {
        var left = first.snapshot();
        var right = second.snapshot();
        if (!Objects.equals(left.identity().accountAuthorities(), right.identity().accountAuthorities())) {
            blockers.add(new PreparationBlocker("comparison", "account-permissions", "NOT_MATCHED"));
        }
        if (left.loginOrigin() == null || right.loginOrigin() == null) {
            blockers.add(new PreparationBlocker("comparison", "authentication-level", "NOT_OBSERVED"));
        } else if (!Objects.equals(left.loginOrigin().authenticationType(), right.loginOrigin().authenticationType())
                || !Objects.equals(left.loginOrigin().path(), right.loginOrigin().path())) {
            blockers.add(new PreparationBlocker("comparison", "authentication-level", "NOT_MATCHED"));
        }
        if (!Objects.equals(left.identity().staticPolicySha256(), right.identity().staticPolicySha256())) {
            blockers.add(new PreparationBlocker("comparison", "static-policy", "NOT_MATCHED"));
        }
        if (left.resource().sourceSha256() == null
                || !left.resource().sourceSha256().equals(right.resource().sourceSha256())) {
            blockers.add(new PreparationBlocker("comparison", "business-resources", "NOT_MATCHED"));
        }
        if (!Objects.equals(left.assignedProjects(), right.assignedProjects())) {
            blockers.add(new PreparationBlocker("comparison", "assignments", "NOT_MATCHED"));
        }
        if ((left.approval() == null) != (right.approval() == null)
                || (left.approval() != null && (!Objects.equals(left.approval().status(), right.approval().status())
                || left.approval().required() != right.approval().required()
                || !Objects.equals(left.approval().purpose(), right.approval().purpose())
                || !Objects.equals(left.approval().targets(), right.approval().targets())))) {
            blockers.add(new PreparationBlocker("comparison", "business-approval", "NOT_MATCHED"));
        }
        if (left.environment().applicationSha256() == null
                || !left.environment().applicationSha256().equals(right.environment().applicationSha256())) {
            blockers.add(new PreparationBlocker("comparison", "application-version", "NOT_MATCHED"));
        }
        if (left.runtimeMode().analysisEnabled() || left.runtimeMode().enforcementEnabled()
                || !right.runtimeMode().analysisEnabled() || !right.runtimeMode().enforcementEnabled()) {
            blockers.add(new PreparationBlocker("comparison", "runtime-security", "NOT_MATCHED"));
        }
    }
}
