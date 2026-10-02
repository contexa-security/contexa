package io.contexa.demo.comparison.attestation.service.impl;

import io.contexa.demo.comparison.attestation.dto.ArmAttestation;
import io.contexa.demo.comparison.attestation.dto.AttestationCommand;
import io.contexa.demo.comparison.attestation.dto.AttestationSnapshot;
import io.contexa.demo.comparison.attestation.repository.ArmAttestationRepository;
import io.contexa.demo.comparison.attestation.service.ArmAttestationService;
import io.contexa.demo.comparison.attestation.source.ExecutionEnvironmentQuery;
import io.contexa.demo.comparison.attestation.source.InitialHistoryQuery;
import io.contexa.demo.comparison.attestation.source.LoginOriginQuery;
import io.contexa.demo.comparison.attestation.source.PreparationPlanQuery;
import io.contexa.demo.comparison.preparation.source.ComparisonDocumentSource;
import io.contexa.demo.comparison.preparation.source.ComparisonCustomerSource;
import io.contexa.demo.comparison.batch.source.ComparisonBatchSource;
import io.contexa.demo.comparison.approval.source.ComparisonApprovalQuery;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.identity.service.IdentityQueryService;
import io.contexa.demo.readiness.service.RuntimeSecurityQuery;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.project.repository.ProjectRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.util.UUID;

@Service
@Profile({"baseline", "contexa"})
public class DefaultArmAttestationService implements ArmAttestationService {

    private final PreparationPlanQuery plans;
    private final WorkParticipantQuery participants;
    private final IdentityQueryService identities;
    private final ComparisonDocumentSource source;
    private final ComparisonCustomerSource customerSource;
    private final ProjectRepository projects;
    private final RuntimeSecurityQuery security;
    private final ExecutionEnvironmentQuery environment;
    private final InitialHistoryQuery history;
    private final LoginOriginQuery loginOrigins;
    private final ArmAttestationRepository repository;
    private final DocumentCodec documents;
    private final String arm;
    private final ComparisonBatchSource batches;
    private final ComparisonApprovalQuery approvals;

    public DefaultArmAttestationService(PreparationPlanQuery plans, WorkParticipantQuery participants,
            IdentityQueryService identities, ComparisonDocumentSource source, ProjectRepository projects,
            RuntimeSecurityQuery security, ExecutionEnvironmentQuery environment, InitialHistoryQuery history,
            ArmAttestationRepository repository, DocumentCodec documents, LabProperties properties,
            LoginOriginQuery loginOrigins, ComparisonCustomerSource customerSource, ComparisonBatchSource batches,
            ComparisonApprovalQuery approvals) {
        this.plans = plans;
        this.participants = participants;
        this.identities = identities;
        this.source = source;
        this.projects = projects;
        this.security = security;
        this.environment = environment;
        this.history = history;
        this.loginOrigins = loginOrigins;
        this.customerSource = customerSource;
        this.repository = repository;
        this.documents = documents;
        this.arm = properties.role();
        this.batches = batches;
        this.approvals = approvals;
    }

    @Override
    public ArmAttestation capture(UUID visitorId, AttestationCommand command, Authentication authentication,
            HttpServletRequest request) {
        var identity = identities.inspect(authentication, request);
        if (!identity.authenticated() || !identity.sessionPresent()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_REQUIRED");
        }
        var prepared = plans.find(visitorId, command.preparationId());
        if (prepared == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        var participant = participants.require(visitorId, identity.username());
        if (!participant.workspaceId().equals(prepared.workspaceId())
                || !identity.username().equals(prepared.snapshot().requestPlan().requestedAccount())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMPARISON_ACCOUNT_CHANGED");
        }
        ArmAttestation previous = repository.findCommand(visitorId, command.commandId());
        if (previous != null) {
            if (!previous.preparationId().equals(command.preparationId())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "COMMAND_INPUT_CHANGED");
            }
            return previous;
        }
        String resourceId = prepared.snapshot().resources().get(0).resourceId();
        var plan = prepared.snapshot().requestPlan();
        var selection = plan.exportSelection();
        boolean customer = "CUSTOMER_READ_PAIR".equals(plan.kind());
        String sessionSha256 = documents.hash(request.getSession(false).getId());
        var approval = approvals.capture(plan, resourceId, participant);
        var snapshot = new AttestationSnapshot(identity, sessionSha256,
                customer || selection != null ? null : source.capture(resourceId), projects.assignedProjects(identity.username()).stream().sorted().toList(),
                security.inspect(), environment.capture(), history.capture(identity.username(), request),
                loginOrigins.find(sessionSha256, identity.username()), customer ? customerSource.capture(resourceId) : null,
                selection == null ? null : batches.capture(arm, selection), approval);
        return repository.save(new ArmAttestation(UUID.randomUUID(), visitorId, participant.workspaceId(),
                command.preparationId(), command.commandId(), arm, Instant.now(),
                documents.hash(documents.write(snapshot)), snapshot));
    }
}
