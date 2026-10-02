package io.contexa.demo.comparison.dispatch.service.impl;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.contexa.demo.comparison.dispatch.service.DispatchPlanGuard;
import io.contexa.demo.comparison.dispatch.validation.ComparisonBodyContract;
import io.contexa.demo.comparison.preparation.source.ComparisonDocumentSource;
import io.contexa.demo.comparison.preparation.source.ComparisonCustomerSource;
import io.contexa.demo.comparison.batch.source.ComparisonBatchSource;
import io.contexa.demo.comparison.approval.source.ComparisonApprovalQuery;
import io.contexa.demo.work.participant.dto.WorkParticipant;
import io.contexa.demo.comparison.run.dto.RunRecord;
import io.contexa.demo.configuration.properties.LabProperties;
import io.contexa.demo.identity.service.IdentityQueryService;
import io.contexa.demo.observation.health.service.CollectorRegistry;
import io.contexa.demo.shared.document.DocumentCodec;
import io.contexa.demo.work.project.repository.ProjectRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import java.io.IOException;
import java.util.Objects;
import java.util.List;

@Component
@Profile({"baseline", "contexa"})
public class StoredDispatchPlanGuard implements DispatchPlanGuard {

    private final String arm;
    private final IdentityQueryService identities;
    private final ComparisonDocumentSource documentSource;
    private final ComparisonCustomerSource customerSource;
    private final CollectorRegistry collectors;
    private final DocumentCodec documents;
    private final ObjectMapper mapper;
    private final ProjectRepository projects;
    private final List<ComparisonBodyContract> bodyContracts;
    private final ComparisonBatchSource batches;
    private final ComparisonApprovalQuery approvals;

    public StoredDispatchPlanGuard(LabProperties properties, IdentityQueryService identities,
            ComparisonDocumentSource documentSource, CollectorRegistry collectors, DocumentCodec documents,
            ObjectMapper mapper, ProjectRepository projects, ComparisonCustomerSource customerSource,
            List<ComparisonBodyContract> bodyContracts, ComparisonBatchSource batches, ComparisonApprovalQuery approvals) {
        this.arm = properties.role();
        this.identities = identities;
        this.documentSource = documentSource;
        this.collectors = collectors;
        this.documents = documents;
        this.mapper = mapper;
        this.projects = projects;
        this.customerSource = customerSource;
        this.bodyContracts = List.copyOf(bodyContracts);
        this.batches = batches;
        this.approvals = approvals;
    }

    @Override
    public byte[] verify(RunRecord run, Authentication authentication, HttpServletRequest request) throws IOException {
        var condition = run.manifest().initialConditions().stream()
                .filter(value -> arm.equals(value.arm())).findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.CONFLICT, "ARM_SOURCE_MISSING"));
        var identity = identities.inspect(authentication, request);
        if (!identity.authenticated() || !identity.sessionPresent()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "AUTHENTICATION_REQUIRED");
        }
        if (!Objects.equals(identity.username(), condition.snapshot().identity().username())
                || !Objects.equals(identity.accountAuthorities(), condition.snapshot().identity().accountAuthorities())
                || !Objects.equals(identity.staticPolicySha256(), condition.snapshot().identity().staticPolicySha256())
                || !documents.hash(request.getSession(false).getId()).equals(condition.snapshot().sessionSha256())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "COMPARISON_SESSION_CHANGED");
        }
        if (!collectors.instanceId().equals(condition.snapshot().environment().serverInstanceId())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "BUSINESS_SERVER_RESTARTED");
        }
        if (!projects.assignedProjects(identity.username()).stream().sorted().toList()
                .equals(condition.snapshot().assignedProjects())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "BUSINESS_ASSIGNMENTS_CHANGED");
        }
        var plan = run.manifest().plan();
        if (!plan.method().equals(request.getMethod()) || !plan.path().equals(request.getServletPath())
                || request.getQueryString() != null) {
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "REQUEST_PLAN_MISMATCH");
        }
        byte[] body = request.getInputStream().readNBytes(4097);
        if (body.length > 4096) {
            throw new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "COMPARISON_INPUT_TOO_LARGE");
        }
        JsonNode input;
        try {
            input = mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .readTree(body);
        } catch (JsonProcessingException malformed) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "INVALID_COMPARISON_BODY");
        }
        bodyContracts.stream().filter(contract -> contract.supports(plan.kind())).findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "UNSUPPORTED_REQUEST_PLAN"))
                .verify(plan, input);
        var original = condition.snapshot().resource();
        var resource = plan.exportSelection() != null ? batches.capture(arm, plan.exportSelection()) : "CUSTOMER_READ_PAIR".equals(plan.kind())
                ? customerSource.capture(original.resourceId()) : documentSource.capture(original.resourceId());
        if (!"CAPTURED".equals(resource.state())
                || !Objects.equals(resource.sourceSha256(), original.sourceSha256())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "CUSTOMER_READ_PAIR".equals(plan.kind()) ? "BUSINESS_CUSTOMER_CHANGED" : "BUSINESS_DOCUMENT_CHANGED");
        }
        if (plan.exportSelection() != null || plan.approvalReferences() != null) {
            var approval = approvals.capture(plan, original.resourceId(),
                    new WorkParticipant(run.visitorId(), run.workspaceId(), identity.username()));
            var previous = condition.snapshot().approval();
            if (previous == null || !Objects.equals(previous.status(), approval.status())
                    || !Objects.equals(previous.decisionId(), approval.decisionId())
                    || !Objects.equals(previous.expiresAt(), approval.expiresAt())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "BUSINESS_APPROVAL_CHANGED");
            }
        }
        return body;
    }
}
