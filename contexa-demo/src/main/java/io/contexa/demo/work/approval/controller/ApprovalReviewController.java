package io.contexa.demo.work.approval.controller;

import io.contexa.demo.work.approval.dto.ApprovalDecisionInput;
import io.contexa.demo.work.approval.dto.ApprovalView;
import io.contexa.demo.work.approval.service.ApprovalService;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.request.web.BusinessContextAttributes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@Profile({"baseline", "contexa"})
@RequestMapping("/api/work/admin/approvals")
public class ApprovalReviewController extends AbstractApprovalController {

    private final ApprovalService approvals;

    public ApprovalReviewController(WorkParticipantQuery participants, ApprovalService approvals) {
        super(participants);
        this.approvals = approvals;
    }

    @PostMapping("/{id}/decision")
    public ResponseEntity<ApprovalView> decide(@PathVariable UUID id, @Valid @RequestBody ApprovalDecisionInput input,
            HttpServletRequest request, Authentication authentication) {
        return result(approvals.decide(BusinessContextAttributes.requestId(request), id, actor(request, authentication), input));
    }
}
