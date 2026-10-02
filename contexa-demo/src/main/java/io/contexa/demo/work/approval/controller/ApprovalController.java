package io.contexa.demo.work.approval.controller;

import io.contexa.demo.work.approval.dto.ApprovalRequestInput;
import io.contexa.demo.work.approval.dto.ApprovalView;
import io.contexa.demo.work.approval.service.ApprovalService;
import io.contexa.demo.work.participant.service.WorkParticipantQuery;
import io.contexa.demo.work.request.web.BusinessContextAttributes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@Profile({"baseline", "contexa"})
@RequestMapping("/api/work/approvals")
public class ApprovalController extends AbstractApprovalController {

    private final ApprovalService approvals;

    public ApprovalController(WorkParticipantQuery participants, ApprovalService approvals) {
        super(participants);
        this.approvals = approvals;
    }

    @GetMapping
    public ResponseEntity<List<ApprovalView>> list(HttpServletRequest request, Authentication authentication) {
        return result(approvals.list(actor(request, authentication)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApprovalView> find(@PathVariable UUID id, HttpServletRequest request,
            Authentication authentication) {
        return result(approvals.find(id, actor(request, authentication)));
    }

    @PostMapping
    public ResponseEntity<ApprovalView> create(@Valid @RequestBody ApprovalRequestInput input,
            HttpServletRequest request, Authentication authentication) {
        return result(approvals.request(BusinessContextAttributes.requestId(request), actor(request, authentication), input));
    }
}
