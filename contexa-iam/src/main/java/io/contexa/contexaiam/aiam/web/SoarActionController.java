package io.contexa.contexaiam.aiam.web;

import io.contexa.contexaiam.aiam.protocol.response.ApprovalResponseDto;
import io.contexa.contexaiam.aiam.service.SoarActionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@Controller
@RequiredArgsConstructor
public class SoarActionController {

    private final SoarActionService soarActionService;

    @GetMapping("/admin/soar-analysis")
    public String soarAnalysis(Model model) {
        model.addAttribute("activePage", "soar-alAnalysis");
        return "admin/soar-analysis";
    }

    @PostMapping("/api/soar/actions/approvals/{approvalId}")
//    @PreAuthorize("hasRole('ROLE_SOAR_ADMIN')")
    public ResponseEntity<Void> handleApproval(
            @PathVariable String approvalId,
            @Valid @RequestBody ApprovalResponseDto responseDto,
            Authentication authentication) {

        String reviewer = authentication.getName();
        soarActionService.handleApproval(approvalId, responseDto.approved(), responseDto.comment(), reviewer);

        return ResponseEntity.ok().build();
    }
}