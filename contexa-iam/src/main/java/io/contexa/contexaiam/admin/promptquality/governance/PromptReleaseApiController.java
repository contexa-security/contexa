package io.contexa.contexaiam.admin.promptquality.governance;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Objects;

@RestController
@RequestMapping("/contexa/admin/api/prompt-quality/releases")
@PreAuthorize("hasRole('ADMIN')")
public class PromptReleaseApiController {

    private final JdbcPromptReleaseQueryService releaseQueryService;

    public PromptReleaseApiController(JdbcPromptReleaseQueryService releaseQueryService) {
        this.releaseQueryService = Objects.requireNonNull(releaseQueryService, "releaseQueryService");
    }

    @GetMapping
    public JdbcPromptReleaseQueryService.PromptReleaseSnapshot releases(
            @RequestParam(required = false) String registryScope) {
        return releaseQueryService.releases(registryScope);
    }
}
