package io.contexa.showcase.business.work;

import io.contexa.showcase.business.work.BusinessViews.CustomerView;
import io.contexa.showcase.business.work.BusinessViews.DocumentFile;
import io.contexa.showcase.business.work.BusinessViews.DocumentView;
import io.contexa.showcase.business.work.BusinessViews.ExportResult;
import io.contexa.showcase.business.work.BusinessViews.ExportStream;
import io.contexa.showcase.business.work.BusinessViews.ProjectSummary;
import io.contexa.showcase.business.work.BusinessViews.RoleGrantResult;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The business API of the virtual company (docs/showcase/ADR.md ADR-21). It is registered as a bean by
 * {@link BusinessConfiguration}, not by component scanning, so each workload decides which operations back it.
 * Before calling an operation it writes the business facts of the request as request attributes, which the
 * Contexa engine reads into its resource context; the plain controls ignore them.
 */
@RestController
public class BusinessController {

    /** Largest export a single request may ask for; the virtual company's largest project has 6,400 documents. */
    public static final int MAX_EXPORT_ITEMS = 10_000;
    private static final Pattern RESPONSIBILITY = Pattern.compile("[A-Z_]{2,24}");

    private final BusinessOperations operations;
    private final BusinessRequestAttributes attributes;
    private final String control;
    private final Clock clock;

    public BusinessController(BusinessOperations operations, BusinessRequestAttributes attributes, String control,
                              Clock clock) {
        this.operations = operations;
        this.attributes = attributes;
        this.control = control;
        this.clock = clock;
    }

    @GetMapping("/api/projects")
    public List<ProjectSummary> projects(HttpServletRequest http, Authentication authentication) {
        return operations.listProjects(request(http, authentication));
    }

    @GetMapping("/api/documents/{documentKey}")
    public DocumentView document(@PathVariable("documentKey") String documentKey, HttpServletRequest http,
                                 Authentication authentication) {
        attributes.describeDocument(http, documentKey);
        return operations.readDocument(request(http, authentication), documentKey);
    }

    @GetMapping("/api/documents/{documentKey}/download")
    public ResponseEntity<byte[]> download(@PathVariable("documentKey") String documentKey, HttpServletRequest http,
                                           Authentication authentication) {
        attributes.describeDocument(http, documentKey);
        DocumentFile file = operations.downloadDocument(request(http, authentication), documentKey);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.fileName() + "\"")
                .contentType(MediaType.parseMediaType(file.contentType()))
                .body(file.content());
    }

    @PostMapping("/api/projects/{projectKey}/exports")
    public ExportResult export(@PathVariable("projectKey") String projectKey, @RequestParam("items") int items,
                               HttpServletRequest http, Authentication authentication) {
        requireItems(items);
        attributes.describeExport(http, projectKey, items);
        return operations.exportDocuments(request(http, authentication), projectKey, items);
    }

    @GetMapping(value = "/api/projects/{projectKey}/exports/stream", produces = MediaType.APPLICATION_NDJSON_VALUE)
    public ResponseEntity<StreamingResponseBody> exportStream(@PathVariable("projectKey") String projectKey,
                                                              @RequestParam("items") int items,
                                                              HttpServletRequest http, Authentication authentication) {
        requireItems(items);
        attributes.describeExport(http, projectKey, items);
        ExportStream stream = operations.openExportStream(request(http, authentication), projectKey, items);
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_NDJSON)
                .header("X-Showcase-Export-Job", stream.jobId().toString())
                .header("X-Showcase-Export-Total", Integer.toString(stream.totalItems()))
                .body(stream.body());
    }

    @PostMapping("/api/admin/role-grants")
    public RoleGrantResult grantRole(@RequestParam("project") String projectKey, @RequestParam("grantee") String grantee,
                                     @RequestParam(name = "responsibility", defaultValue = "REVIEW") String responsibility,
                                     HttpServletRequest http, Authentication authentication) {
        if (!RESPONSIBILITY.matcher(responsibility).matches()) {
            throw new IllegalArgumentException("responsibility must be 2 to 24 capital letters");
        }
        attributes.describeGrant(http, projectKey, grantee, responsibility);
        return operations.grantRole(request(http, authentication), projectKey, grantee, responsibility);
    }

    @GetMapping("/api/customers/{customerKey}")
    public CustomerView customer(@PathVariable("customerKey") String customerKey, HttpServletRequest http,
                                 Authentication authentication) {
        attributes.describeCustomer(http, customerKey);
        return operations.readCustomer(request(http, authentication), customerKey);
    }

    @ExceptionHandler(BusinessNotFoundException.class)
    public ResponseEntity<Map<String, String>> notFound(BusinessNotFoundException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "NOT_FOUND", "message", e.getMessage()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("error", "BAD_REQUEST", "message", e.getMessage()));
    }

    private BusinessRequest request(HttpServletRequest http, Authentication authentication) {
        return BusinessRequest.of(http, authentication.getName(), control, clock);
    }

    private static void requireItems(int items) {
        if (items < 1 || items > MAX_EXPORT_ITEMS) {
            throw new IllegalArgumentException("items must be between 1 and " + MAX_EXPORT_ITEMS);
        }
    }
}
