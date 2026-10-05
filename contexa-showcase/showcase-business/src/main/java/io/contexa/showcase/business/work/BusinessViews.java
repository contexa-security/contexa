package io.contexa.showcase.business.work;

import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Response shapes of the business API. Every view carries enough to judge the business outcome: whether data was
 * delivered and how much (deck p.24).
 */
public final class BusinessViews {

    private BusinessViews() {
    }

    public record ProjectSummary(String projectKey, String displayName, String program, String sensitivity,
                                 int documents) {
    }

    public record DocumentView(String documentKey, String projectKey, String documentType, String title,
                               String revision, String sensitivity, int sizeBytes, String body) {
    }

    public record DocumentFile(String fileName, String contentType, byte[] content, String projectKey) {
    }

    public record ExportedDocument(String documentKey, String title, String revision) {
    }

    /**
     * @param manifestSha256 SHA-256 over the exported document keys joined by newlines
     */
    public record ExportResult(UUID jobId, String projectKey, int requestedItems, int deliveredItems,
                               String manifestSha256, List<ExportedDocument> documents) {
    }

    /** A started streaming export: the body writes one document per line until done or cut. */
    public record ExportStream(UUID jobId, String projectKey, int requestedItems, int totalItems,
                               StreamingResponseBody body) {
    }

    /** A role given on a project (deck A5). */
    public record RoleGrantResult(UUID grantId, String grantee, String projectKey, String responsibility,
                                  Instant grantedAt) {
    }

    public record CustomerView(String customerKey, String displayName, String region, String accountManager,
                               String projectKey) {
    }
}
