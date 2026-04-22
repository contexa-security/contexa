package io.contexa.contexaiam.admin.web.center.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.contexa.contexaiam.security.xacml.pap.dto.AIPolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.DuplicatePolicyDto;
import io.contexa.contexaiam.security.xacml.pap.dto.FullValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyConflictDto;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyImpactReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyMatrixReport;
import io.contexa.contexaiam.security.xacml.pap.dto.PolicyValidationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationReport;
import io.contexa.contexaiam.security.xacml.pap.dto.SimulationTestCase;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

public final class PolicyCenterDtos {

    private PolicyCenterDtos() {
    }

    private static <T, R> List<R> mapList(List<T> source, Function<T, R> mapper) {
        return source == null ? null : source.stream()
                .map(item -> item == null ? null : mapper.apply(item))
                .toList();
    }

    private static <T, R> List<List<R>> mapNestedList(List<List<T>> source, Function<T, R> mapper) {
        return source == null
                ? null
                : source.stream()
                .map(row -> mapList(row, mapper))
                .toList();
    }

    public record PolicyPageResponse<T>(
            List<T> content,
            long totalElements,
            int totalPages,
            int number,
            int size
    ) {
    }

    public record PolicyAvailablePermissionsResponse(
            List<PolicyPermissionResponse> content,
            long totalElements,
            int totalPages,
            int number,
            int size,
            Set<Long> alreadyMappedIds,
            Map<String, List<Long>> rolePermissionMap
    ) {
    }

    public record PolicyRoleResponse(
            Long id,
            String roleName,
            String roleDesc,
            boolean expression,
            boolean enabled,
            LocalDateTime createdAt,
            LocalDateTime updatedAt,
            String createdBy,
            List<Long> permissionIds,
            int permissionCount
    ) {
    }

    public record PolicyPermissionResponse(
            Long id,
            String name,
            String friendlyName,
            String description,
            String targetType,
            String actionType,
            String conditionExpression,
            Long managedResourceId,
            String managedResourceIdentifier
    ) {
    }

    public record PolicyResourceResponse(
            Long id,
            String resourceIdentifier,
            String resourceType,
            String httpMethod,
            String friendlyName,
            String status,
            String serviceOwner,
            String sourceCodeLocation,
            String apiDocsUrl,
            String description,
            String createdAt
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicySystemStatsResponse(
            Long roleCount,
            Long permissionCount,
            Long conditionCount,
            Long policyCount,
            Long resourceTotal,
            Long resourceNeedsDefinition,
            Long resourcePermissionCreated,
            Long resourcePolicyConnected
    ) {
        public static PolicySystemStatsResponse basic(
                long roleCount,
                long permissionCount,
                long conditionCount,
                long policyCount) {
            return new PolicySystemStatsResponse(
                    roleCount,
                    permissionCount,
                    conditionCount,
                    policyCount,
                    null,
                    null,
                    null,
                    null
            );
        }
    }

    public record PolicySpelPermissionResponse(
            Long id,
            String name,
            String expression,
            String description,
            String category
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyQuickCreateResponse(
            Boolean success,
            Long policyId,
            String message,
            String warning
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyActionResponse(
            Boolean success,
            String message,
            Integer updated
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyBatchCreateResponse(
            Boolean success,
            List<PolicyBatchItemResponse> results,
            Integer created,
            Integer total,
            String message
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyBatchItemResponse(
            String resourceIdentifier,
            String status,
            String reason,
            Long policyId,
            String policyName
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyMigrationResponse(
            Boolean success,
            Integer migrated,
            String message
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyCleanupResponse(
            Boolean success,
            Integer deleted,
            String message
    ) {
    }

    public interface PolicyApiResponse {
    }

    public record PolicyErrorResponse(
            String error
    ) implements PolicyApiResponse {
    }

    public record PolicyFullValidationResponse(
            long totalPolicies,
            String healthStatus,
            List<PolicyConflictResponse> conflicts,
            List<PolicyDuplicateResponse> duplicates
    ) {
        public static PolicyFullValidationResponse from(FullValidationReport report) {
            return new PolicyFullValidationResponse(
                    report.totalPolicies(),
                    report.healthStatus(),
                    mapList(report.conflicts(), PolicyConflictResponse::from),
                    mapList(report.duplicates(), PolicyDuplicateResponse::from)
            );
        }
    }

    public record PolicyValidationResponse(
            List<PolicyConflictResponse> conflicts,
            List<PolicyDuplicateResponse> duplicates,
            boolean canCreate,
            String blockedReason
    ) {
        public static PolicyValidationResponse from(PolicyValidationReport report) {
            return new PolicyValidationResponse(
                    mapList(report.conflicts(), PolicyConflictResponse::from),
                    mapList(report.duplicates(), PolicyDuplicateResponse::from),
                    report.canCreate(),
                    report.blockedReason()
            );
        }
    }

    public record PolicyConflictResponse(
            Long newPolicyId,
            String newPolicyName,
            Long existingPolicyId,
            String existingPolicyName,
            String conflictDescription,
            String severity
    ) {
        public static PolicyConflictResponse from(PolicyConflictDto conflict) {
            return new PolicyConflictResponse(
                    conflict.newPolicyId(),
                    conflict.newPolicyName(),
                    conflict.existingPolicyId(),
                    conflict.existingPolicyName(),
                    conflict.conflictDescription(),
                    conflict.severity() == null ? null : conflict.severity().name()
            );
        }
    }

    public record PolicyDuplicateResponse(
            String reason,
            List<Long> policyIds,
            String policySignature,
            String type
    ) {
        public static PolicyDuplicateResponse from(DuplicatePolicyDto duplicate) {
            return new PolicyDuplicateResponse(
                    duplicate.reason(),
                    duplicate.policyIds(),
                    duplicate.policySignature(),
                    duplicate.type() == null ? null : duplicate.type().name()
            );
        }
    }

    public record PolicyAiValidationResponse(
            List<ValidationItem> items,
            boolean canApprove,
            String blockedReason
    ) {
        public static PolicyAiValidationResponse from(AIPolicyValidationReport report) {
            return new PolicyAiValidationResponse(
                    mapList(report.items(), ValidationItem::from),
                    report.canApprove(),
                    report.blockedReason()
            );
        }

        public record ValidationItem(
                String checkName,
                String result,
                String detail
        ) {
            public static ValidationItem from(AIPolicyValidationReport.ValidationItem item) {
                return new ValidationItem(
                        item.checkName(),
                        item.result() == null ? null : item.result().name(),
                        item.detail()
                );
            }
        }
    }

    public record PolicySimulationResponse(
            List<SimulationResult> results,
            SimulationSummary summary
    ) {
        public record SimulationResult(
                TestCase testCase,
                String username,
                DecisionDetail currentResult,
                DecisionDetail newResult,
                boolean changed,
                String changeType
        ) {
            public static SimulationResult from(SimulationReport.SimulationResult result) {
                return new SimulationResult(
                        TestCase.from(result.testCase()),
                        result.username(),
                        DecisionDetail.from(result.currentResult()),
                        DecisionDetail.from(result.newResult()),
                        result.changed(),
                        result.changeType()
                );
            }
        }

        public record TestCase(
                Long userId,
                String targetType,
                String path,
                String httpMethod
        ) {
            public static TestCase from(SimulationTestCase testCase) {
                if (testCase == null) {
                    return null;
                }
                return new TestCase(
                        testCase.userId(),
                        testCase.targetType(),
                        testCase.path(),
                        testCase.httpMethod()
                );
            }
        }

        public record DecisionDetail(
                String decision,
                Long matchedPolicyId,
                String matchedPolicyName,
                String matchedExpression,
                List<String> userAuthorities
        ) {
            public static DecisionDetail from(SimulationReport.DecisionDetail detail) {
                if (detail == null) {
                    return null;
                }
                return new DecisionDetail(
                        detail.decision(),
                        detail.matchedPolicyId(),
                        detail.matchedPolicyName(),
                        detail.matchedExpression(),
                        detail.userAuthorities()
                );
            }
        }

        public record SimulationSummary(
                int unchanged,
                int allowToDeny,
                int denyToAllow,
                int otherChanges
        ) {
            public static SimulationSummary from(SimulationReport.SimulationSummary summary) {
                if (summary == null) {
                    return null;
                }
                return new SimulationSummary(
                        summary.unchanged(),
                        summary.allowToDeny(),
                        summary.denyToAllow(),
                        summary.otherChanges()
                );
            }
        }

        public static PolicySimulationResponse from(SimulationReport report) {
            return new PolicySimulationResponse(
                    mapList(report.results(), SimulationResult::from),
                    SimulationSummary.from(report.summary())
            );
        }
    }

    public record PolicyImpactResponse(
            int affectedUserCount,
            List<AffectedUser> affectedUsers,
            List<AffectedResource> affectedResources,
            AccessChangeSummary accessChangeSummary
    ) implements PolicyApiResponse {
        public static PolicyImpactResponse from(PolicyImpactReport report) {
            return new PolicyImpactResponse(
                    report.affectedUserCount(),
                    mapList(report.affectedUsers(), AffectedUser::from),
                    mapList(report.affectedResources(), AffectedResource::from),
                    AccessChangeSummary.from(report.accessChangeSummary())
            );
        }

        public record AffectedUser(
                Long userId,
                String username,
                List<String> roles,
                List<String> groups,
                String currentAccess,
                String newAccess,
                String changeType
        ) {
            public static AffectedUser from(PolicyImpactReport.AffectedUser user) {
                return new AffectedUser(
                        user.userId(),
                        user.username(),
                        user.roles(),
                        user.groups(),
                        user.currentAccess(),
                        user.newAccess(),
                        user.changeType()
                );
            }
        }

        public record AffectedResource(
                String identifier,
                String httpMethod,
                int currentPolicyCount,
                List<String> matchedPolicyNames
        ) {
            public static AffectedResource from(PolicyImpactReport.AffectedResource resource) {
                return new AffectedResource(
                        resource.identifier(),
                        resource.httpMethod(),
                        resource.currentPolicyCount(),
                        resource.matchedPolicyNames()
                );
            }
        }

        public record AccessChangeSummary(
                int gained,
                int lost,
                int changed,
                int unchanged
        ) {
            public static AccessChangeSummary from(PolicyImpactReport.AccessChangeSummary summary) {
                if (summary == null) {
                    return null;
                }
                return new AccessChangeSummary(
                        summary.gained(),
                        summary.lost(),
                        summary.changed(),
                        summary.unchanged()
                );
            }
        }
    }

    public record PolicyMatrixResponse(
            List<ResourceEntry> resources,
            List<String> roles,
            List<List<MatrixCell>> cells,
            List<ConflictCell> conflictCells,
            int totalRoles,
            int totalPages,
            int currentPage
    ) {
        public static PolicyMatrixResponse from(PolicyMatrixReport report) {
            return new PolicyMatrixResponse(
                    mapList(report.resources(), ResourceEntry::from),
                    report.roles(),
                    mapNestedList(report.cells(), MatrixCell::from),
                    mapList(report.conflictCells(), ConflictCell::from),
                    report.totalRoles(),
                    report.totalPages(),
                    report.currentPage()
            );
        }

        public record ResourceEntry(
                String identifier,
                String httpMethod,
                String friendlyName
        ) {
            public static ResourceEntry from(PolicyMatrixReport.ResourceEntry resource) {
                return new ResourceEntry(
                        resource.identifier(),
                        resource.httpMethod(),
                        resource.friendlyName()
                );
            }
        }

        public record MatrixCell(
                String access,
                Long policyId,
                String policyName,
                boolean inherited
        ) {
            public static MatrixCell from(PolicyMatrixReport.MatrixCell cell) {
                return new MatrixCell(
                        cell.access(),
                        cell.policyId(),
                        cell.policyName(),
                        cell.inherited()
                );
            }
        }

        public record ConflictCell(
                int row,
                int col,
                String severity
        ) {
            public static ConflictCell from(PolicyMatrixReport.ConflictCell cell) {
                return new ConflictCell(
                        cell.row(),
                        cell.col(),
                        cell.severity()
                );
            }
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyVersionSummaryResponse(
            Integer versionNumber,
            String changeType,
            String changedBy,
            String changeReason,
            String changedAt
    ) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record PolicyVersionSnapshotResponse(
            Integer versionNumber,
            String changeType,
            String changedBy,
            String changeReason,
            String changedAt,
            String snapshot,
            String error
    ) {
    }

    public record PolicyRollbackRequest(
            String reason
    ) {
    }

    public record PolicyVersionDiffResponse(
            String field,
            String before,
            String after
    ) {
    }
}
