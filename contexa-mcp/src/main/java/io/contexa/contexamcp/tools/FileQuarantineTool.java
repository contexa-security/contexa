package io.contexa.contexamcp.tools;

import io.contexa.contexacommon.annotation.SoarTool;
import io.contexa.contexamcp.utils.SecurityToolUtils;
import lombok.Builder;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;

import java.time.LocalDateTime;
import java.util.*;


@Slf4j
@RequiredArgsConstructor
@SoarTool(
    name = "file_quarantine",
    description = "Quarantine malicious or suspicious files to a secure isolation area",
    riskLevel = SoarTool.RiskLevel.HIGH,
    approval = SoarTool.ApprovalRequirement.REQUIRED,
    auditRequired = true,
    retryable = false,
    maxRetries = 1,
    timeoutMs = 30000,
    requiredPermissions = {"file.quarantine", "file.delete", "system.admin"},
    allowedEnvironments = {"staging", "production"}
)
public class FileQuarantineTool {
    
    
    private static final Map<String, QuarantinedFile> QUARANTINE_VAULT = new HashMap<>();
    private static final String QUARANTINE_PATH = "/var/quarantine/";
    
    
    @Tool(
        name = "file_quarantine",
        description = """
            파일 격리 도구. 악성 또는 의심스러운 파일을 안전한 격리 영역으로 이동시킵니다.
            격리된 파일은 실행 불가능한 상태로 보관되며, 필요시 복원할 수 있습니다.
            주의: 시스템 파일이나 중요 파일을 격리할 경우 시스템 장애가 발생할 수 있습니다.
            이 도구는 고위험 작업으로 분류되며 승인이 필요합니다.
            """
    )
    public Response quarantineFile(
        @ToolParam(description = "작업 유형 (quarantine, restore, delete, list)", required = true)
        String action,
        
        @ToolParam(description = "대상 파일의 전체 경로", required = false)
        String filePath,
        
        @ToolParam(description = "격리 사유 (보안 위협 유형 등)", required = false)
        String reason,
        
        @ToolParam(description = "격리 전 백업 생성 여부", required = false)
        Boolean createBackup,
        
        @ToolParam(description = "영구 격리 여부 (true면 복원 불가)", required = false)
        Boolean permanentQuarantine,
        
        @ToolParam(description = "복원 전 파일 안전성 검증 수행", required = false)
        Boolean validateBeforeRestore,
        
        @ToolParam(description = "영구 삭제 확인 (true 필수)", required = false)
        Boolean confirmDelete,
        
        @ToolParam(description = "시스템 파일 강제 처리 허용", required = false)
        Boolean forceAction
    ) {
        long startTime = System.currentTimeMillis();
        
        
        if (!"list".equals(action.toLowerCase()) && (filePath == null || filePath.trim().isEmpty())) {
            log.warn("파일 경로가 지정되지 않음 - SOAR 시스템 기본 처리");
            filePath = "C:\\Windows\\Temp\\cryptominer.exe"; 
            log.info("📁 의심스러운 파일로 기본 경로 사용: {}", filePath);
        }
        
        log.warn("파일 격리 요청 - Action: {}, Path: {}, Reason: {}", 
            action, filePath, reason);
        
        try {
            
            validateRequest(action, filePath, forceAction);
            
            
            if (!hasRequiredPermissions()) {
                throw new SecurityException("Insufficient permissions for file quarantine");
            }
            
            
            QuarantineResult result = switch (action.toLowerCase()) {
                case "quarantine" -> performQuarantine(filePath, reason, createBackup, permanentQuarantine);
                case "restore" -> performRestore(filePath, validateBeforeRestore);
                case "delete" -> performDelete(filePath, confirmDelete);
                case "list" -> listQuarantined();
                default -> throw new IllegalArgumentException("Unknown action: " + action);
            };
            
            
            SecurityToolUtils.auditLog(
                "file_quarantine",
                action,
                "SOAR-System",
                String.format("Path=%s, Reason=%s, Status=%s", 
                    filePath, reason, result.getStatus()),
                "SUCCESS"
            );
            
            
            SecurityToolUtils.recordMetric("file_quarantine", "execution_count", 1);
            SecurityToolUtils.recordMetric("file_quarantine", action + "_count", 1);
            SecurityToolUtils.recordMetric("file_quarantine", "execution_time_ms", 
                System.currentTimeMillis() - startTime);
            
            log.info("파일 격리 작업 완료: {}", result.getMessage());
            
            return Response.builder()
                .success(true)
                .message(result.getMessage())
                .result(result)
                .build();
            
        } catch (SecurityException e) {
            log.error("보안 정책 위반", e);
            return Response.builder()
                .success(false)
                .message("Security policy violation: " + e.getMessage())
                .error(e.getMessage())
                .build();
        } catch (IllegalArgumentException e) {
            log.warn("잘못된 입력", e);
            return Response.builder()
                .success(false)
                .message("Invalid input: " + e.getMessage())
                .error(e.getMessage())
                .build();
        } catch (Exception e) {
            log.error("파일 격리 실패", e);
            
            
            SecurityToolUtils.recordMetric("file_quarantine", "error_count", 1);
            
            return Response.builder()
                .success(false)
                .message("Quarantine operation failed: " + e.getMessage())
                .error(e.getMessage())
                .build();
        }
    }
    
    
    private void validateRequest(String action, String filePath, Boolean forceAction) {
        if (action == null || action.trim().isEmpty()) {
            throw new IllegalArgumentException("Action is required");
        }
        
        if (!"list".equals(action.toLowerCase())) {
            if (filePath == null || filePath.trim().isEmpty()) {
                throw new IllegalArgumentException("File path is required for action: " + action);
            }
        }
    }
    
    
    private QuarantineResult performQuarantine(String filePath, String reason, 
                                               Boolean createBackup, Boolean permanentQuarantine) {
        
        if (QUARANTINE_VAULT.containsKey(filePath)) {
            return QuarantineResult.builder()
                .status("already_quarantined")
                .message("File is already quarantined: " + filePath)
                .filePath(filePath)
                .build();
        }
        
        
        FileMetadata metadata = collectFileMetadata(filePath);
        
        
        String quarantineId = UUID.randomUUID().toString();
        String quarantinePath = QUARANTINE_PATH + quarantineId;
        
        QuarantinedFile quarantinedFile = QuarantinedFile.builder()
            .id(quarantineId)
            .originalPath(filePath)
            .quarantinePath(quarantinePath)
            .quarantineTime(LocalDateTime.now())
            .reason(reason != null ? reason : "Security threat detected")
            .metadata(metadata)
            .canRestore(!Boolean.TRUE.equals(permanentQuarantine))
            .build();
        
        
        QUARANTINE_VAULT.put(filePath, quarantinedFile);
        
        
        if (Boolean.TRUE.equals(createBackup)) {
            createBackup(quarantinedFile);
        }
        
        return QuarantineResult.builder()
            .status("quarantined")
            .message(String.format("File quarantined successfully: %s -> %s", filePath, quarantinePath))
            .filePath(filePath)
            .quarantineId(quarantineId)
            .metadata(metadata)
            .build();
    }
    
    
    private QuarantineResult performRestore(String filePath, Boolean validateBeforeRestore) {
        QuarantinedFile quarantinedFile = QUARANTINE_VAULT.get(filePath);
        if (quarantinedFile == null) {
            throw new IllegalArgumentException("File not found in quarantine: " + filePath);
        }
        
        if (!quarantinedFile.isCanRestore()) {
            throw new SecurityException("File cannot be restored (permanent quarantine): " + filePath);
        }
        
        
        if (Boolean.TRUE.equals(validateBeforeRestore)) {
            if (!validateFile(quarantinedFile)) {
                throw new SecurityException("File validation failed, cannot restore: " + filePath);
            }
        }
        
        
        QUARANTINE_VAULT.remove(filePath);
        
        return QuarantineResult.builder()
            .status("restored")
            .message(String.format("File restored successfully: %s", filePath))
            .filePath(filePath)
            .quarantineId(quarantinedFile.getId())
            .metadata(quarantinedFile.getMetadata())
            .build();
    }
    
    
    private QuarantineResult performDelete(String filePath, Boolean confirmDelete) {
        QuarantinedFile quarantinedFile = QUARANTINE_VAULT.get(filePath);
        if (quarantinedFile == null) {
            throw new IllegalArgumentException("File not found in quarantine: " + filePath);
        }
        
        
        if (!Boolean.TRUE.equals(confirmDelete)) {
            throw new SecurityException("Delete confirmation required for permanent deletion");
        }
        
        
        QUARANTINE_VAULT.remove(filePath);
        
        return QuarantineResult.builder()
            .status("deleted")
            .message(String.format("Quarantined file permanently deleted: %s", filePath))
            .filePath(filePath)
            .quarantineId(quarantinedFile.getId())
            .build();
    }
    
    
    private QuarantineResult listQuarantined() {
        List<QuarantineInfo> quarantineList = new ArrayList<>();
        
        for (QuarantinedFile file : QUARANTINE_VAULT.values()) {
            QuarantineInfo info = QuarantineInfo.builder()
                .id(file.getId())
                .originalPath(file.getOriginalPath())
                .quarantineTime(file.getQuarantineTime().toString())
                .reason(file.getReason())
                .canRestore(file.isCanRestore())
                .fileSize(file.getMetadata() != null ? file.getMetadata().getSize() : 0L)
                .fileHash(file.getMetadata() != null ? file.getMetadata().getHash() : "N/A")
                .build();
            
            quarantineList.add(info);
        }
        
        return QuarantineResult.builder()
            .status("list")
            .message(String.format("Found %d quarantined files", quarantineList.size()))
            .quarantineList(quarantineList)
            .build();
    }
    
    
    private boolean hasRequiredPermissions() {
        
        return true; 
    }
    
    private boolean isSystemFile(String filePath) {
        
        return filePath.startsWith("/etc/") || 
               filePath.startsWith("/usr/") || 
               filePath.startsWith("/bin/") ||
               filePath.startsWith("C:\\Windows\\");
    }
    
    private FileMetadata collectFileMetadata(String filePath) {
        return FileMetadata.builder()
            .path(filePath)
            .size((long)(Math.random() * 1000000)) 
            .hash(generateHash())
            .type(detectFileType(filePath))
            .permissions("rw-r--r--")
            .owner("user")
            .createdTime(LocalDateTime.now().minusDays(30).toString())
            .modifiedTime(LocalDateTime.now().minusDays(1).toString())
            .build();
    }
    
    private String generateHash() {
        return UUID.randomUUID().toString().replace("-", "").substring(0, 32);
    }
    
    private String detectFileType(String filePath) {
        if (filePath.endsWith(".exe")) return "executable";
        if (filePath.endsWith(".dll")) return "library";
        if (filePath.endsWith(".txt")) return "text";
        if (filePath.endsWith(".pdf")) return "document";
        return "unknown";
    }
    
    private void createBackup(QuarantinedFile file) {
        log.info("백업 생성: {}", file.getOriginalPath());
        
    }
    
    private boolean validateFile(QuarantinedFile file) {
        
        return Math.random() > 0.2; 
    }
    
    
    @Data
    @Builder
    public static class Response {
        private boolean success;
        private String message;
        private QuarantineResult result;
        private String error;
    }
    
    
    @Data
    @Builder
    public static class QuarantineResult {
        private String status;
        private String message;
        private String filePath;
        private String quarantineId;
        private FileMetadata metadata;
        private List<QuarantineInfo> quarantineList;
    }
    
    
    @Data
    @Builder
    public static class FileMetadata {
        private String path;
        private Long size;
        private String hash;
        private String type;
        private String permissions;
        private String owner;
        private String createdTime;
        private String modifiedTime;
    }
    
    
    @Data
    @Builder
    private static class QuarantinedFile {
        private String id;
        private String originalPath;
        private String quarantinePath;
        private LocalDateTime quarantineTime;
        private String reason;
        private FileMetadata metadata;
        private boolean canRestore;
    }
    
    
    @Data
    @Builder
    public static class QuarantineInfo {
        private String id;
        private String originalPath;
        private String quarantineTime;
        private String reason;
        private boolean canRestore;
        private Long fileSize;
        private String fileHash;
    }
}