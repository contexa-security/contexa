package io.contexa.contexacommon.domain.context;

import io.contexa.contexacommon.enums.AuditRequirement;
import io.contexa.contexacommon.enums.SecurityLevel;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;


@Getter
@Setter
public abstract class IAMContext extends DomainContext {
    
    private final SecurityLevel securityLevel;
    private final AuditRequirement auditRequirement;
    private final Map<String, Object> iamMetadata;
    
    private String organizationId;
    private String tenantId;
    private List<String> userRoles;
    private List<String> userPermissions;

    protected IAMContext(SecurityLevel securityLevel, AuditRequirement auditRequirement) {
        super();
        this.securityLevel = securityLevel;
        this.auditRequirement = auditRequirement;
        this.iamMetadata = new ConcurrentHashMap<>();
    }
    
    protected IAMContext(String userId, String sessionId, SecurityLevel securityLevel, AuditRequirement auditRequirement) {
        super(userId, sessionId);
        this.securityLevel = securityLevel;
        this.auditRequirement = auditRequirement;
        this.iamMetadata = new ConcurrentHashMap<>();
    }
    
    @Override
    public String getDomainType() {
        return "IAM";
    }
    
    @Override
    public int getPriorityLevel() {
        return securityLevel.getLevel();
    }

    public abstract String getIAMContextType();

    public void addIAMMetadata(String key, Object value) {
        this.iamMetadata.put(key, value);
    }

    public <T> T getIAMMetadata(String key, Class<T> type) {
        Object value = iamMetadata.get(key);
        return type.isInstance(value) ? (T) value : null;
    }

    public Map<String, Object> getAllIAMMetadata() { return Map.copyOf(iamMetadata); }

}
