package io.contexa.contexacommon.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Map;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto implements Serializable {

    private static final long serialVersionUID = 1L;

    
    private Long id;
    private String username;
    private String password;
    private String name;
    private boolean mfaEnabled;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastMfaUsedAt;
    private String preferredMfaFactor;
    private String lastUsedMfaFactor;

    
    private Collection<? extends GrantedAuthority> authorities;

    
    private java.util.List<String> roles;
    private java.util.List<String> permissions;
    private java.util.List<Long> selectedGroupIds;

    
    private Double trustScore;
    private String trustTier;
    private Map<String, Object> trustMetadata;
}
