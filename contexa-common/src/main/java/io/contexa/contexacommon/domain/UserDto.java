package io.contexa.contexacommon.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import lombok.ToString;
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
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;
    private String name;
    private String email;
    private String phone;
    private String department;
    private String position;
    private boolean enabled;
    private boolean accountLocked;
    private boolean credentialsExpired;
    private boolean externalAuthOnly;
    private int failedLoginAttempts;
    private LocalDateTime lockExpiresAt;
    private boolean mfaEnabled;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastMfaUsedAt;
    private String preferredMfaFactor;
    private String lastUsedMfaFactor;
    private LocalDateTime lastLoginAt;
    private String lastLoginIp;
    private LocalDateTime passwordChangedAt;
    private String locale;
    private String timezone;
    private Collection<? extends GrantedAuthority> authorities;
    private java.util.List<String> roles;
    private java.util.List<String> permissions;
    private java.util.List<Long> selectedGroupIds;
    private Double trustScore;
    private String trustTier;
    private Map<String, Object> trustMetadata;
}
