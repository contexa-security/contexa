package io.contexa.contexaidentity.domain.dto;

import io.contexa.contexacommon.entity.UserGroup;
import io.contexa.contexaidentity.security.filter.MfaGrantedAuthority;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto implements Serializable {
    private Long id;
    private String username;
    private int age;
    private String password;
    private Collection<? extends GrantedAuthority> authorities;
}
