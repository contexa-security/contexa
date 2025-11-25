package io.contexa.contexaiam.domain.dto;

import io.contexa.contexacommon.dto.UserDto;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
public class UserContext implements UserDetails {
    private UserDto userDto;
    private final List<GrantedAuthority> roles;

    public UserContext(UserDto userDto, List<GrantedAuthority> roles) {
      this.userDto = userDto;
      this.roles = roles;
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }
    @Override
    public String getPassword() {
        return userDto.getPassword();
    }
    @Override
    public String getUsername() {
        return userDto.getUsername();
    }
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    @Override
    public boolean isEnabled() {
        return true;
    }
}
