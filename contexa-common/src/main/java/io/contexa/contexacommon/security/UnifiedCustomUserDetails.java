package io.contexa.contexacommon.security;

import io.contexa.contexacommon.domain.UserDto;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


@Getter
public class UnifiedCustomUserDetails implements UserDetails {

    private final UserDto user;
    private final Set<GrantedAuthority> originalAuthorities;  

    
    public UnifiedCustomUserDetails(UserDto user, Set<GrantedAuthority> authorities) {
        this.user = user;
        this.originalAuthorities = Collections.unmodifiableSet(new HashSet<>(authorities));
        
        this.user.setAuthorities(this.originalAuthorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        
        
        Collection<? extends GrantedAuthority> adjustedAuthorities = user.getAuthorities();
        return adjustedAuthorities != null ? adjustedAuthorities : originalAuthorities;
    }

    public UserDto getAccount() {
        return user;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
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
