package io.contexa.contexacommon.security;

import io.contexa.contexacommon.domain.UserDto;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class UnifiedCustomUserDetailsTest {

    @Test
    @DisplayName("Constructor should store user and create unmodifiable authorities copy")
    void constructor_shouldStoreUserAndUnmodifiableAuthorities() {
        // given
        UserDto user = UserDto.builder()
                .id(1L)
                .username("user@test.com")
                .password("pwd")
                .name("Test")
                .build();
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        // when
        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(user, authorities);

        // then
        assertThat(details.getUser()).isEqualTo(user);
        assertThat(details.getOriginalAuthorities()).containsExactly(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Test
    @DisplayName("Original authorities should be immutable")
    void originalAuthorities_shouldBeImmutable() {
        // given
        UserDto user = UserDto.builder()
                .id(1L)
                .username("user@test.com")
                .password("pwd")
                .name("Test")
                .build();
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(user, authorities);

        // when & then
        assertThatThrownBy(() -> details.getOriginalAuthorities().add(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("Modifying original set should not affect stored authorities")
    void constructor_shouldDefensivelyCopyAuthorities() {
        // given
        UserDto user = UserDto.builder()
                .id(1L)
                .username("user@test.com")
                .password("pwd")
                .name("Test")
                .build();
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(user, authorities);

        // when
        authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));

        // then
        assertThat(details.getOriginalAuthorities()).hasSize(1);
    }

    @Test
    @DisplayName("getAuthorities should return user authorities when not null")
    void getAuthorities_shouldReturnUserAuthorities() {
        // given
        UserDto user = UserDto.builder()
                .id(1L)
                .username("user@test.com")
                .password("pwd")
                .name("Test")
                .build();
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(user, authorities);

        // when & then
        assertThat(details.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("getAuthorities should fallback to originalAuthorities when user authorities are null")
    void getAuthorities_shouldFallbackToOriginalWhenUserAuthoritiesNull() {
        // given
        UserDto user = UserDto.builder()
                .id(1L)
                .username("user@test.com")
                .password("pwd")
                .name("Test")
                .build();
        Set<GrantedAuthority> authorities = new HashSet<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(user, authorities);

        // when
        user.setAuthorities(null);

        // then
        assertThat(details.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }

    @Test
    @DisplayName("getUsername should delegate to user")
    void getUsername_shouldDelegateToUser() {
        // given
        UserDto user = UserDto.builder()
                .id(1L)
                .username("user@test.com")
                .password("pwd")
                .name("Test")
                .build();
        Set<GrantedAuthority> authorities = Set.of(new SimpleGrantedAuthority("ROLE_USER"));

        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(user, authorities);

        // when & then
        assertThat(details.getUsername()).isEqualTo("user@test.com");
    }

    @Test
    @DisplayName("getPassword should delegate to user")
    void getPassword_shouldDelegateToUser() {
        // given
        UserDto user = UserDto.builder()
                .id(1L)
                .username("user@test.com")
                .password("pwd")
                .name("Test")
                .build();
        Set<GrantedAuthority> authorities = Set.of(new SimpleGrantedAuthority("ROLE_USER"));

        UnifiedCustomUserDetails details = new UnifiedCustomUserDetails(user, authorities);

        // when & then
        assertThat(details.getPassword()).isEqualTo("pwd");
    }

    @Test
    @DisplayName("Should be compatible with Spring Security UserDetails interface")
    void shouldBeCompatibleWithUserDetailsInterface() {
        // given
        UserDto user = UserDto.builder()
                .id(1L)
                .username("user@test.com")
                .password("pwd")
                .name("Test")
                .build();
        Set<GrantedAuthority> authorities = Set.of(new SimpleGrantedAuthority("ROLE_USER"));

        // when
        UserDetails userDetails = new UnifiedCustomUserDetails(user, authorities);

        // then
        assertThat(userDetails).isInstanceOf(UserDetails.class);
        assertThat(userDetails.getUsername()).isNotNull();
        assertThat(userDetails.getPassword()).isNotNull();
        assertThat(userDetails.getAuthorities()).isNotEmpty();
    }
}
