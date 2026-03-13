package io.contexa.contexacommon.security.authority;

import io.contexa.contexacommon.entity.Role;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoleAuthorityTest {

    @Test
    @DisplayName("Constructor should create authority from valid role")
    void constructor_shouldCreateAuthorityFromValidRole() {
        // given
        Role role = Role.builder()
                .id(1L)
                .roleName("admin")
                .build();

        // when
        RoleAuthority authority = new RoleAuthority(role);

        // then
        assertThat(authority.getRoleId()).isEqualTo(1L);
        assertThat(authority.getRoleName()).isEqualTo("admin");
    }

    @Test
    @DisplayName("Constructor should throw exception when role is null")
    void constructor_shouldThrowWhenRoleIsNull() {
        assertThatThrownBy(() -> new RoleAuthority(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Constructor should throw exception when role ID is null")
    void constructor_shouldThrowWhenRoleIdIsNull() {
        // given
        Role role = Role.builder()
                .roleName("admin")
                .build();

        // when & then
        assertThatThrownBy(() -> new RoleAuthority(role))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Constructor should throw exception when role name is empty")
    void constructor_shouldThrowWhenRoleNameIsEmpty() {
        // given
        Role role = Role.builder()
                .id(1L)
                .roleName("")
                .build();

        // when & then
        assertThatThrownBy(() -> new RoleAuthority(role))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("getAuthority should add ROLE_ prefix and uppercase when not present")
    void getAuthority_shouldAddRolePrefixAndUppercase() {
        // given
        Role role = Role.builder()
                .id(1L)
                .roleName("admin")
                .build();

        RoleAuthority authority = new RoleAuthority(role);

        // when & then
        assertThat(authority.getAuthority()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    @DisplayName("getAuthority should keep ROLE_ prefix when already present")
    void getAuthority_shouldKeepExistingRolePrefix() {
        // given
        Role role = Role.builder()
                .id(1L)
                .roleName("ROLE_ADMIN")
                .build();

        RoleAuthority authority = new RoleAuthority(role);

        // when & then
        assertThat(authority.getAuthority()).isEqualTo("ROLE_ADMIN");
    }

    @Test
    @DisplayName("getAuthority should convert lowercase name to uppercase with ROLE_ prefix")
    void getAuthority_shouldConvertToUppercase() {
        // given
        Role role = Role.builder()
                .id(1L)
                .roleName("user")
                .build();

        RoleAuthority authority = new RoleAuthority(role);

        // when & then
        assertThat(authority.getAuthority()).isEqualTo("ROLE_USER");
    }

    @Test
    @DisplayName("equals should return true for same roleId and roleName")
    void equals_shouldReturnTrueForSameIdAndName() {
        // given
        Role role1 = Role.builder().id(1L).roleName("admin").build();
        Role role2 = Role.builder().id(1L).roleName("admin").build();

        RoleAuthority authority1 = new RoleAuthority(role1);
        RoleAuthority authority2 = new RoleAuthority(role2);

        // when & then
        assertThat(authority1).isEqualTo(authority2);
    }

    @Test
    @DisplayName("equals should return false for different roleId")
    void equals_shouldReturnFalseForDifferentId() {
        // given
        Role role1 = Role.builder().id(1L).roleName("admin").build();
        Role role2 = Role.builder().id(2L).roleName("admin").build();

        RoleAuthority authority1 = new RoleAuthority(role1);
        RoleAuthority authority2 = new RoleAuthority(role2);

        // when & then
        assertThat(authority1).isNotEqualTo(authority2);
    }

    @Test
    @DisplayName("equals should return false for different roleName")
    void equals_shouldReturnFalseForDifferentName() {
        // given
        Role role1 = Role.builder().id(1L).roleName("admin").build();
        Role role2 = Role.builder().id(1L).roleName("user").build();

        RoleAuthority authority1 = new RoleAuthority(role1);
        RoleAuthority authority2 = new RoleAuthority(role2);

        // when & then
        assertThat(authority1).isNotEqualTo(authority2);
    }

    @Test
    @DisplayName("hashCode should be equal for equal objects")
    void hashCode_shouldBeEqualForEqualObjects() {
        // given
        Role role1 = Role.builder().id(1L).roleName("admin").build();
        Role role2 = Role.builder().id(1L).roleName("admin").build();

        RoleAuthority authority1 = new RoleAuthority(role1);
        RoleAuthority authority2 = new RoleAuthority(role2);

        // when & then
        assertThat(authority1.hashCode()).isEqualTo(authority2.hashCode());
    }

    @Test
    @DisplayName("equals should return false when compared with null")
    void equals_shouldReturnFalseForNull() {
        // given
        Role role = Role.builder().id(1L).roleName("admin").build();
        RoleAuthority authority = new RoleAuthority(role);

        // when & then
        assertThat(authority).isNotEqualTo(null);
    }

    @Test
    @DisplayName("equals should return false when compared with different type")
    void equals_shouldReturnFalseForDifferentType() {
        // given
        Role role = Role.builder().id(1L).roleName("admin").build();
        RoleAuthority authority = new RoleAuthority(role);

        // when & then
        assertThat(authority).isNotEqualTo("not a RoleAuthority");
    }
}
