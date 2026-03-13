package io.contexa.contexacommon.security.authority;

import io.contexa.contexacommon.entity.Permission;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PermissionAuthorityTest {

    @Test
    @DisplayName("Constructor should create authority from valid permission")
    void constructor_shouldCreateAuthorityFromValidPermission() {
        // given
        Permission permission = Permission.builder()
                .id(1L)
                .name("read_users")
                .targetType("USER")
                .actionType("READ")
                .build();

        // when
        PermissionAuthority authority = new PermissionAuthority(permission);

        // then
        assertThat(authority.getPermissionId()).isEqualTo(1L);
        assertThat(authority.getPermissionName()).isEqualTo("read_users");
        assertThat(authority.getTargetType()).isEqualTo("USER");
        assertThat(authority.getActionType()).isEqualTo("READ");
    }

    @Test
    @DisplayName("Constructor should throw exception when permission is null")
    void constructor_shouldThrowWhenPermissionIsNull() {
        assertThatThrownBy(() -> new PermissionAuthority(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Constructor should throw exception when permission ID is null")
    void constructor_shouldThrowWhenPermissionIdIsNull() {
        // given
        Permission permission = Permission.builder()
                .name("read_users")
                .build();

        // when & then
        assertThatThrownBy(() -> new PermissionAuthority(permission))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Constructor should throw exception when permission name is empty")
    void constructor_shouldThrowWhenPermissionNameIsEmpty() {
        // given
        Permission permission = Permission.builder()
                .id(1L)
                .name("")
                .build();

        // when & then
        assertThatThrownBy(() -> new PermissionAuthority(permission))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("getAuthority should return uppercase permission name")
    void getAuthority_shouldReturnUppercasePermissionName() {
        // given
        Permission permission = Permission.builder()
                .id(1L)
                .name("read_users")
                .build();

        PermissionAuthority authority = new PermissionAuthority(permission);

        // when & then
        assertThat(authority.getAuthority()).isEqualTo("READ_USERS");
    }

    @Test
    @DisplayName("getAuthority should keep already uppercase name unchanged")
    void getAuthority_shouldKeepUppercaseNameUnchanged() {
        // given
        Permission permission = Permission.builder()
                .id(1L)
                .name("READ_USERS")
                .build();

        PermissionAuthority authority = new PermissionAuthority(permission);

        // when & then
        assertThat(authority.getAuthority()).isEqualTo("READ_USERS");
    }

    @Test
    @DisplayName("equals should return true for same permissionId and permissionName")
    void equals_shouldReturnTrueForSameIdAndName() {
        // given
        Permission permission1 = Permission.builder().id(1L).name("read_users").build();
        Permission permission2 = Permission.builder().id(1L).name("read_users").build();

        PermissionAuthority authority1 = new PermissionAuthority(permission1);
        PermissionAuthority authority2 = new PermissionAuthority(permission2);

        // when & then
        assertThat(authority1).isEqualTo(authority2);
    }

    @Test
    @DisplayName("equals should return false for different permissionId")
    void equals_shouldReturnFalseForDifferentId() {
        // given
        Permission permission1 = Permission.builder().id(1L).name("read_users").build();
        Permission permission2 = Permission.builder().id(2L).name("read_users").build();

        PermissionAuthority authority1 = new PermissionAuthority(permission1);
        PermissionAuthority authority2 = new PermissionAuthority(permission2);

        // when & then
        assertThat(authority1).isNotEqualTo(authority2);
    }

    @Test
    @DisplayName("equals should return false for different permissionName")
    void equals_shouldReturnFalseForDifferentName() {
        // given
        Permission permission1 = Permission.builder().id(1L).name("read_users").build();
        Permission permission2 = Permission.builder().id(1L).name("write_users").build();

        PermissionAuthority authority1 = new PermissionAuthority(permission1);
        PermissionAuthority authority2 = new PermissionAuthority(permission2);

        // when & then
        assertThat(authority1).isNotEqualTo(authority2);
    }

    @Test
    @DisplayName("hashCode should be equal for equal objects")
    void hashCode_shouldBeEqualForEqualObjects() {
        // given
        Permission permission1 = Permission.builder().id(1L).name("read_users").build();
        Permission permission2 = Permission.builder().id(1L).name("read_users").build();

        PermissionAuthority authority1 = new PermissionAuthority(permission1);
        PermissionAuthority authority2 = new PermissionAuthority(permission2);

        // when & then
        assertThat(authority1.hashCode()).isEqualTo(authority2.hashCode());
    }

    @Test
    @DisplayName("equals should return false when compared with null")
    void equals_shouldReturnFalseForNull() {
        // given
        Permission permission = Permission.builder().id(1L).name("read_users").build();
        PermissionAuthority authority = new PermissionAuthority(permission);

        // when & then
        assertThat(authority).isNotEqualTo(null);
    }

    @Test
    @DisplayName("equals should return false when compared with different type")
    void equals_shouldReturnFalseForDifferentType() {
        // given
        Permission permission = Permission.builder().id(1L).name("read_users").build();
        PermissionAuthority authority = new PermissionAuthority(permission);

        // when & then
        assertThat(authority).isNotEqualTo("not a PermissionAuthority");
    }
}
