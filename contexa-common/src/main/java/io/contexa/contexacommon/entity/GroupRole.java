package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "GROUP_ROLES") // Group과 Role의 조인 테이블
@IdClass(GroupRoleId.class) // 복합 PK를 위한 @IdClass 사용
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class GroupRole implements Serializable {
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "group_id")
    @ToString.Exclude
    private Group group; // 그룹 엔티티

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id")
    @ToString.Exclude
    private Role role; // 역할 엔티티

    // 추가 속성 (예: 역할 할당일, 역할 유효기간 등)
    // @Column(name = "assigned_at")
    // private Instant assignedAt;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        GroupRole groupRole = (GroupRole) o;
        return Objects.equals(group, groupRole.group) &&
                Objects.equals(role, groupRole.role);
    }

    @Override
    public int hashCode() {
        return Objects.hash(group, role);
    }
}

// 복합 PK를 위한 ID 클래스
@NoArgsConstructor
@AllArgsConstructor
class GroupRoleId implements Serializable {
    private Long group; // Group 엔티티의 ID 타입과 일치해야 함
    private Long role;  // Role 엔티티의 ID 타입과 일치해야 함

}
