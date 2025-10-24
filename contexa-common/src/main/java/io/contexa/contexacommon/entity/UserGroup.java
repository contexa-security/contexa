package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "USER_GROUPS") // User와 Group의 조인 테이블
@IdClass(UserGroupId.class) // 복합 PK를 위한 @IdClass 사용
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class UserGroup implements Serializable {
    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id")
    @ToString.Exclude
    private Users user; // 사용자 엔티티

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "group_id")
    @ToString.Exclude
    private Group group; // 그룹 엔티티

    // 추가 속성 (예: 그룹 가입일, 그룹 내 직위 등)
    // @Column(name = "joined_at")
    // private Instant joinedAt;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserGroup userGroup = (UserGroup) o;
        return Objects.equals(user, userGroup.user) &&
                Objects.equals(group, userGroup.group);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user, group);
    }
}

// 복합 PK를 위한 ID 클래스
@NoArgsConstructor
@AllArgsConstructor
class UserGroupId implements Serializable {
    private Long user;  // Users 엔티티의 ID 타입과 일치해야 함
    private Long group; // Group 엔티티의 ID 타입과 일치해야 함

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        UserGroupId that = (UserGroupId) o;
        return Objects.equals(user, that.user) && Objects.equals(group, that.group);
    }

    @Override
    public int hashCode() {
        return Objects.hash(user, group);
    }
}
