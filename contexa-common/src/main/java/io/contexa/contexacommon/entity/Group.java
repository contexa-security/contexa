package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "APP_GROUP") // 'GROUP'은 SQL 예약어일 수 있으므로 'APP_GROUP'으로 변경
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Group implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "group_id")
    private Long id;

    @Column(name = "group_name", unique = true, nullable = false)
    private String name; // 그룹 이름 (예: "영업부", "개발부", "임원진")

    @Column(name = "description")
    private String description;

    // 그룹에 속한 사용자들 (UserGroup 조인 엔티티를 통한 OneToMany 관계)
    @OneToMany(mappedBy = "group", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    @ToString.Exclude
    private Set<UserGroup> userGroups = new HashSet<>();

    // 그룹에 할당된 역할들 (GroupRole 조인 엔티티를 통한 OneToMany 관계)
    @OneToMany(mappedBy = "group", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    @ToString.Exclude
    private Set<GroupRole> groupRoles = new HashSet<>();

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Group group = (Group) o;
        return id.equals(group.id); // 이름으로 동등성 판단
    }

    @Override
    public int hashCode() {
        return id.hashCode(); // 이름으로 해시코드 생성
    }
}
