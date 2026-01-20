package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "GROUP_ROLES") 
@IdClass(GroupRoleId.class) 
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
    private Group group; 

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id")
    @ToString.Exclude
    private Role role; 

    
    
    

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


@NoArgsConstructor
@AllArgsConstructor
class GroupRoleId implements Serializable {
    private Long group; 
    private Long role;  

}
