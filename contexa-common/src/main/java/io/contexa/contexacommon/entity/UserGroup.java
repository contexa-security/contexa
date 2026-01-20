package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "USER_GROUPS") 
@IdClass(UserGroupId.class) 
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
    private Users user; 

    @Id
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "group_id")
    @ToString.Exclude
    private Group group; 

    
    
    

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


@NoArgsConstructor
@AllArgsConstructor
class UserGroupId implements Serializable {
    private Long user;  
    private Long group; 

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
