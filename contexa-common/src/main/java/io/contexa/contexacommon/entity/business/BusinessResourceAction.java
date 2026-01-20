package io.contexa.contexacommon.entity.business;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "BUSINESS_RESOURCE_ACTION")
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class BusinessResourceAction {

    @EmbeddedId
    private BusinessResourceActionId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("businessResourceId") 
    @JoinColumn(name = "business_resource_id")
    private BusinessResource businessResource;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("businessActionId") 
    @JoinColumn(name = "business_action_id")
    private BusinessAction businessAction;

    @Column(name = "mapped_permission_name", nullable = false)
    private String mappedPermissionName;

    
    
    
    @Embeddable
    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class BusinessResourceActionId implements Serializable {
        private static final long serialVersionUID = 1L;

        private Long businessResourceId;
        private Long businessActionId;

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            BusinessResourceActionId that = (BusinessResourceActionId) o;
            return Objects.equals(businessResourceId, that.businessResourceId) && Objects.equals(businessActionId, that.businessActionId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(businessResourceId, businessActionId);
        }
    }
}
