package io.contexa.contexacommon.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "admin_menu_role", uniqueConstraints = @UniqueConstraint(columnNames = {"menu_id", "role_name"}))
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AdminMenuRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "menu_id", nullable = false)
    @JsonIgnore
    private AdminMenu menu;

    @Column(name = "role_name", nullable = false, length = 100)
    private String roleName;
}
