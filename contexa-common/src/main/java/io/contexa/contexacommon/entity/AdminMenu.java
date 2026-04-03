package io.contexa.contexacommon.entity;

import jakarta.persistence.*;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "admin_menu")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AdminMenu {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 255)
    private String url;

    @Column(length = 2000)
    private String icon;

    @Column(name = "parent_id")
    private Long parentId;

    @Column(name = "menu_order", nullable = false)
    @Builder.Default
    private int menuOrder = 0;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(name = "menu_type", nullable = false, length = 20)
    @Builder.Default
    private String menuType = "CORE";

    @Column(name = "data_page", length = 50)
    private String dataPage;

    @OneToMany(mappedBy = "menu", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @Builder.Default
    private Set<AdminMenuRole> roles = new HashSet<>();

    public void addRole(String roleName) {
        AdminMenuRole role = new AdminMenuRole();
        role.setMenu(this);
        role.setRoleName(roleName);
        this.roles.add(role);
    }

    public void clearRoles() {
        this.roles.clear();
    }
}
