/*
 * Copyright 2026 The Contexa Project
 *
 * The Contexa Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
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
