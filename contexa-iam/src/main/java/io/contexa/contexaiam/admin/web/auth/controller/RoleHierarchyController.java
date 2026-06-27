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
package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.dto.RoleHierarchyDtos.ActiveHierarchyView;
import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.impl.RoleHierarchyService;
import io.contexa.contexaiam.domain.dto.RoleDetailDto;
import io.contexa.contexaiam.domain.dto.GroupWithRolesDto;
import io.contexa.contexaiam.domain.dto.RoleHierarchyDto;
import io.contexa.contexaiam.domain.dto.RoleMetadataDto;
import io.contexa.contexaiam.domain.entity.RoleHierarchyEntity;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.GroupRole;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.RolePermission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/contexa/admin/role-hierarchies")
@RequiredArgsConstructor
@Slf4j
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
public class RoleHierarchyController {

    private final RoleHierarchyService roleHierarchyService;
    private final ModelMapper modelMapper;
    private final RoleService roleService;
    private final GroupService groupService;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String getRoleHierarchies(@RequestParam(required = false) String keyword,
                                     @RequestParam(defaultValue = "0") int page,
                                     Model model) {
        PageRequest pageable = PageRequest.of(page, 20, Sort.by(Sort.Direction.DESC, "id"));
        Page<RoleHierarchyEntity> hierarchyPage = roleHierarchyService.searchRoleHierarchies(keyword, pageable);
        Page<RoleHierarchyDto> dtoPage = hierarchyPage.map(h -> modelMapper.map(h, RoleHierarchyDto.class));
        model.addAttribute("hierarchies", dtoPage.getContent());
        model.addAttribute("hierarchyPage", dtoPage);
        model.addAttribute("keyword", keyword);
        return "contexa/admin/role-hierarchies";
    }

    @GetMapping("/register")
    public String registerRoleHierarchyForm(Model model) {
        model.addAttribute("hierarchy", new RoleHierarchyDto());
        prepareHierarchyFormModel(model, new ArrayList<>(), null);
        return "contexa/admin/role-hierarchy-details";
    }

    @PostMapping
    @Transactional(transactionManager = "contexaTransactionManager")
    public String createRoleHierarchy(@ModelAttribute("hierarchy") RoleHierarchyDto hierarchyDto, RedirectAttributes ra) {
        try {
            RoleHierarchyEntity entity = modelMapper.map(hierarchyDto, RoleHierarchyEntity.class);
            roleHierarchyService.createRoleHierarchy(entity);
            ra.addFlashAttribute("message", msg("msg.hierarchy.created"));
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
            return "redirect:/contexa/admin/role-hierarchies/register";
        }
        return "redirect:/contexa/admin/role-hierarchies";
    }

    @GetMapping("/{id}")
    public String roleHierarchyDetails(@PathVariable Long id, Model model) {
        try {
            RoleHierarchyEntity entity = roleHierarchyService.getRoleHierarchy(id)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid RoleHierarchy ID: " + id));

            RoleHierarchyDto dto = modelMapper.map(entity, RoleHierarchyDto.class);

            String hierarchyString = entity.getHierarchyString();

            if (hierarchyString != null && hierarchyString.contains("\\n")) {
                hierarchyString = hierarchyString.replace("\\n", "\n");
            }

            List<RoleHierarchyDto.HierarchyPair> pairs = new ArrayList<>();
            if (hierarchyString != null && !hierarchyString.trim().isEmpty()) {

                String[] lines = hierarchyString.split("\n");

                for (String line : lines) {
                    line = line.trim();
                    if (line.contains(">")) {
                        String[] parts = line.split("\\s*>\\s*");
                        if (parts.length == 2) {
                            String parent = parts[0].trim();
                            String child = parts[1].trim();

                            pairs.add(new RoleHierarchyDto.HierarchyPair(parent, child));
                        }
                    }
                }
            }

            dto.setHierarchyPairs(pairs);
            model.addAttribute("hierarchy", dto);
            prepareHierarchyFormModel(model, pairs, id);

        } catch (Exception e) {
            log.error("Error loading role hierarchy details for ID: {}", id, e);
            model.addAttribute("error", msg("msg.hierarchy.load.error"));
            return "redirect:/contexa/admin/role-hierarchies";
        }

        return "contexa/admin/role-hierarchy-details";
    }

    @PostMapping("/{id}/edit")
    @Transactional(transactionManager = "contexaTransactionManager")
    public String updateRoleHierarchy(@PathVariable Long id, @ModelAttribute("hierarchy") RoleHierarchyDto hierarchyDto, RedirectAttributes ra) {
        try {
            hierarchyDto.setId(id);
            RoleHierarchyEntity entity = modelMapper.map(hierarchyDto, RoleHierarchyEntity.class);
            roleHierarchyService.updateRoleHierarchy(entity);
            ra.addFlashAttribute("message", msg("msg.hierarchy.updated"));
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
            return "redirect:/contexa/admin/role-hierarchies/" + id;
        }
        return "redirect:/contexa/admin/role-hierarchies";
    }

    @PostMapping("/delete/{id}")
    @Transactional(transactionManager = "contexaTransactionManager")
    public String deleteRoleHierarchy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            roleHierarchyService.deleteRoleHierarchy(id);
            ra.addFlashAttribute("message", msg("msg.hierarchy.deleted", id));
        } catch (Exception e) {
            ra.addFlashAttribute("error", e.getMessage());
            log.error("Error deleting role hierarchy ID: {}", id, e);
        }
        return "redirect:/contexa/admin/role-hierarchies";
    }

    @PostMapping("/{id}/activate")
    @Transactional(transactionManager = "contexaTransactionManager")
    public String activateRoleHierarchy(@PathVariable Long id, RedirectAttributes ra) {
        try {
            boolean newState = roleHierarchyService.activateRoleHierarchy(id);
            String status = newState ? msg("msg.hierarchy.status.activated") : msg("msg.hierarchy.status.deactivated");
            ra.addFlashAttribute("message", msg("msg.hierarchy.status.changed", id, status));
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("error", e.getMessage());
        }
        return "redirect:/contexa/admin/role-hierarchies";
    }

    private void prepareHierarchyFormModel(Model model, List<RoleHierarchyDto.HierarchyPair> existingPairs, Long excludeId) {
        try {

            List<Group> allGroups = groupService.getAllGroups();

            List<GroupWithRolesDto> groupsWithRoles = allGroups.stream()
                    .map(group -> {
                        GroupWithRolesDto gwrDto = new GroupWithRolesDto();
                        gwrDto.setGroupId(group.getId());
                        gwrDto.setGroupName(group.getName());
                        gwrDto.setGroupDescription(group.getDescription());

                        List<RoleDetailDto> roleDetails = groupRoles(group).stream()
                                .map(GroupRole::getRole)
                                .filter(role -> role != null && !role.isExpression())
                                .map(role -> {
                                    RoleDetailDto rdDto = new RoleDetailDto();
                                    rdDto.setRoleId(role.getId());
                                    rdDto.setRoleName(role.getRoleName());
                                    rdDto.setRoleDesc(role.getRoleDesc() != null ? role.getRoleDesc() : role.getRoleName());

                                    List<String> permissions = rolePermissions(role).stream()
                                            .filter(rp -> rp.getPermission() != null)
                                            .map(rp -> rp.getPermission().getFriendlyName())
                                            .filter(name -> name != null)
                                            .sorted()
                                            .collect(Collectors.toList());
                                    rdDto.setPermissions(permissions);

                                    return rdDto;
                                })
                                .collect(Collectors.toList());

                        gwrDto.setRoles(roleDetails);
                        return gwrDto;
                    })
                    .filter(gwrDto -> !gwrDto.getRoles().isEmpty())
                    .collect(Collectors.toList());

            List<RoleMetadataDto> ungroupedRoles = roleService.getRolesWithoutExpression().stream()
                    .filter(role -> allGroups.stream()
                            .noneMatch(group -> groupRoles(group).stream()
                                    .anyMatch(gr -> gr.getRole() != null && gr.getRole().getId().equals(role.getId()))))
                    .map(role -> modelMapper.map(role, RoleMetadataDto.class))
                    .collect(Collectors.toList());

            model.addAttribute("groupsWithRoles", groupsWithRoles);
            model.addAttribute("ungroupedRoles", ungroupedRoles);
            model.addAttribute("hierarchyPairs", existingPairs);

            List<RoleMetadataDto> allRoles = roleService.getRolesWithoutExpression().stream()
                    .filter(Role::isEnabled)
                    .map(role -> modelMapper.map(role, RoleMetadataDto.class))
                    .collect(Collectors.toList());
            model.addAttribute("allRoles", allRoles);

            // Active hierarchies for client-side cross-validation (exclude current editing hierarchy)
            List<ActiveHierarchyView> activeHierarchies = roleHierarchyService.getAllRoleHierarchies().stream()
                    .filter(h -> Boolean.TRUE.equals(h.getIsActive()))
                    .filter(h -> excludeId == null || !excludeId.equals(h.getId()))
                    .map(h -> new ActiveHierarchyView(h.getId(), h.getDescription(), h.getHierarchyString()))
                    .collect(Collectors.toList());
            model.addAttribute("activeHierarchies", activeHierarchies);

        } catch (Exception e) {
            log.error("Error preparing hierarchy form model", e);
            model.addAttribute("groupsWithRoles", new ArrayList<>());
            model.addAttribute("ungroupedRoles", new ArrayList<>());
            model.addAttribute("allRoles", new ArrayList<>());
            model.addAttribute("activeHierarchies", new ArrayList<>());
        }
    }

    private Collection<GroupRole> groupRoles(Group group) {
        return group.getGroupRoles() != null ? group.getGroupRoles() : List.of();
    }

    private Collection<RolePermission> rolePermissions(Role role) {
        return role.getRolePermissions() != null ? role.getRolePermissions() : List.of();
    }
}
