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

import io.contexa.contexaiam.admin.web.auth.dto.AffectedPolicyDtos.AffectedPoliciesResponse;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.entity.FunctionCatalog;
import io.contexa.contexaiam.admin.web.metadata.service.FunctionCatalogService;
import io.contexa.contexacommon.entity.Permission;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Controller
@RequestMapping("/contexa/admin/permissions")
@RequiredArgsConstructor
@Slf4j
public class PermissionController {

    private final PermissionService permissionService;
    private final ModelMapper modelMapper;
    private final FunctionCatalogService functionCatalogService;
    private final MessageSource messageSource;

    private String msg(String key, Object... args) {
        return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
    }

    @GetMapping
    public String getPermissions(@RequestParam(required = false) String keyword,
                                 @PageableDefault(size = 15, sort = "id", direction = Sort.Direction.DESC) Pageable pageable,
                                 Model model) {
        Page<Permission> permissionPage = permissionService.searchPermissions(keyword, pageable);
        Page<PermissionDto> dtoPage = permissionPage.map(this::convertToDto);
        model.addAttribute("permissions", dtoPage.getContent());
        model.addAttribute("page", dtoPage);
        model.addAttribute("keyword", keyword);
        return "contexa/admin/permissions";
    }

    @GetMapping("/register")
    public String registerPermissionForm(Model model) {
        model.addAttribute("permission", new PermissionDto());

        return "contexa/admin/permissiondetails";
    }

    @PostMapping
    public String createPermission(@ModelAttribute("permission") PermissionDto permissionDto, RedirectAttributes ra) {
        Permission permission = modelMapper.map(permissionDto, Permission.class);
        permissionService.createPermission(permission);
        ra.addFlashAttribute("message", msg("msg.permission.created", permission.getName()));
        return "redirect:/contexa/admin/permissions";
    }

    @GetMapping("/{id}")
    public String permissionDetails(@PathVariable Long id, Model model) {
        Permission permission = permissionService.getPermission(id)
                .orElseThrow(() -> new IllegalArgumentException("Invalid permission ID: " + id));

        PermissionDto permissionDto = convertToDto(permission);
        model.addAttribute("permission", permissionDto);

        return "contexa/admin/permissiondetails";
    }

    @PostMapping("/{id}/edit")
    public String updatePermission(@PathVariable Long id, @ModelAttribute("permission") PermissionDto permissionDto,
                                   RedirectAttributes ra) {
        Permission permission = permissionService.updatePermission(id, permissionDto);
        ra.addFlashAttribute("message", msg("msg.permission.updated", permission.getName()));
        return "redirect:/contexa/admin/permissions";
    }

    private void addCommonAttributesToModel(Model model) {
        List<FunctionCatalog> allActiveFunctions = functionCatalogService.findAllActiveFunctions();
        model.addAttribute("allFunctions", allActiveFunctions);
    }

    @GetMapping("/api/{id}/affected-policies")
    @ResponseBody
    public ResponseEntity<AffectedPoliciesResponse> getAffectedPolicies(@PathVariable Long id) {
        return permissionService.getAffectedPolicies(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/delete/{id}")
    public String deletePermission(@PathVariable Long id, RedirectAttributes ra) {
        try {
            permissionService.deletePermission(id);
            ra.addFlashAttribute("message", msg("msg.permission.deleted", id));
        } catch (Exception e) {
            ra.addFlashAttribute("errorMessage", msg("msg.permission.delete.error", e.getMessage()));
        }
        return "redirect:/contexa/admin/permissions";
    }

    private PermissionDto convertToDto(Permission permission) {
        PermissionDto dto = modelMapper.map(permission, PermissionDto.class);
        if (permission.getManagedResource() != null) {
            dto.setLinkedResourceId(permission.getManagedResource().getId());
            dto.setLinkedResourceIdentifier(permission.getManagedResource().getResourceIdentifier());
        }
        return dto;
    }
}
