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
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorException;
import io.contexa.contexaiam.admin.web.auth.service.PermissionService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.common.ConsoleFault;
import io.contexa.contexaiam.domain.dto.PermissionDto;
import io.contexa.contexaiam.domain.dto.RoleDto;
import io.contexa.contexacommon.entity.Role;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.support.RequestContextUtils;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.annotation.Qualifier;

@Slf4j
@Controller
@RequestMapping("/contexa/admin/roles")
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class RoleController {

	private final RoleService roleService;
	private final PermissionService permissionService;
	private final ModelMapper modelMapper;
	private final MessageSource messageSource;


	public RoleController(RoleService roleService, PermissionService permissionService, @Qualifier("contexaModelMapper") ModelMapper modelMapper, MessageSource messageSource) {
		this.roleService = roleService;
		this.permissionService = permissionService;
		this.modelMapper = modelMapper;
		this.messageSource = messageSource;
	}

	private String msg(String key, Object... args) {
		return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
	}

	@GetMapping
	public String getRoles(@RequestParam(required = false) String keyword,
						   @PageableDefault(size = 15, sort = "id", direction = Sort.Direction.DESC) Pageable pageable,
						   Model model) {
		Page<Role> rolePage = roleService.searchRoles(keyword, pageable);
		Page<RoleDto> dtoPage = rolePage.map(role -> {
			RoleDto dto = modelMapper.map(role, RoleDto.class);
			dto.setPermissionCount(role.getRolePermissions() != null ? role.getRolePermissions().size() : 0);
			return dto;
		});
		model.addAttribute("roles", dtoPage.getContent());
		model.addAttribute("page", dtoPage);
		model.addAttribute("keyword", keyword);
		return "contexa/admin/roles";
	}

	@GetMapping("/register")
	public String registerRoleForm(Model model) {
		// A refused registration comes back here with what was typed.
		RoleDto roleDto = model.getAttribute("role") instanceof RoleDto typed ? typed : null;
		if (roleDto == null) {
			roleDto = new RoleDto();
			roleDto.setEnabled(true);
		}
		model.addAttribute("role", roleDto);
		model.addAttribute("permissionList", permissionService.getAllPermissions());
		model.addAttribute("selectedPermissionIds",
				roleDto.getPermissionIds() != null ? roleDto.getPermissionIds() : new ArrayList<Long>());
		return "contexa/admin/rolesdetails";
	}

	@PostMapping
	@Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
	public String createRole(@ModelAttribute("role") RoleDto roleDto, RedirectAttributes ra) {
		try {
			Role role = modelMapper.map(roleDto, Role.class);
			roleService.createRole(role, roleDto.getPermissionIds());
			ra.addFlashAttribute("message", msg("msg.role.created"));
			return "redirect:/contexa/admin/roles";
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", textOf(e, "create role " + roleDto.getRoleName()));
			ra.addFlashAttribute("role", roleDto);
			return "redirect:/contexa/admin/roles/register";
		}
	}

	@GetMapping("/{id}")
	public String getRoleDetails(@PathVariable Long id, Model model, RedirectAttributes ra) {
		// Looked up without an exception: one thrown through the service would mark this read-only transaction for
		// rollback, and its commit would end the request with a server error.
		Role role = roleService.findRole(id).orElse(null);
		if (role == null) {
			log.warn("[RoleManagement] No role with ID {}", id);
			ra.addFlashAttribute("errorMessage", msg("msg.role.not.found.id", String.valueOf(id)));
			return "redirect:/contexa/admin/roles";
		}
		RoleDto roleDto = modelMapper.map(role, RoleDto.class);
		List<Long> selectedPermissionIds = role.getRolePermissions().stream().map(rp -> rp.getPermission().getId()).toList();

		List<PermissionDto> permissionList = permissionService.getAllPermissions().stream()
				.map(p -> modelMapper.map(p, PermissionDto.class))
				.toList();

		model.addAttribute("role", roleDto);
		model.addAttribute("permissionList", permissionList);
		model.addAttribute("selectedPermissionIds", selectedPermissionIds);
		return "contexa/admin/rolesdetails";
	}

	@PostMapping("/{id}/edit")
	@Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
	public String updateRole(@PathVariable Long id, @ModelAttribute("role") RoleDto roleDto, RedirectAttributes ra) {
		try {
			roleDto.setId(id);
			Role role = modelMapper.map(roleDto, Role.class);
			roleService.updateRole(role, roleDto.getPermissionIds());
			ra.addFlashAttribute("message", msg("msg.role.updated"));
			return "redirect:/contexa/admin/roles";
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", textOf(e, "update role " + id));
			return "redirect:/contexa/admin/roles/" + id;
		}
	}

	@GetMapping("/api/{id}/affected-policies")
	@ResponseBody
	public ResponseEntity<AffectedPoliciesResponse> getAffectedPolicies(@PathVariable Long id) {
		return roleService.getAffectedPolicies(id)
				.map(ResponseEntity::ok)
				.orElseGet(() -> ResponseEntity.notFound().build());
	}

	@PostMapping("/delete/{id}")
	@Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
	public String deleteRole(@PathVariable Long id, RedirectAttributes ra) {
		try {
			roleService.deleteRole(id);
			ra.addFlashAttribute("message", msg("msg.role.deleted"));
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", textOf(e, "delete role " + id));
		}
		return "redirect:/contexa/admin/roles";
	}

	/**
	 * A change of a role that would take the console's last active administrator, thrown past the handlers above, goes
	 * back to the list of roles with the reason: nothing of it was kept (the refusal rolls the transaction back), and the
	 * address left is the list's, not the one of the request that was refused.
	 */
	@ExceptionHandler(LastAdministratorException.class)
	public String lastAdministrator(LastAdministratorException refusal, HttpServletRequest request) {
		log.warn("[RoleManagement] {}", refusal.getMessage());
		RequestContextUtils.getOutputFlashMap(request).put("errorMessage", refusal.getMessage());
		return "redirect:/contexa/admin/roles";
	}

	/** What the administrator is told of a failed change: a refusal is logged as one, a fault with its stack. */
	private String textOf(Exception failure, String doing) {
		if (ConsoleFault.isRefusal(failure)) {
			log.warn("[RoleManagement] Could not {}: {}", doing, failure.getMessage());
		}
		return ConsoleFault.textOf(failure, log, doing);
	}
}
