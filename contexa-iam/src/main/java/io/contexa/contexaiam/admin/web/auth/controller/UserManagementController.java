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

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.LastAdministratorException;
import io.contexa.contexaiam.admin.web.auth.service.PasswordPolicyService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexaiam.admin.web.auth.service.VerificationCoverageService;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexaiam.common.ConsoleFault;
import io.contexa.contexaiam.domain.dto.UserListDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.support.RequestContextUtils;
import org.springframework.security.access.prepost.PreAuthorize;

import java.util.List;

@Slf4j
@Controller
@RequestMapping("/contexa/admin/users")
@RequiredArgsConstructor
@Transactional(transactionManager = "contexaTransactionManager", readOnly = true)
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
public class UserManagementController {

	private final UserManagementService userManagementService;
	private final RoleService roleService;
	private final GroupService groupService;
	private final PasswordPolicyService passwordPolicyService;
	private final MessageSource messageSource;
	private VerificationCoverageService verificationCoverage;

	/** Q-1: who could not answer a CHALLENGE, shown on the list. */
	@Autowired(required = false)
	public void setVerificationCoverage(VerificationCoverageService verificationCoverage) {
		this.verificationCoverage = verificationCoverage;
	}

	private long usersWithoutFactor() {
		if (verificationCoverage == null) {
			return 0;
		}
		try {
			return verificationCoverage.usersWithoutFactor();
		} catch (RuntimeException e) {
			log.error("[UserManagement] Could not count the users who cannot answer a CHALLENGE: {}", e.toString());
			return 0;
		}
	}

	private String msg(String key, Object... args) {
		return messageSource.getMessage(key, args, LocaleContextHolder.getLocale());
	}

	@GetMapping
	public String getUsers(@RequestParam(required = false) String keyword,
						   @PageableDefault(size = 15, sort = "id", direction = Sort.Direction.DESC) Pageable pageable,
						   Model model) {
		Page<UserListDto> dtoPage = userManagementService.getUsers(keyword, pageable);
		model.addAttribute("users", dtoPage.getContent());
		model.addAttribute("page", dtoPage);
		model.addAttribute("keyword", keyword);
		model.addAttribute("usersWithoutFactor", usersWithoutFactor());
		return "contexa/admin/users";
	}

	@GetMapping("/new")
	public String showCreateForm(Model model) {
		UserDto userDto = new UserDto();
		// A new account can sign in unless the administrator turns it off: left off, it was refused as if its password
		// were wrong, and nothing on the form said why.
		userDto.setEnabled(true);
		List<Role> roleList = roleService.getRolesWithoutExpression();
		List<Group> groupList = groupService.getAllGroups();

		model.addAttribute("user", userDto);
		model.addAttribute("roleList", roleList);
		model.addAttribute("groupList", groupList);
		model.addAttribute("selectedGroupIds", List.of());
		model.addAttribute("policy", passwordPolicyService.getCurrentPolicy());

		return "contexa/admin/userdetails";
	}

	@GetMapping("/{id}")
	public String getUser(@PathVariable Long id, Model model, RedirectAttributes ra) {
		try {
			// Looked up without an exception: one thrown through the service would mark this read-only transaction for
			// rollback, and its commit would end the request with a server error.
			UserDto userDto = userManagementService.findUser(id).orElse(null);
			if (userDto == null) {
				return toListWithoutUser(id, ra);
			}
			List<Role> roleList = roleService.getRolesWithoutExpression();
			List<Group> groupList = groupService.getAllGroups();

			List<Long> selectedGroupIds = userDto.getSelectedGroupIds();
			if (selectedGroupIds == null) {
				selectedGroupIds = List.of();
			}

			model.addAttribute("user", userDto);
			model.addAttribute("roleList", roleList);
			model.addAttribute("groupList", groupList);
			model.addAttribute("selectedGroupIds", selectedGroupIds);
			model.addAttribute("policy", passwordPolicyService.getCurrentPolicy());

			return "contexa/admin/userdetails";
		} catch (IllegalArgumentException e) {
			ra.addFlashAttribute("errorMessage", e.getMessage());
			log.warn("Failed to load user details: {}", e.getMessage());
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", msg("msg.user.load.failed", ConsoleFault.textOf(e)));
			log.error("Error loading user details for ID: {}", id, e);
		}
		return "redirect:/contexa/admin/users";
	}

	@PutMapping("/{id}")
	@Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
	public String updateUser(@PathVariable Long id,
							 @ModelAttribute("user") UserDto userDto,
							 @RequestParam(value = "selectedGroupIds", required = false) List<Long> selectedGroupIds,
							 RedirectAttributes ra) {
		// A user who is not there is refused by the service; the user's page then goes back to the list and says so.
		try {
			userDto.setId(id);
			userDto.setSelectedGroupIds(selectedGroupIds);
			userManagementService.modifyUser(userDto);
			ra.addFlashAttribute("message", msg("msg.user.updated", userDto.getUsername()));
		} catch (LastAdministratorException e) {
			ra.addFlashAttribute("errorMessage", textOf(e, "modify user " + id));
			return "redirect:/contexa/admin/users/" + id;
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", msg("msg.user.update.error", textOf(e, "modify user " + id)));
			return "redirect:/contexa/admin/users/" + id;
		}
		return "redirect:/contexa/admin/users";
	}

	@PostMapping("/{id}")
	@Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
	public String updateUserPost(@PathVariable Long id,
								 @ModelAttribute("user") UserDto userDto,
								 @RequestParam(value = "selectedGroupIds", required = false) List<Long> selectedGroupIds,
								 RedirectAttributes ra) {
		return updateUser(id, userDto, selectedGroupIds, ra);
	}

	@PostMapping("")
	@Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
	public String createUser(@ModelAttribute("user") UserDto userDto,
							 @RequestParam(value = "selectedGroupIds", required = false) List<Long> selectedGroupIds,
							 Model model,
							 RedirectAttributes ra) {
		try {
			userDto.setSelectedGroupIds(selectedGroupIds);
			userManagementService.createUser(userDto);
			ra.addFlashAttribute("message", msg("msg.user.created", userDto.getUsername()));
		} catch (Exception e) {
			model.addAttribute("errorMessage", textOf(e, "create user " + userDto.getUsername()));
			model.addAttribute("user", userDto);
			model.addAttribute("roleList", roleService.getRolesWithoutExpression());
			model.addAttribute("groupList", groupService.getAllGroups());
			model.addAttribute("selectedGroupIds", selectedGroupIds != null ? selectedGroupIds : List.of());
			model.addAttribute("policy", passwordPolicyService.getCurrentPolicy());
			return "contexa/admin/userdetails";
		}
		return "redirect:/contexa/admin/users";
	}

	@PostMapping("/{id}/unlock")
	@Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
	public String unlockUser(@PathVariable Long id, RedirectAttributes ra) {
		try {
			if (userManagementService.unlockUser(id)) {
				ra.addFlashAttribute("message", msg("msg.user.unlocked"));
			} else {
				ra.addFlashAttribute("errorMessage", msg("msg.user.not.locked"));
			}
		} catch (IllegalArgumentException e) {
			ra.addFlashAttribute("errorMessage", e.getMessage());
			return "redirect:/contexa/admin/users";
		}
		return "redirect:/contexa/admin/users/" + id;
	}

	@DeleteMapping("/{id}")
	@Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
	public String removeUser(@PathVariable Long id, RedirectAttributes ra) {
		try {
			userManagementService.deleteUser(id);
			ra.addFlashAttribute("message", msg("msg.user.deleted", String.valueOf(id)));
		} catch (LastAdministratorException e) {
			// Told in its own words, as the change of a user that it refuses is.
			ra.addFlashAttribute("errorMessage", textOf(e, "delete user " + id));
		} catch (Exception e) {
			ra.addFlashAttribute("errorMessage", msg("msg.user.delete.error", textOf(e, "delete user " + id)));
		}
		return "redirect:/contexa/admin/users";
	}

	@PostMapping("/delete/{id}")
	@Transactional(transactionManager = "contexaTransactionManager", propagation = Propagation.NOT_SUPPORTED)
	public String removeUserGet(@PathVariable Long id, RedirectAttributes ra) {
		return removeUser(id, ra);
	}

	/**
	 * A change of a user that would take the console's last active administrator, thrown past the handlers above, goes
	 * back to the list of users with the reason: nothing of it was kept (the refusal rolls the transaction back), and the
	 * address left is the list's, not the one of the request that was refused.
	 */
	@ExceptionHandler(LastAdministratorException.class)
	public String lastAdministrator(LastAdministratorException refusal, HttpServletRequest request) {
		log.warn("[UserManagement] {}", refusal.getMessage());
		RequestContextUtils.getOutputFlashMap(request).put("errorMessage", refusal.getMessage());
		return "redirect:/contexa/admin/users";
	}

	/** The list of users, telling that the one asked for is not there. */
	private String toListWithoutUser(Long id, RedirectAttributes ra) {
		log.warn("[UserManagement] No user with ID {}", id);
		ra.addFlashAttribute("errorMessage", msg("msg.user.not.found.id", String.valueOf(id)));
		return "redirect:/contexa/admin/users";
	}

	/** What the administrator is told of a failed change: a refusal is logged as one, a fault with its stack. */
	private String textOf(Exception failure, String doing) {
		if (ConsoleFault.isRefusal(failure)) {
			log.warn("[UserManagement] Could not {}: {}", doing, failure.getMessage());
		}
		return ConsoleFault.textOf(failure, log, doing);
	}
}
