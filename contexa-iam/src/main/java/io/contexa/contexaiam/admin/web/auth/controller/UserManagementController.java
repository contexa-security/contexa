package io.contexa.contexaiam.admin.web.auth.controller;

import io.contexa.contexaiam.admin.web.auth.service.GroupService;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import io.contexa.contexaiam.admin.web.auth.service.UserManagementService;
import io.contexa.contexacommon.domain.UserDto;
import io.contexa.contexaiam.domain.dto.UserListDto;
import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Role;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.util.List;

@Slf4j
@Controller
@RequestMapping("/admin/users")
@RequiredArgsConstructor
public class UserManagementController {

	private final UserManagementService userManagementService;
	private final RoleService roleService;
	private final GroupService groupService;

	@GetMapping
	public String getUsers(Model model) {
		List<UserListDto> users = userManagementService.getUsers();
		model.addAttribute("users", users);
		return "admin/users";
	}

	@GetMapping("/new")
	public String showCreateForm(Model model) {
		UserDto userDto = new UserDto();
		List<Role> roleList = roleService.getRolesWithoutExpression();
		List<Group> groupList = groupService.getAllGroups();

		model.addAttribute("user", userDto);
		model.addAttribute("roleList", roleList);
		model.addAttribute("groupList", groupList);
		model.addAttribute("selectedGroupIds", List.of());

		return "admin/userdetails";
	}

	@GetMapping("/{id}")
	public String getUser(@PathVariable Long id, Model model) {
		UserDto userDto = userManagementService.getUser(id);
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

		return "admin/userdetails";
	}

	@PutMapping("/{id}")
	public String updateUser(@PathVariable Long id,
							 @ModelAttribute("user") UserDto userDto,
							 @RequestParam(value = "selectedGroupIds", required = false) List<Long> selectedGroupIds,
							 RedirectAttributes ra) {
		try {
			userDto.setId(id);
			userDto.setSelectedGroupIds(selectedGroupIds);
			userManagementService.modifyUser(userDto);
			ra.addFlashAttribute("message", "User '" + userDto.getUsername() + "' information has been successfully updated!");
					} catch (Exception e) {
			log.error("Error modifying user: ", e);
			ra.addFlashAttribute("errorMessage", "An error occurred while updating user: " + e.getMessage());
			return "redirect:/admin/users/" + id;
		}
		return "redirect:/admin/users";
	}

	@PostMapping("/{id}")
	public String updateUserPost(@PathVariable Long id,
								 @ModelAttribute("user") UserDto userDto,
								 @RequestParam(value = "selectedGroupIds", required = false) List<Long> selectedGroupIds,
								 RedirectAttributes ra) {
		return updateUser(id, userDto, selectedGroupIds, ra);
	}

	@DeleteMapping("/{id}")
	public String removeUser(@PathVariable Long id, RedirectAttributes ra) {
		try {
			userManagementService.deleteUser(id);
			ra.addFlashAttribute("message", "User (ID: " + id + ") has been successfully deleted!");
					} catch (Exception e) {
			log.error("Error deleting user: ", e);
			ra.addFlashAttribute("errorMessage", "An error occurred while deleting user: " + e.getMessage());
		}
		return "redirect:/admin/users";
	}

	@PostMapping("/delete/{id}")
	public String removeUserGet(@PathVariable Long id, RedirectAttributes ra) {
		return removeUser(id, ra);
	}
}