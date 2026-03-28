package io.contexa.contexaiam.admin.web.center;

import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.*;
import io.contexa.contexaiam.admin.web.auth.service.RoleService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/admin/access-center")
@RequiredArgsConstructor
@Slf4j
public class AccessCenterController {

    private final UserRepository userRepository;
    private final UserRoleRepository userRoleRepository;
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RoleService roleService;

    // ==================== Main Page ====================

    @GetMapping
    public String accessCenter(
            @RequestParam(required = false, defaultValue = "users") String tab,
            Model model) {
        model.addAttribute("activePage", "access-center");
        model.addAttribute("activeTab", tab);

        // Statistics for overview
        model.addAttribute("userCount", userRepository.count());
        model.addAttribute("groupCount", groupRepository.count());
        model.addAttribute("roleCount", roleRepository.count());
        model.addAttribute("permissionCount", permissionRepository.count());

        return "admin/access-center";
    }

    // ==================== Users Tab API ====================

    @GetMapping("/api/users")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> searchUsers(
            @RequestParam(required = false) String keyword,
            @PageableDefault(size = 20) Pageable pageable) {
        Page<Users> page;
        if (keyword != null && !keyword.isBlank()) {
            page = userRepository.findByUsernameContainingIgnoreCaseOrNameContainingIgnoreCase(
                    keyword, keyword, pageable);
        } else {
            page = userRepository.findAll(pageable);
        }

        List<Map<String, Object>> content = page.getContent().stream().map(u -> {
            Map<String, Object> m = new HashMap<>();
            m.put("id", u.getId());
            m.put("username", u.getUsername());
            m.put("name", u.getName());
            m.put("email", u.getEmail());
            m.put("enabled", u.isEnabled());
            m.put("department", u.getDepartment());
            return m;
        }).toList();

        Map<String, Object> response = new HashMap<>();
        response.put("content", content);
        response.put("totalElements", page.getTotalElements());
        response.put("totalPages", page.getTotalPages());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/api/users/{userId}/detail")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getUserDetail(@PathVariable Long userId) {
        log.error("[AccessCenterController] findByIdWithGroupsRolesAndPermissions userId={}", userId);
        Users user = userRepository.findByIdWithGroupsRolesAndPermissions(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        Map<String, Object> result = new HashMap<>();
        result.put("id", user.getId());
        result.put("username", user.getUsername());
        result.put("name", user.getName());
        result.put("email", user.getEmail());
        result.put("department", user.getDepartment());
        result.put("enabled", user.isEnabled());

        // Groups
        List<Map<String, Object>> groups = user.getUserGroups().stream()
                .map(ug -> {
                    Map<String, Object> g = new HashMap<>();
                    g.put("id", ug.getGroup().getId());
                    g.put("name", ug.getGroup().getName());
                    return g;
                }).toList();
        result.put("groups", groups);

        // Direct roles
        List<Map<String, Object>> directRoles = user.getUserRoles().stream()
                .map(ur -> {
                    Map<String, Object> r = new HashMap<>();
                    r.put("id", ur.getRole().getId());
                    r.put("name", ur.getRole().getRoleName());
                    r.put("desc", ur.getRole().getRoleDesc());
                    r.put("source", "direct");
                    return r;
                }).toList();
        result.put("directRoles", directRoles);

        // Group-inherited roles
        List<Map<String, Object>> groupRoles = user.getUserGroups().stream()
                .flatMap(ug -> ug.getGroup().getGroupRoles().stream()
                        .map(gr -> {
                            Map<String, Object> r = new HashMap<>();
                            r.put("id", gr.getRole().getId());
                            r.put("name", gr.getRole().getRoleName());
                            r.put("desc", gr.getRole().getRoleDesc());
                            r.put("source", "group");
                            r.put("groupName", ug.getGroup().getName());
                            return r;
                        }))
                .toList();
        result.put("groupRoles", groupRoles);

        // Effective permissions (union of all roles' permissions)
        Set<Long> allRoleIds = new HashSet<>();
        user.getUserRoles().forEach(ur -> allRoleIds.add(ur.getRole().getId()));
        user.getUserGroups().forEach(ug ->
                ug.getGroup().getGroupRoles().forEach(gr -> allRoleIds.add(gr.getRole().getId())));

        Set<String> seenPermNames = new HashSet<>();
        List<Map<String, Object>> permissions = new ArrayList<>();
        // Direct role permissions
        user.getUserRoles().stream()
                .flatMap(ur -> ur.getRole().getRolePermissions().stream())
                .forEach(rp -> {
                    if (seenPermNames.add(rp.getPermission().getName())) {
                        Map<String, Object> p = new HashMap<>();
                        p.put("name", rp.getPermission().getName());
                        p.put("friendlyName", rp.getPermission().getFriendlyName());
                        p.put("source", "direct");
                        permissions.add(p);
                    }
                });
        // Group role permissions
        user.getUserGroups().stream()
                .flatMap(ug -> ug.getGroup().getGroupRoles().stream())
                .flatMap(gr -> gr.getRole().getRolePermissions().stream())
                .forEach(rp -> {
                    if (seenPermNames.add(rp.getPermission().getName())) {
                        Map<String, Object> p = new HashMap<>();
                        p.put("name", rp.getPermission().getName());
                        p.put("friendlyName", rp.getPermission().getFriendlyName());
                        p.put("source", "group");
                        permissions.add(p);
                    }
                });
        result.put("permissions", permissions);

        return ResponseEntity.ok(result);
    }

    // ==================== User-Group Assignment ====================

    @PostMapping("/api/users/{userId}/groups")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> updateUserGroups(
            @PathVariable Long userId,
            @RequestBody Map<String, List<Long>> body) {
        try {
            List<Long> groupIds = body.getOrDefault("groupIds", Collections.emptyList());
            Users user = userRepository.findById(userId)
                    .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

            user.getUserGroups().clear();
            groupIds.forEach(gid -> {
                Group group = groupRepository.findById(gid)
                        .orElseThrow(() -> new IllegalArgumentException("Group not found: " + gid));
                user.getUserGroups().add(UserGroup.builder().user(user).group(group).build());
            });
            userRepository.save(user);

            return ResponseEntity.ok(Map.of("success", true, "message", "Groups updated successfully."));
        } catch (Exception e) {
            log.error("Failed to update user groups", e);
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", e.getMessage()));
        }
    }

    // ==================== User-Role Direct Assignment ====================

    @PostMapping("/api/users/{userId}/roles")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> updateUserDirectRoles(
            @PathVariable Long userId,
            @RequestBody Map<String, List<Long>> body) {
        try {
            List<Long> roleIds = body.getOrDefault("roleIds", Collections.emptyList());
            Users user = userRepository.findById(userId)
                    .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

            user.getUserRoles().clear();
            roleIds.forEach(rid -> {
                Role role = roleRepository.findById(rid)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found: " + rid));
                user.getUserRoles().add(UserRole.builder().user(user).role(role).build());
            });
            userRepository.save(user);

            return ResponseEntity.ok(Map.of("success", true, "message", "Direct roles updated successfully."));
        } catch (Exception e) {
            log.error("Failed to update user direct roles", e);
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", e.getMessage()));
        }
    }

    // ==================== Groups Tab API ====================

    @GetMapping("/api/groups")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> getAllGroups() {
        List<Map<String, Object>> groups = groupRepository.findAll().stream().map(g -> {
            Map<String, Object> m = new HashMap<>();
            m.put("id", g.getId());
            m.put("name", g.getName());
            m.put("description", g.getDescription());
            return m;
        }).toList();
        return ResponseEntity.ok(groups);
    }

    @GetMapping("/api/groups/{groupId}/detail")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getGroupDetail(@PathVariable Long groupId) {
        Group group = groupRepository.findById(groupId)
                .orElseThrow(() -> new IllegalArgumentException("Group not found: " + groupId));
        Map<String, Object> result = new HashMap<>();
        result.put("id", group.getId());
        result.put("name", group.getName());
        result.put("description", group.getDescription());

        List<Map<String, Object>> roles = group.getGroupRoles().stream().map(gr -> {
            Map<String, Object> r = new HashMap<>();
            r.put("id", gr.getRole().getId());
            r.put("name", gr.getRole().getRoleName());
            r.put("desc", gr.getRole().getRoleDesc());
            return r;
        }).toList();
        result.put("roles", roles);

        // Members (users in this group)
        List<Map<String, Object>> members = userRepository.findAll().stream()
                .filter(u -> u.getUserGroups().stream().anyMatch(ug -> ug.getGroup().getId().equals(groupId)))
                .map(u -> {
                    Map<String, Object> m = new HashMap<>();
                    m.put("id", u.getId());
                    m.put("username", u.getUsername());
                    m.put("name", u.getName());
                    return m;
                }).toList();
        result.put("members", members);

        return ResponseEntity.ok(result);
    }

    @PostMapping("/api/groups/{groupId}/roles")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> updateGroupRoles(
            @PathVariable Long groupId,
            @RequestBody Map<String, List<Long>> body) {
        try {
            List<Long> roleIds = body.getOrDefault("roleIds", Collections.emptyList());
            Group group = groupRepository.findById(groupId)
                    .orElseThrow(() -> new IllegalArgumentException("Group not found: " + groupId));
            group.getGroupRoles().clear();
            roleIds.forEach(rid -> {
                Role role = roleRepository.findById(rid)
                        .orElseThrow(() -> new IllegalArgumentException("Role not found: " + rid));
                group.getGroupRoles().add(GroupRole.builder().group(group).role(role).build());
            });
            groupRepository.save(group);
            return ResponseEntity.ok(Map.of("success", true, "message", "Group roles updated successfully."));
        } catch (Exception e) {
            log.error("Failed to update group roles", e);
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", e.getMessage()));
        }
    }

    // ==================== Roles Tab API ====================

    @GetMapping("/api/roles")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> getAllRoles() {
        List<Map<String, Object>> roles = roleRepository.findAllWithPermissions().stream().map(r -> {
            Map<String, Object> m = new HashMap<>();
            m.put("id", r.getId());
            m.put("name", r.getRoleName());
            m.put("desc", r.getRoleDesc());
            m.put("permCount", r.getRolePermissions() != null ? r.getRolePermissions().size() : 0);
            return m;
        }).toList();
        return ResponseEntity.ok(roles);
    }

    @GetMapping("/api/roles/{roleId}/detail")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getRoleDetail(@PathVariable Long roleId) {
        Role role = roleService.getRole(roleId);
        Map<String, Object> result = new HashMap<>();
        result.put("id", role.getId());
        result.put("name", role.getRoleName());
        result.put("desc", role.getRoleDesc());

        List<Map<String, Object>> permissions = role.getRolePermissions().stream().map(rp -> {
            Map<String, Object> p = new HashMap<>();
            p.put("id", rp.getPermission().getId());
            p.put("name", rp.getPermission().getName());
            p.put("friendlyName", rp.getPermission().getFriendlyName());
            p.put("description", rp.getPermission().getDescription());
            return p;
        }).toList();
        result.put("permissions", permissions);

        // Users with this role (direct)
        List<Map<String, Object>> directUsers = userRoleRepository.findByRoleIdWithUser(roleId).stream().map(ur -> {
            Map<String, Object> u = new HashMap<>();
            u.put("id", ur.getUser().getId());
            u.put("username", ur.getUser().getUsername());
            u.put("name", ur.getUser().getName());
            return u;
        }).toList();
        result.put("directUsers", directUsers);

        return ResponseEntity.ok(result);
    }

    @PostMapping("/api/roles/{roleId}/permissions")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> updateRolePermissions(
            @PathVariable Long roleId,
            @RequestBody Map<String, List<Long>> body) {
        try {
            List<Long> permissionIds = body.getOrDefault("permissionIds", Collections.emptyList());
            Role role = roleService.getRole(roleId);
            roleService.updateRole(role, permissionIds);
            return ResponseEntity.ok(Map.of("success", true, "message", "Role permissions updated successfully."));
        } catch (Exception e) {
            log.error("Failed to update role permissions", e);
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", e.getMessage()));
        }
    }

    // ==================== Common API ====================

    @GetMapping("/api/all-groups")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> getAllGroupsSimple() {
        return getAllGroups();
    }

    @GetMapping("/api/all-roles")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> getAllRolesSimple() {
        List<Map<String, Object>> roles = roleRepository.findAll().stream().map(r -> {
            Map<String, Object> m = new HashMap<>();
            m.put("id", r.getId());
            m.put("name", r.getRoleName());
            m.put("desc", r.getRoleDesc());
            return m;
        }).toList();
        return ResponseEntity.ok(roles);
    }

    @GetMapping("/api/all-permissions")
    @ResponseBody
    public ResponseEntity<List<Map<String, Object>>> getAllPermissions() {
        List<Map<String, Object>> perms = permissionRepository.findAll().stream().map(p -> {
            Map<String, Object> m = new HashMap<>();
            m.put("id", p.getId());
            m.put("name", p.getName());
            m.put("friendlyName", p.getFriendlyName());
            m.put("description", p.getDescription());
            return m;
        }).toList();
        return ResponseEntity.ok(perms);
    }
}
