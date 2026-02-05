package io.contexa.contexaiam.aiam.components.retriever;

import io.contexa.contexacore.std.components.retriever.ContextRetriever;
import io.contexa.contexacore.std.components.retriever.ContextRetrieverRegistry;
import io.contexa.contexacommon.domain.request.AIRequest;
import io.contexa.contexaiam.aiam.protocol.context.StudioQueryContext;
import io.contexa.contexaiam.aiam.labs.studio.StudioQueryVectorService;
import io.contexa.contexacommon.entity.*;
import io.contexa.contexacommon.repository.GroupRepository;
import io.contexa.contexacommon.repository.PermissionRepository;
import io.contexa.contexacommon.repository.RoleRepository;
import io.contexa.contexacommon.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.beans.factory.annotation.Value;

import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class StudioQueryContextRetriever extends ContextRetriever {

    private final VectorStore vectorStore;
    private final ContextRetrieverRegistry registry;
    private final UserRepository userRepository;
    private final GroupRepository groupRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final StudioQueryVectorService vectorService;

    public StudioQueryContextRetriever(
            VectorStore vectorStore,
            ContextRetrieverRegistry registry,
            UserRepository userRepository,
            GroupRepository groupRepository,
            RoleRepository roleRepository,
            PermissionRepository permissionRepository,
            StudioQueryVectorService vectorService) {
        super(vectorStore);
        this.vectorStore = vectorStore;
        this.registry = registry;
        this.userRepository = userRepository;
        this.groupRepository = groupRepository;
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.vectorService = vectorService;
    }

    @EventListener
    public void onApplicationEvent(ContextRefreshedEvent event) {
        registry.registerRetriever(StudioQueryContext.class, this);
    }

    @Override
    public ContextRetrievalResult retrieveContext(AIRequest<?> request) {
        if (request.getContext() instanceof StudioQueryContext) {
            String contextInfo = retrieveStudioQueryContext((AIRequest<StudioQueryContext>) request);
            return new ContextRetrievalResult(
                    contextInfo,
                    List.of(),
                    Map.of("retrieverType", "StudioQueryContextRetriever", "timestamp", System.currentTimeMillis())
            );
        }
        return super.retrieveContext(request);
    }

    public String retrieveStudioQueryContext(AIRequest<StudioQueryContext> request) {
        try {
            StudioQueryContext context = request.getContext();
            StringBuilder contextBuilder = new StringBuilder();

            String naturalQuery = request.getNaturalLanguageQuery();
            if (naturalQuery == null || naturalQuery.trim().isEmpty()) {
                return "";
            }

            String similarQueryPatterns = searchSimilarQueryPatterns(naturalQuery);
            if (!similarQueryPatterns.isEmpty()) {
                contextBuilder.append("## [Similar Query Pattern Analysis]\n");
                contextBuilder.append(similarQueryPatterns).append("\n\n");
            }

            String authorizationStructure = buildAuthorizationStructure(context);
            contextBuilder.append("## [Current Authorization Structure]\n");
            contextBuilder.append(authorizationStructure).append("\n\n");

            String mappingInfo = buildUserGroupRolePermissionMapping(context);
            contextBuilder.append("## [Permission Mapping Information]\n");
            contextBuilder.append(mappingInfo);

            return contextBuilder.toString();

        } catch (Exception e) {
            log.error("Failed to retrieve Studio Query context", e);
            return "";
        }
    }

    private String searchSimilarQueryPatterns(String naturalQuery) {
        try {
            List<Document> similarQueries = vectorService.findSimilarQueries(naturalQuery, 5);

            String searchQuery = String.format("Authorization Studio query: %s", naturalQuery);
            SearchRequest searchRequest = SearchRequest.builder()
                    .query(searchQuery)
                    .topK(3)
                    .similarityThreshold(0.6)
                    .build();
            List<Document> vectorDocs = vectorStore.similaritySearch(searchRequest);

            List<Document> allDocs = new ArrayList<>();
            allDocs.addAll(similarQueries);

            for (Document doc : vectorDocs) {
                boolean isDuplicate = allDocs.stream()
                        .anyMatch(existing -> existing.getText().equals(doc.getText()));
                if (!isDuplicate) {
                    allDocs.add(doc);
                }
            }

            if (allDocs.isEmpty()) {
                return "";
            }

            StringBuilder patterns = new StringBuilder();
            patterns.append("### Similar Query Cases:\n");

            for (int i = 0; i < Math.min(allDocs.size(), 8); i++) {
                Document doc = allDocs.get(i);
                patterns.append(String.format("%d. %s\n", i + 1, doc.getText()));

                if (doc.getMetadata().containsKey("queryType")) {
                    patterns.append("   - Query Type: ").append(doc.getMetadata().get("queryType")).append("\n");
                }
            }

            return patterns.toString();

        } catch (Exception e) {
            log.error("Failed to search similar query patterns: {}", e.getMessage());
            return "";
        }
    }

    private String buildAuthorizationStructure(StudioQueryContext context) {
        StringBuilder structure = new StringBuilder();

        try {
            long totalUsers = userRepository.count();
            structure.append(String.format("- Total Users: %d\n", totalUsers));

            long totalGroups = groupRepository.count();
            structure.append(String.format("- Total Groups: %d\n", totalGroups));

            long totalRoles = roleRepository.count();
            structure.append(String.format("- Total Roles: %d\n", totalRoles));

            long totalPermissions = permissionRepository.count();
            structure.append(String.format("- Total Permissions: %d\n", totalPermissions));

            List<Group> topGroups = groupRepository.findAll().stream()
                    .limit(10)
                    .toList();

            if (!topGroups.isEmpty()) {
                structure.append("### Main Groups:\n");
                topGroups.forEach(group -> {
                    structure.append(String.format("- %s (ID: %d)\n", group.getName(), group.getId()));
                });
                structure.append("\n");
            }

            List<Role> topRoles = roleRepository.findAll().stream()
                    .limit(10)
                    .toList();

            if (!topRoles.isEmpty()) {
                structure.append("### Main Roles:\n");
                topRoles.forEach(role -> {
                    structure.append(String.format("- %s (ID: %d)\n", role.getRoleName(), role.getId()));
                });
                structure.append("\n");
            }

            List<Permission> topPermissions = permissionRepository.findAll().stream()
                    .limit(15)
                    .toList();

            if (!topPermissions.isEmpty()) {
                structure.append("### Main Permissions:\n");
                topPermissions.forEach(perm -> {
                    structure.append(String.format("- %s (%s)\n",
                            perm.getFriendlyName(), perm.getManagedResource().getResourceIdentifier()));
                });
            }

        } catch (Exception e) {
            log.error("Failed to build authorization structure: {}", e.getMessage());
            structure.append("Error occurred while fetching authorization structure.\n");
        }

        return structure.toString();
    }

    private String buildUserGroupRolePermissionMapping(StudioQueryContext context) {
        StringBuilder mapping = new StringBuilder();

        try {
            List<Users> sampleUsers = userRepository.findAllWithDetails().stream()
                    .limit(5)
                    .toList();

            if (!sampleUsers.isEmpty()) {
                mapping.append("### User Permission Structure Sample:\n");

                for (Users user : sampleUsers) {
                    mapping.append(String.format("\n#### %s (ID: %d):\n", user.getName(), user.getId()));

                    Set<UserGroup> userGroups = user.getUserGroups();
                    if (userGroups != null && !userGroups.isEmpty()) {
                        mapping.append("- Groups: ");
                        String groupNames = userGroups.stream()
                                .map(ug -> ug.getGroup().getName())
                                .collect(Collectors.joining(", "));
                        mapping.append(groupNames).append("\n");
                    }

                    Set<Role> userRoles = getUserRolesFromGroups(user);
                    if (!userRoles.isEmpty()) {
                        mapping.append("- Roles: ");
                        String roleNames = userRoles.stream()
                                .map(Role::getRoleName)
                                .collect(Collectors.joining(", "));
                        mapping.append(roleNames).append("\n");
                    }

                    Set<Permission> userPermissions = getPermissionsFromRoles(userRoles);
                    if (!userPermissions.isEmpty()) {
                        mapping.append("- Permissions: ");
                        String permissionNames = userPermissions.stream()
                                .map(Permission::getFriendlyName)
                                .limit(10)
                                .collect(Collectors.joining(", "));
                        mapping.append(permissionNames);
                        if (userPermissions.size() > 10) {
                            mapping.append(String.format(" and %d more", userPermissions.size() - 10));
                        }
                        mapping.append("\n");
                    }
                }
            }

            mapping.append("\n### Group-Role Mapping:\n");
            List<Group> sampleGroups = groupRepository.findAllWithRolesAndPermissions().stream()
                    .limit(5)
                    .toList();

            for (Group group : sampleGroups) {
                mapping.append(String.format("- %s: ", group.getName()));

                Set<GroupRole> groupRoles = group.getGroupRoles();
                if (groupRoles != null && !groupRoles.isEmpty()) {
                    String roleNames = groupRoles.stream()
                            .map(gr -> gr.getRole().getRoleName())
                            .collect(Collectors.joining(", "));
                    mapping.append(roleNames);
                } else {
                    mapping.append("No roles");
                }
                mapping.append("\n");
            }

        } catch (Exception e) {
            log.error("Failed to build mapping information: {}", e.getMessage());
            mapping.append("Error occurred while fetching mapping information.\n");
        }

        return mapping.toString();
    }

    private Set<Role> getUserRolesFromGroups(Users user) {
        Set<Role> roles = new HashSet<>();
        if (user.getUserGroups() != null) {
            for (UserGroup userGroup : user.getUserGroups()) {
                Group group = userGroup.getGroup();
                if (group != null && group.getGroupRoles() != null) {
                    for (GroupRole groupRole : group.getGroupRoles()) {
                        if (groupRole.getRole() != null) {
                            roles.add(groupRole.getRole());
                        }
                    }
                }
            }
        }
        return roles;
    }

    private Set<Permission> getPermissionsFromRoles(Set<Role> roles) {
        Set<Permission> permissions = new HashSet<>();
        for (Role role : roles) {
            if (role.getRolePermissions() != null) {
                for (RolePermission rolePermission : role.getRolePermissions()) {
                    if (rolePermission.getPermission() != null) {
                        permissions.add(rolePermission.getPermission());
                    }
                }
            }
        }
        return permissions;
    }
}
