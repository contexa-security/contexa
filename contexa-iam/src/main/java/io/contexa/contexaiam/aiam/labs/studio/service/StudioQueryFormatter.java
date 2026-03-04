package io.contexa.contexaiam.aiam.labs.studio.service;

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexaiam.aiam.labs.studio.domain.IAMDataSet;
import io.contexa.contexaiam.aiam.protocol.request.StudioQueryRequest;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.Hibernate;
import org.hibernate.LazyInitializationException;

import java.util.Date;

@Slf4j
public class StudioQueryFormatter {

    public String formatForAIMData(IAMDataSet dataSet) {

        if (dataSet == null) {
            return "No IAM data available.";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("=== Current System Permission Status ===\n\n");

        if (dataSet.getUsers() != null && !dataSet.getUsers().isEmpty()) {
            sb.append("Permission information by user:\n");

            dataSet.getUsers().forEach(user -> {
                sb.append("- ").append(user.getName()).append(" ");

                try {

                    if (user.getUserGroups() != null && Hibernate.isInitialized(user.getUserGroups()) && !user.getUserGroups().isEmpty()) {
                        user.getUserGroups().forEach(userGroup -> {
                            Group group = userGroup.getGroup();
                            if (group != null) {
                                sb.append("belongs to group ").append(group.getName()).append(", ");

                                try {
                                    if (group.getGroupRoles() != null &&
                                            Hibernate.isInitialized(group.getGroupRoles()) &&
                                            !group.getGroupRoles().isEmpty()) {

                                        group.getGroupRoles().forEach(groupRole -> {
                                            Role role = groupRole.getRole();
                                            if (role != null) {
                                                String roleDesc = role.getRoleDesc();
                                                                                                sb.append("with role ").append(roleDesc).append(" ");

                                                try {
                                                    if (role.getRolePermissions() != null &&
                                                            Hibernate.isInitialized(role.getRolePermissions()) &&
                                                            !role.getRolePermissions().isEmpty()) {

                                                        role.getRolePermissions().forEach(rolePermission -> {
                                                            Permission permission = rolePermission.getPermission();
                                                            if (permission != null) {
                                                                String friendlyName = permission.getFriendlyName();

                                                                if (friendlyName == null || friendlyName.trim().isEmpty()) {
                                                                    friendlyName = permission.getName();
                                                                }
                                                                                                                                sb.append("having permission ").append(friendlyName).append(" ");
                                                            }
                                                        });
                                                        sb.append("granted.\n");
                                                    } else {
                                                        sb.append("no special permissions assigned.\n");
                                                    }
                                                } catch (LazyInitializationException e) {
                                                                                                        sb.append("unable to load permission information.\n");
                                                }
                                            }
                                        });
                                    } else {
                                        sb.append("no special roles assigned.\n");
                                    }
                                } catch (LazyInitializationException e) {
                                                                        sb.append("unable to load role information.\n");
                                }
                            }
                        });
                    } else {
                        sb.append("does not belong to any group.\n");
                    }
                } catch (LazyInitializationException e) {
                                        sb.append("unable to load group information.\n");
                }
            });
        }

        if (dataSet.getGroups() != null && !dataSet.getGroups().isEmpty()) {
            sb.append("\nGroup details:\n");
            dataSet.getGroups().forEach(group -> {
                sb.append("- ").append(group.getName()).append(" (").append(group.getDescription()).append(")\n");

                try {
                    if (group.getUserGroups() != null && Hibernate.isInitialized(group.getUserGroups())) {
                        sb.append("  Members: ").append(group.getUserGroups().size()).append("\n");
                    }
                } catch (LazyInitializationException e) {
                                    }

                try {
                    if (group.getGroupRoles() != null &&
                            Hibernate.isInitialized(group.getGroupRoles()) &&
                            !group.getGroupRoles().isEmpty()) {
                        sb.append("  Roles: ");
                        group.getGroupRoles().forEach(groupRole -> {
                            sb.append(groupRole.getRole().getRoleDesc()).append(" ");
                        });
                        sb.append("\n");
                    }
                } catch (LazyInitializationException e) {
                                    }
            });
        }

        if (dataSet.getRoles() != null && !dataSet.getRoles().isEmpty()) {
            sb.append("\nRole details:\n");
            dataSet.getRoles().forEach(role -> {
                sb.append("- ").append(role.getRoleDesc()).append(" (").append(role.getRoleName()).append(")\n");

                try {
                    if (role.getRolePermissions() != null &&
                            Hibernate.isInitialized(role.getRolePermissions()) &&
                            !role.getRolePermissions().isEmpty()) {
                        sb.append("  Permissions: ");
                        role.getRolePermissions().forEach(rolePermission -> {
                            String friendlyName = rolePermission.getPermission().getFriendlyName();

                            if (friendlyName == null || friendlyName.trim().isEmpty()) {
                                friendlyName = rolePermission.getPermission().getName();
                            }
                            sb.append(friendlyName).append(" ");
                        });
                        sb.append("\n");
                    }
                } catch (LazyInitializationException e) {
                                    }
            });
        }

        if (dataSet.getPermissions() != null && !dataSet.getPermissions().isEmpty()) {
            sb.append("\nPermission details:\n");
            dataSet.getPermissions().forEach(permission -> {
                String friendlyName = permission.getFriendlyName();

                if (friendlyName == null || friendlyName.trim().isEmpty()) {
                    friendlyName = permission.getName();
                }
                sb.append("- ").append(friendlyName).append(" (").append(permission.getName()).append(")\n");
                sb.append("  Target type: ").append(permission.getTargetType()).append("\n");
                sb.append("  Action type: ").append(permission.getActionType()).append("\n");
            });
        }

        sb.append("\n=== Data collection complete ===\n");
        sb.append("Please perform an accurate analysis based on the actual data above.\n");

        return sb.toString();
    }

    public String formatSystemMetadata(StudioQueryRequest request) {

        StringBuilder sb = new StringBuilder();
        sb.append("AI-Native Authorization Studio\n");
        sb.append("Query: ").append(request.getNaturalLanguageQuery()).append("\n");
        sb.append("Analysis time: ").append(new Date()).append("\n");
        sb.append("Analysis mode: AI-Native (hardcoding removed)\n");

        return sb.toString();
    }
}
