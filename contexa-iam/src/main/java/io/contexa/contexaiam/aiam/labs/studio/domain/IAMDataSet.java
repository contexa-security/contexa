package io.contexa.contexaiam.aiam.labs.studio.domain;

import io.contexa.contexacommon.entity.Group;
import io.contexa.contexacommon.entity.Permission;
import io.contexa.contexacommon.entity.Role;
import io.contexa.contexacommon.entity.Users;
import lombok.Data;

import java.util.List;

@Data
public class IAMDataSet {
    
    private List<Users> users;
    private List<Group> groups;
    private List<Role> roles;
    private List<Permission> permissions;
    
    private String error;
    private boolean success = true;

    public void setError(String error) {
        this.error = error;
        this.success = false;
    }

    public boolean isSuccess() {
        return success && error == null;
    }

    public boolean hasData() {
        return (users != null && !users.isEmpty()) ||
               (groups != null && !groups.isEmpty()) ||
               (roles != null && !roles.isEmpty()) ||
               (permissions != null && !permissions.isEmpty());
    }

    public String getSummary() {
        if (!isSuccess()) {
            return "Data collection failed: " + error;
        }

        StringBuilder summary = new StringBuilder();
        summary.append("Collected data: ");

        if (users != null) summary.append("Users: ").append(users.size()).append(", ");
        if (groups != null) summary.append("Groups: ").append(groups.size()).append(", ");
        if (roles != null) summary.append("Roles: ").append(roles.size()).append(", ");
        if (permissions != null) summary.append("Permissions: ").append(permissions.size()).append(", ");
        
        return summary.toString().replaceAll(", $", "");
    }
} 