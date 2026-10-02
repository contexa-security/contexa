package io.contexa.demo.work.project.repository;

import io.contexa.demo.work.project.dto.ProjectView;

import java.util.List;

public interface ProjectRepository {

    List<ProjectView> list(String username);

    List<String> assignedProjects(String username);
}
