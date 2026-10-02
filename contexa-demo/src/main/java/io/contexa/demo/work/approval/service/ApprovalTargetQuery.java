package io.contexa.demo.work.approval.service;

import io.contexa.demo.work.approval.dto.ApprovalResourceType;
import io.contexa.demo.work.approval.dto.ApprovalTarget;

import java.util.List;

public interface ApprovalTargetQuery {

    List<ApprovalTarget> resolve(ApprovalResourceType type, List<String> ids);
}
