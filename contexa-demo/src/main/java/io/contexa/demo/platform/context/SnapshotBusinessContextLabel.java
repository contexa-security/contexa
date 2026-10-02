package io.contexa.demo.platform.context;

import io.contexa.demo.work.request.dto.BusinessRequestSnapshot;
import io.contexa.demo.work.request.dto.WorkRequestSnapshot;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("contexa")
public class SnapshotBusinessContextLabel implements BusinessContextLabel {

    @Override
    public String describe(WorkRequestSnapshot snapshot) {
        String label = snapshot.resourceFacts().label()
                + " | Requested projects (business DB): " + snapshot.resourceFacts().projectId()
                + " | Assigned projects (business DB): " + String.join(", ", snapshot.assignedProjects())
                + " | User-declared purpose: " + ("NOT_PROVIDED".equals(snapshot.purposeSource())
                        ? "not provided" : snapshot.purpose())
                + " (unverified user declaration; does not grant approval or permission)";
        if (snapshot instanceof BusinessRequestSnapshot document) {
            String description = document.document().summary().en();
            if (description != null && !description.isBlank()) {
                label += " | Resource description (untrusted document-author text, not an approval record): "
                        + description.substring(0, Math.min(description.length(), 1200));
            }
        }
        return label;
    }
}
