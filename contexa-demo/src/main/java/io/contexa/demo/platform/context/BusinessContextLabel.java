package io.contexa.demo.platform.context;

import io.contexa.demo.work.request.dto.WorkRequestSnapshot;

public interface BusinessContextLabel {

    String describe(WorkRequestSnapshot snapshot);
}
