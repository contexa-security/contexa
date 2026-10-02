package io.contexa.demo.readiness.probe;

import io.contexa.demo.entry.mail.EntryMailGateway;
import io.contexa.demo.readiness.dto.ReadinessCheckResult;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Profile("portal")
public class MailReadinessCheck extends AbstractReadinessCheck {

    private final EntryMailGateway mail;

    public MailReadinessCheck(EntryMailGateway mail) {
        super("mail");
        this.mail = mail;
    }

    @Override
    protected List<ReadinessCheckResult> observe() {
        return List.of(new ReadinessCheckResult(
                "mail",
                mail.configured() ? "CONFIGURED_UNVERIFIED" : "MISSING",
                "발송 설정만 확인합니다. 실제 수신 여부는 이메일 확인 과정에서 검증합니다.",
                null));
    }
}
