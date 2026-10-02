package io.contexa.demo.entry.mail;

import io.contexa.demo.entry.configuration.EntryProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Properties;

@Component
@Profile("portal")
public class SmtpEntryMailGateway implements EntryMailGateway {

    private final EntryProperties properties;
    private final JavaMailSenderImpl sender;

    public SmtpEntryMailGateway(EntryProperties properties) {
        this.properties = properties;
        var mail = properties.mail();
        sender = new JavaMailSenderImpl();
        sender.setHost(mail.host());
        sender.setPort(mail.port());
        sender.setUsername(mail.username());
        sender.setPassword(mail.password());
        sender.setDefaultEncoding(StandardCharsets.UTF_8.name());
        Properties transport = sender.getJavaMailProperties();
        transport.setProperty("mail.smtp.auth", Boolean.toString(hasText(mail.username())));
        transport.setProperty("mail.smtp.starttls.enable", Boolean.toString(mail.starttls()));
        transport.setProperty("mail.smtp.starttls.required", Boolean.toString(mail.starttls()));
        transport.setProperty("mail.smtp.ssl.enable", Boolean.toString(mail.ssl()));
        transport.setProperty("mail.smtp.connectiontimeout", "10000");
        transport.setProperty("mail.smtp.timeout", "10000");
        transport.setProperty("mail.smtp.writetimeout", "10000");
    }

    public boolean configured() {
        return hasText(properties.mail().host()) && hasText(properties.mail().from());
    }

    public void send(String email, String code, String language) {
        if (!configured()) {
            throw new IllegalStateException("Entry mail is not configured");
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(properties.mail().from());
        message.setTo(email);
        boolean english = "en".equals(language);
        message.setSubject(english ? "Your Contexa Runtime Lab verification code" : "Contexa Runtime Lab 이메일 확인 코드");
        message.setText(english
                ? "Your verification code is " + code + ".\nIt expires in " + properties.codeLifetime().toMinutes()
                  +
                  " minutes. Enter it only in the browser where you requested it.\nIf you did not request this, ignore this email."
                : "이메일 확인 코드: " + code + "\n유효 시간은 " + properties.codeLifetime().toMinutes()
                  + "분입니다. 코드를 요청한 브라우저에서만 입력하세요.\n직접 요청하지 않았다면 이 메일을 무시하세요.");
        sender.send(message);
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
