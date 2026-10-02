package io.contexa.demo.entry.mail;

public interface EntryMailGateway {

    boolean configured();

    void send(String email, String code, String language);
}
