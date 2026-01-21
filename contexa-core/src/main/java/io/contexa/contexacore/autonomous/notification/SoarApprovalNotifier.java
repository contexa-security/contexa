package io.contexa.contexacore.autonomous.notification;

public interface SoarApprovalNotifier {

    void receiveApprovalNotification(String message);

    void sendApprovalReminder(String approvalId);
}
