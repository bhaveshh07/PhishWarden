package com.phishwarden.service;

import com.phishwarden.model.ThreatEvent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class MfaService {

    @Autowired private JavaMailSender mailSender;
    @Autowired private BlockedIpService blockedIpService;
    @Autowired private AlertService alertService;

    private final Map<String, OtpEntry>     pendingVerifications = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> failedAttempts      = new ConcurrentHashMap<>();

    private static final int MAX_OTP_ATTEMPTS = 3;
    private final SecureRandom random = new SecureRandom();

    public String sendOtp(String email, String userEmail) {
        String otp          = String.format("%06d", random.nextInt(1_000_000));
        String sessionToken = Long.toHexString(random.nextLong()) +
                              Long.toHexString(random.nextLong());

        pendingVerifications.put(sessionToken,
                new OtpEntry(otp, userEmail, LocalDateTime.now().plusMinutes(10)));
        failedAttempts.put(sessionToken, new AtomicInteger(0));

        System.out.println("[PhishWarden MFA] OTP for " + userEmail + " -> " + otp);
        sendOtpEmail(userEmail, otp);
        return sessionToken;
    }

    // Returns: email string if valid, null if wrong, "BLOCKED" if IP now blocked
    public String verifyOtp(String sessionToken, String inputOtp, String ip) {
        OtpEntry entry = pendingVerifications.get(sessionToken);

        if (entry == null) return null;

        if (LocalDateTime.now().isAfter(entry.expiresAt)) {
            pendingVerifications.remove(sessionToken);
            failedAttempts.remove(sessionToken);
            return null;
        }

        if (!entry.otp.equals(inputOtp.trim())) {
            AtomicInteger attempts = failedAttempts.get(sessionToken);
            int count = attempts != null ? attempts.incrementAndGet() : 1;

            System.out.println("[PhishWarden MFA] Wrong OTP from IP: " + ip +
                               " (attempt " + count + "/" + MAX_OTP_ATTEMPTS + ")");

            if (count >= MAX_OTP_ATTEMPTS) {
                blockedIpService.blockIp(ip);
                pendingVerifications.remove(sessionToken);
                failedAttempts.remove(sessionToken);

                alertService.fireThreatEvent(
                        ThreatEvent.EventType.BRUTE_FORCE,
                        ThreatEvent.Severity.CRITICAL, ip,
                        "OTP BRUTE FORCE: IP " + ip + " blocked after " +
                        MAX_OTP_ATTEMPTS + " wrong OTP attempts for " + entry.email);

                return "BLOCKED";
            }
            return null;
        }

        pendingVerifications.remove(sessionToken);
        failedAttempts.remove(sessionToken);
        return entry.email;
    }

    private void sendOtpEmail(String toEmail, String otp) {
        try {
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setTo(toEmail);
            msg.setSubject("PhishWarden - Your login verification code");
            msg.setText("Hello,\n\nYour verification code is:\n\n    " + otp +
                        "\n\nExpires in 10 minutes.\n\n- PhishWarden Security");
            mailSender.send(msg);
        } catch (Exception e) {
            System.err.println("[PhishWarden MFA] Email send failed: " + e.getMessage());
        }
    }

    private static class OtpEntry {
        final String otp;
        final String email;
        final LocalDateTime expiresAt;
        OtpEntry(String otp, String email, LocalDateTime expiresAt) {
            this.otp = otp; this.email = email; this.expiresAt = expiresAt;
        }
    }
}