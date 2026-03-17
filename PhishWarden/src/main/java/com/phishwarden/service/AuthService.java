package com.phishwarden.service;

import com.phishwarden.model.Honeytoken;
import com.phishwarden.model.LoginAttempt;
import com.phishwarden.model.ThreatEvent;
import com.phishwarden.model.User;
import com.phishwarden.repository.HoneytokenRepository;
import com.phishwarden.repository.LoginAttemptRepository;
import com.phishwarden.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
public class AuthService {

    @Autowired private UserRepository userRepo;
    @Autowired private HoneytokenRepository honeytokenRepo;
    @Autowired private LoginAttemptRepository loginAttemptRepo;
    @Autowired private AlertService alertService;
    @Autowired private MfaService mfaService;

    @Value("${phishwarden.jwt.secret}")
    private String jwtSecret;

    @Value("${phishwarden.jwt.expiry-ms}")
    private long jwtExpiryMs;

    private final BCryptPasswordEncoder bcrypt = new BCryptPasswordEncoder(12);

    // ─────────────────────────────────────────────────────────────
    // Main login entry point
    // ─────────────────────────────────────────────────────────────
    public LoginResult login(String email, String password, HttpServletRequest req) {
        String ip = getClientIp(req);
        String ua = req.getHeader("User-Agent");

        // 1. Progressive brute-force guard
        LockoutStatus lockout = getLockoutStatus(ip);
        if (lockout.locked) {
            logAttempt(email, ip, ua, LoginAttempt.AttemptType.BRUTE_FORCE, false);
            alertService.fireThreatEvent(
                    ThreatEvent.EventType.BRUTE_FORCE,
                    ThreatEvent.Severity.HIGH, ip,
                    "Brute force from " + ip);
            sleepMs(2000);
            return LoginResult.blocked(
                "Too many failed attempts. Try again in " +
                formatSeconds(lockout.secondsRemaining) + ".",
                lockout.secondsRemaining
            );
        }

        // 2. Check honeytokens FIRST
        Optional<Honeytoken> honeyOpt = honeytokenRepo.findByFakeEmail(email.toLowerCase());
        if (honeyOpt.isPresent() && honeyOpt.get().getFakePassword().equals(password)) {
            return handleHoneytokenHit(honeyOpt.get(), ip, ua);
        }

        // 3. Real user lookup
        Optional<User> userOpt = userRepo.findByEmail(email.toLowerCase());
        if (userOpt.isEmpty()) {
            logAttempt(email, ip, ua, LoginAttempt.AttemptType.UNKNOWN, false);
            sleepMs(400);
            return LoginResult.failure("Invalid credentials.");
        }

        User user = userOpt.get();
        if (!bcrypt.matches(password, user.getPasswordHash())) {
            logAttempt(email, ip, ua, LoginAttempt.AttemptType.UNKNOWN, false);
            sleepMs(400);
            return LoginResult.failure("Invalid credentials.");
        }

        // 4. Credentials valid — check if this IP is known for this user
        List<String> knownIps = loginAttemptRepo.findKnownIpsForEmail(user.getEmail());
        boolean isNewDevice = knownIps.isEmpty() || !knownIps.contains(ip);

        if (isNewDevice) {
            // New device/IP → trigger MFA
            logAttempt(email, ip, ua, LoginAttempt.AttemptType.REAL_USER, false);

            String sessionToken = mfaService.sendOtp(email, user.getEmail());

            // LOW severity — this is informational, not an attack
            alertService.fireThreatEvent(
                    ThreatEvent.EventType.PHISHING_CRED_HARVEST,
                    ThreatEvent.Severity.LOW, ip,
                    "MFA triggered for " + email + " from new IP: " + ip +
                    " | Known IPs: " + knownIps);

            return LoginResult.mfaRequired(sessionToken,
                    "A verification code has been sent to your email.");
        }

        // 5. Known device — log as success and issue JWT directly
        logAttempt(email, ip, ua, LoginAttempt.AttemptType.REAL_USER, true);
        checkSuspiciousLogin(user, ip, ua);
        String jwt = generateJwt(user.getId(), user.getEmail(), false);
        return LoginResult.success(jwt, user.getName(), user.getRole().name(), false);
    }

    // ─────────────────────────────────────────────────────────────
    // Called by MfaController after OTP is verified.
    // ─────────────────────────────────────────────────────────────
    public LoginResult issueJwtForVerifiedUser(User user, String ip, String ua) {
        logAttempt(user.getEmail(), ip, ua, LoginAttempt.AttemptType.REAL_USER, true);
        String jwt = generateJwt(user.getId(), user.getEmail(), false);
        return LoginResult.success(jwt, user.getName(), user.getRole().name(), false);
    }

    // ─────────────────────────────────────────────────────────────
    // Honeytoken hit
    // ─────────────────────────────────────────────────────────────
    private LoginResult handleHoneytokenHit(Honeytoken token, String ip, String ua) {
        token.setTriggered(true);
        honeytokenRepo.save(token);
        logAttempt(token.getFakeEmail(), ip, ua, LoginAttempt.AttemptType.HONEYTOKEN_HIT, true);
        alertService.fireThreatEvent(
                ThreatEvent.EventType.HONEYTOKEN_LOGIN,
                ThreatEvent.Severity.CRITICAL, ip,
                "Honeytoken triggered! Email: " + token.getFakeEmail()
                + " | UID: " + token.getTokenUid()
                + " | IP: " + ip + " | UA: " + ua);
        String honeyJwt = generateJwt(-1L, token.getFakeEmail(), true);
        return LoginResult.success(honeyJwt, "Employee", "EMPLOYEE", true);
    }

    // ─────────────────────────────────────────────────────────────
    // Progressive lockout
    // ─────────────────────────────────────────────────────────────
    private LockoutStatus getLockoutStatus(String ip) {
        LocalDateTime now = LocalDateTime.now();

        LocalDateTime lastSuccess = loginAttemptRepo
                .findLastSuccessTimeForIp(ip)
                .orElse(now.minusHours(24));

        long failsSinceSuccess = loginAttemptRepo.countFailedSinceTime(ip, lastSuccess);

        if (failsSinceSuccess < 5) {
            return new LockoutStatus(false, 0);
        }

        int tier       = (int) Math.min(failsSinceSuccess / 5, 4);
        int windowMins = (int) (5 * Math.pow(2, tier - 1));

        LocalDateTime lockoutStart = now.minusMinutes(windowMins);
        LocalDateTime countFrom    = lockoutStart.isAfter(lastSuccess) ? lockoutStart : lastSuccess;
        long failsInWindow         = loginAttemptRepo.countFailedSinceTime(ip, countFrom);

        if (failsInWindow >= 5) {
            LocalDateTime lastFail = loginAttemptRepo
                    .findLastFailTimeForIp(ip)
                    .orElse(now.minusMinutes(windowMins));
            long elapsedSeconds   = java.time.Duration.between(lastFail, now).getSeconds();
            long remainingSeconds = Math.max(0, (windowMins * 60L) - elapsedSeconds);
            return new LockoutStatus(true, remainingSeconds);
        }

        return new LockoutStatus(false, 0);
    }

    private static class LockoutStatus {
        final boolean locked;
        final long secondsRemaining;
        LockoutStatus(boolean locked, long secondsRemaining) {
            this.locked           = locked;
            this.secondsRemaining = secondsRemaining;
        }
    }

    // ─────────────────────────────────────────────────────────────
    // Suspicious login detection
    // ─────────────────────────────────────────────────────────────
    private void checkSuspiciousLogin(User user, String ip, String ua) {
        String email          = user.getEmail();
        int hour              = LocalDateTime.now().getHour();
        boolean unusualHour   = hour >= 23 || hour <= 5;
        long recentLogins     = loginAttemptRepo
                .countRecentLoginsForEmail(email, LocalDateTime.now().minusMinutes(10));
        boolean tooManyRecent = recentLogins > 3;

        if (unusualHour) {
            alertService.fireThreatEvent(
                ThreatEvent.EventType.PHISHING_CRED_HARVEST,
                ThreatEvent.Severity.MEDIUM, ip,
                "UNUSUAL HOUR: " + email + " logged in at " + hour + ":xx from " + ip);
        }
        if (tooManyRecent) {
            alertService.fireThreatEvent(
                ThreatEvent.EventType.PHISHING_CRED_HARVEST,
                ThreatEvent.Severity.HIGH, ip,
                "CRED STUFFING: " + email + " — " + recentLogins + " attempts in 10 mins");
        }
    }

    // ─────────────────────────────────────────────────────────────
    // JWT
    // ─────────────────────────────────────────────────────────────
    public String generateJwt(Long userId, String email, boolean isHoney) {
        Key key = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        return Jwts.builder()
                .setSubject(email)
                .claim("userId", userId)
                .claim("isHoney", isHoney)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiryMs))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // ─────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────
    private String formatSeconds(long secs) {
        if (secs >= 60) return (secs / 60) + " minutes";
        return secs + " seconds";
    }

    private void logAttempt(String email, String ip, String ua,
                             LoginAttempt.AttemptType type, boolean success) {
        LoginAttempt attempt = new LoginAttempt();
        attempt.setEmailUsed(email);
        attempt.setIpAddress(ip);
        attempt.setUserAgent(ua);
        attempt.setAttemptType(type);
        attempt.setWasSuccessful(success);
        loginAttemptRepo.save(attempt);
    }

    private String getClientIp(HttpServletRequest req) {
        String xfh = req.getHeader("X-Forwarded-For");
        return (xfh != null && !xfh.isBlank())
                ? xfh.split(",")[0].trim()
                : req.getRemoteAddr();
    }

    private void sleepMs(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) {}
    }

    // ─────────────────────────────────────────────────────────────
    // LoginResult DTO
    // ─────────────────────────────────────────────────────────────
    public static class LoginResult {
        private final boolean blocked;
        private final boolean success;
        private final boolean mfaRequired;
        private final boolean isHoneySession;
        private final String token;
        private final String name;
        private final String role;
        private final String message;
        private final long lockoutSeconds;
        private final String sessionToken;

        private LoginResult(boolean blocked, boolean success, boolean mfaRequired,
                            boolean isHoneySession, String token, String name,
                            String role, String message, long lockoutSeconds,
                            String sessionToken) {
            this.blocked        = blocked;
            this.success        = success;
            this.mfaRequired    = mfaRequired;
            this.isHoneySession = isHoneySession;
            this.token          = token;
            this.name           = name;
            this.role           = role;
            this.message        = message;
            this.lockoutSeconds = lockoutSeconds;
            this.sessionToken   = sessionToken;
        }

        public static LoginResult success(String token, String name, String role, boolean honey) {
            return new LoginResult(false, true, false, honey,
                    token, name, role, "Login successful", 0, null);
        }
        public static LoginResult failure(String msg) {
            return new LoginResult(false, false, false, false,
                    null, null, null, msg, 0, null);
        }
        public static LoginResult blocked(String msg, long seconds) {
            return new LoginResult(true, false, false, false,
                    null, null, null, msg, seconds, null);
        }
        public static LoginResult mfaRequired(String sessionToken, String msg) {
            return new LoginResult(false, false, true, false,
                    null, null, null, msg, 0, sessionToken);
        }

        public boolean isBlocked()         { return blocked; }
        public boolean isSuccess()         { return success; }
        public boolean isMfaRequired()     { return mfaRequired; }
        public boolean isHoneySession()    { return isHoneySession; }
        public String  getToken()          { return token; }
        public String  getName()           { return name; }
        public String  getRole()           { return role; }
        public String  getMessage()        { return message; }
        public long    getLockoutSeconds() { return lockoutSeconds; }
        public String  getSessionToken()   { return sessionToken; }
    }
}