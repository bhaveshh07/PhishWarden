package com.phishwarden.config;

import com.phishwarden.service.BlockedIpService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class IpBlockFilter extends OncePerRequestFilter {

    @Autowired
    private BlockedIpService blockedIpService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String ip = getClientIp(request);

        // Allow SOC dashboard and block-management endpoints through
        // so the admin can still unblock IPs
        String uri = request.getRequestURI();
        boolean isManagementEndpoint = uri.startsWith("/api/soc/") ||
                                       uri.startsWith("/pages/soc-dashboard");

        if (!isManagementEndpoint && blockedIpService.isBlocked(ip)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write(
                "{\"error\":\"Access denied. Your IP has been blocked by the security system.\"}"
            );
            System.out.println("[PhishWarden] Blocked request from IP: " + ip + " → " + uri);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String getClientIp(HttpServletRequest req) {
        String xfh = req.getHeader("X-Forwarded-For");
        return (xfh != null && !xfh.isBlank())
                ? xfh.split(",")[0].trim()
                : req.getRemoteAddr();
    }
}