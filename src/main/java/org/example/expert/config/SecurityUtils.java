package org.example.expert.config;

import org.example.expert.domain.common.dto.AuthUser;
import org.example.expert.domain.user.enums.UserRole;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

public class SecurityUtils {

    public static AuthUser getAuthUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        String userId = authentication.getName();
        String email = (String) authentication.getCredentials();
        UserRole role = UserRole.valueOf(authentication.getAuthorities().iterator().next().getAuthority().substring(5));
        return new AuthUser(Long.parseLong(userId), email, "", role);
    }
}
