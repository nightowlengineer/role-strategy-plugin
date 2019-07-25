package org.jenkinsci.plugins.rolestrategy.util;

import hudson.model.User;
import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContext;
import org.acegisecurity.context.SecurityContextHolder;

public class TemporaryUserSession implements AutoCloseable {
    private Authentication originalUser;
    private final SecurityContext seccon = SecurityContextHolder.getContext();

    public TemporaryUserSession(final String user)
    {
        SecurityContext seccon = SecurityContextHolder.getContext();
        originalUser = seccon.getAuthentication();
        seccon.setAuthentication(User.get(user).impersonate());
    }

    public void close() {
        seccon.setAuthentication(originalUser);
    }
}
