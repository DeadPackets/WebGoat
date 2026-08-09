/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import org.springframework.http.HttpHeaders;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Matches an authentication post that carries neither Origin nor Referer, so a client which has no
 * session yet can still obtain one. A browser always states where a cross site form post came from,
 * which keeps a forged login covered by the token check; a client that sends neither header cannot
 * be made to attach someone else's cookies in the first place.
 */
public class TokenlessAuthenticationMatcher implements RequestMatcher {

  private final Set<String> paths;

  public TokenlessAuthenticationMatcher(String... paths) {
    this.paths = Set.of(paths);
  }

  @Override
  public boolean matches(HttpServletRequest request) {
    return "POST".equalsIgnoreCase(request.getMethod())
        && paths.contains(pathWithinApplication(request))
        && request.getHeader(HttpHeaders.ORIGIN) == null
        && request.getHeader(HttpHeaders.REFERER) == null;
  }

  private String pathWithinApplication(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String contextPath = request.getContextPath();
    return contextPath.isEmpty() ? uri : uri.substring(contextPath.length());
  }
}
