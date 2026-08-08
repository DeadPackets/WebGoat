/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Refuses a login another site submitted, so a page under attacker control cannot silently swap the
 * browser's WebGoat session for one the attacker owns. A request that carries neither Origin nor
 * Referer passes: the headers are not sent by every client and their absence proves nothing.
 */
class CrossOriginLoginFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    if (isCrossOriginLogin(request)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN, "Cross-origin login is not allowed");
      return;
    }
    filterChain.doFilter(request, response);
  }

  private boolean isCrossOriginLogin(HttpServletRequest request) {
    if (!"POST".equalsIgnoreCase(request.getMethod()) || !isLoginPath(request)) {
      return false;
    }
    String host = request.getHeader(HttpHeaders.HOST);
    String origin = request.getHeader(HttpHeaders.ORIGIN);
    if (origin == null) {
      origin = request.getHeader(HttpHeaders.REFERER);
    }
    if (host == null || origin == null) {
      return false;
    }
    String[] originParts = origin.split("/");
    return originParts.length < 3 || !originParts[2].equals(host);
  }

  private boolean isLoginPath(HttpServletRequest request) {
    String uri = request.getRequestURI();
    String contextPath = request.getContextPath();
    return "/login".equals(uri.substring(contextPath.length()));
  }
}
