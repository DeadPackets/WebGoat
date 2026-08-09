/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Hands the CSRF token to clients that cannot read the cookie themselves. */
@RestController
public class CsrfTokenController {

  @GetMapping("/csrf/token")
  public Token token(CsrfToken csrfToken) {
    return new Token(
        csrfToken.getHeaderName(), csrfToken.getParameterName(), csrfToken.getToken());
  }

  record Token(String headerName, String parameterName, String token) {}
}
