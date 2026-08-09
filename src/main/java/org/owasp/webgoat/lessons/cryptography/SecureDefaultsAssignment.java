/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cryptography;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "crypto-secure-defaults.hints.1",
  "crypto-secure-defaults.hints.2",
  "crypto-secure-defaults.hints.3"
})
public class SecureDefaultsAssignment implements AssignmentEndpoint {

  // uppercase because HashingAssignment.getHash returns uppercase hex
  private static final String EXPECTED_SECRET_SHA256 =
      "34DE66E5CAF2CB69FF2BEBDC1F3091ECF6296852446C718E38EBFA60E4AA75D2";

  @PostMapping("/crypto/secure/defaults")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String secretFileName, @RequestParam String secretText)
      throws NoSuchAlgorithmException {
    if (secretFileName != null && secretFileName.equals("default_secret")) {
      if (secretText != null
          && MessageDigest.isEqual(
              HashingAssignment.getHash(secretText, "SHA-256").getBytes(StandardCharsets.UTF_8),
              EXPECTED_SECRET_SHA256.getBytes(StandardCharsets.UTF_8))) {
        return success(this).feedback("crypto-secure-defaults.success").build();
      } else {
        return failed(this).feedback("crypto-secure-defaults.messagenotok").build();
      }
    }
    return failed(this).feedback("crypto-secure-defaults.notok").build();
  }
}
