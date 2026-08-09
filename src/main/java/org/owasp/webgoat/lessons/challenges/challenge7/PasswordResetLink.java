/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Random;

/**
 * @author nbaars
 * @since 8/17/17.
 */
public class PasswordResetLink {

  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /**
   * The link is drawn from a cryptographically secure generator. Deriving it from the user name, or
   * from a seed an attacker can reconstruct, let anyone build the link for an account they do not
   * own and take it over.
   */
  public String createPasswordReset(String username, String key) {
    byte[] link = new byte[16];
    SECURE_RANDOM.nextBytes(link);
    return HexFormat.of().formatHex(link);
  }

  public static String scramble(Random random, String inputString) {
    char[] a = inputString.toCharArray();
    for (int i = 0; i < a.length; i++) {
      int j = random.nextInt(a.length);
      char temp = a[i];
      a[i] = a[j];
      a[j] = temp;
    }
    return new String(a);
  }

  public static void main(String[] args) {
    if (args == null || args.length != 2) {
      System.out.println("Need a username and key");
      System.exit(1);
    }
    String username = args[0];
    String key = args[1];
    System.out.println("Generation password reset link for " + username);
    System.out.println(
        "Created password reset link: "
            + new PasswordResetLink().createPasswordReset(username, key));
  }
}
