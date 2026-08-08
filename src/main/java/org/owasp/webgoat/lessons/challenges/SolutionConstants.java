/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges;

import java.util.UUID;

public interface SolutionConstants {

  // the admin password must not be derivable from the repository
  String PASSWORD = "!!webgoat_admin_" + UUID.randomUUID() + "_1234!!";
}
