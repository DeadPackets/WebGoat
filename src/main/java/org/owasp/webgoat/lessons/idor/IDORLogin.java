/*
 * SPDX-FileCopyrightText: Copyright © 2014 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({"idor.hints.idor_login"})
public class IDORLogin implements AssignmentEndpoint {

  private final LessonSession lessonSession;

  private final Map<String, Map<String, String>> idorUserInfo = new HashMap<>();

  public IDORLogin(LessonSession lessonSession) {
    this.lessonSession = lessonSession;
  }

  public void initIDORInfo() {

    idorUserInfo.put("tom", new HashMap<String, String>());
    // the lesson publishes this credential (IDOR_login.adoc): the step is a legitimate login into
    // the simulated account, the authorization abuse comes later
    idorUserInfo.get("tom").put("password", "cat");
    idorUserInfo.get("tom").put("id", "2342384");
    idorUserInfo.get("tom").put("color", "yellow");
    idorUserInfo.get("tom").put("size", "small");

    idorUserInfo.put("bill", new HashMap<String, String>());
    idorUserInfo.get("bill").put("id", "2342388");
    idorUserInfo.get("bill").put("color", "brown");
    idorUserInfo.get("bill").put("size", "large");
  }

  @PostMapping("/IDOR/login")
  @ResponseBody
  public AttackResult completed(@RequestParam String username, @RequestParam String password) {
    initIDORInfo();

    if ("tom".equals(username) && idorUserInfo.get("tom").get("password").equals(password)) {
      lessonSession.setValue("idor-authenticated-as", username);
      lessonSession.setValue("idor-authenticated-user-id", idorUserInfo.get(username).get("id"));
      return success(this).feedback("idor.login.success").feedbackArgs(username).build();
    }
    // the same answer for an unknown account and for a wrong password
    return failed(this).feedback("idor.login.failure").build();
  }
}
