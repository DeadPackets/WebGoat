/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.idor;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints({
  "idor.hints.ownProfileAltUrl1",
  "idor.hints.ownProfileAltUrl2",
  "idor.hints.ownProfileAltUrl3"
})
public class IDORViewOwnProfileAltUrl implements AssignmentEndpoint {
  private final LessonSession userSessionData;

  public IDORViewOwnProfileAltUrl(LessonSession userSessionData) {
    this.userSessionData = userSessionData;
  }

  @PostMapping("/IDOR/profile/alt-path")
  @ResponseBody
  public AttackResult completed(@RequestParam String url) {
    String authUserId = (String) userSessionData.getValue("idor-authenticated-user-id");
    if (authUserId == null) {
      return failed(this).feedback("idor.view.own.profile.failure2").build();
    }

    // only the caller's own profile is ever resolved here, so the submitted path can confirm the
    // route but can never reference another user's object
    String[] urlParts = url.split("/");
    if (urlParts.length == 4
        && urlParts[0].equals("WebGoat")
        && urlParts[1].equals("IDOR")
        && urlParts[2].equals("profile")
        && urlParts[3].equals(authUserId)) {
      UserProfile userProfile = new UserProfile(authUserId);
      return success(this)
          .feedback("idor.view.own.profile.success")
          .output(userProfile.profileToMap().toString())
          .build();
    }
    return failed(this).feedback("idor.view.own.profile.failure1").build();
  }
}
