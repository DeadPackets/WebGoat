/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.csrf;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.owasp.webgoat.container.i18n.PluginMessages;
import org.owasp.webgoat.container.session.LessonSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

/** Created by jason on 9/30/17. */
@RestController
public class CSRFGetFlag {

  @Autowired LessonSession userSessionData;
  @Autowired private PluginMessages pluginMessages;

  @PostMapping(
      path = "/csrf/basic-get-flag",
      produces = {"application/json"})
  @ResponseBody
  public Map<String, Object> invoke(HttpServletRequest req) {

    Map<String, Object> response = new HashMap<>();

    String host = (req.getHeader("host") == null) ? "NULL" : req.getHeader("host");
    String referer = (req.getHeader("referer") == null) ? "NULL" : req.getHeader("referer");
    String[] refererArr = referer.split("/");

    // only a request this application's own pages made may act on the session; missing origin
    // information fails closed
    boolean sameOrigin =
        !referer.equals("NULL") && refererArr.length > 2 && refererArr[2].equals(host);
    if (sameOrigin) {
      response.put("success", false);
      response.put("message", "Appears the request came from the original host");
    } else {
      response.put("success", false);
      response.put("message", pluginMessages.getMessage("csrf-get-null-referer.success"));
    }
    response.put("flag", null);

    return response;
  }
}
