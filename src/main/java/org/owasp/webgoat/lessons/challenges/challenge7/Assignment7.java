/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.challenges.challenge7;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HexFormat;
import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.owasp.webgoat.lessons.challenges.Email;
import org.owasp.webgoat.lessons.challenges.Flags;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

/**
 * @author nbaars
 * @since 4/8/17.
 */
@RestController
@Slf4j
public class Assignment7 implements AssignmentEndpoint {

  // Generated at startup so the algorithm in the leaked git repository no longer predicts it.
  public static final String ADMIN_PASSWORD_LINK = randomLink();

  private static final String TEMPLATE =
      "Hi, you requested a password reset link, please use this <a target='_blank'"
          + " href='%s/challenge/7/reset-password/%s'>link</a> to reset your"
          + " password.\n"
          + " \n\n"
          + "If you did not request this password change you can ignore this message.\n"
          + "If you have any comments or questions, please do not hesitate to reach us at"
          + " support@webgoat-cloud.org\n\n"
          + "Kind regards, \n"
          + "Team WebGoat";

  private final Flags flags;
  private final RestTemplate restTemplate;
  private final String webWolfMailURL;
  private final String webGoatURL;

  public Assignment7(
      Flags flags,
      RestTemplate restTemplate,
      @Value("${webwolf.mail.url}") String webWolfMailURL,
      @Value("${webgoat.url}") String webGoatURL) {
    this.flags = flags;
    this.restTemplate = restTemplate;
    this.webWolfMailURL = webWolfMailURL;
    this.webGoatURL = webGoatURL;
  }

  private static String randomLink() {
    var link = new byte[16];
    new SecureRandom().nextBytes(link);
    return HexFormat.of().formatHex(link);
  }

  @GetMapping("/challenge/7/reset-password/{link}")
  public ResponseEntity<String> resetPassword(@PathVariable(value = "link") String link) {
    if (link.equals(ADMIN_PASSWORD_LINK)) {
      return ResponseEntity.accepted()
          .body(
              "<h1>Success!!</h1>"
                  + "<img src='/WebGoat/images/hi-five-cat.jpg'>"
                  + "<br/><br/>Here is your flag: "
                  + flags.getFlag(7));
    }
    return ResponseEntity.status(HttpStatus.I_AM_A_TEAPOT)
        .body("That is not the reset link for admin");
  }

  @PostMapping("/challenge/7")
  @ResponseBody
  public AttackResult sendPasswordResetLink(@RequestParam String email) {
    if (StringUtils.hasText(email)) {
      int at = email.indexOf("@");
      String username = at < 0 ? email : email.substring(0, at);
      if (StringUtils.hasText(username)) {
        String resetLink =
            "admin".equalsIgnoreCase(username)
                ? ADMIN_PASSWORD_LINK
                : new PasswordResetLink().createPasswordReset(username, "webgoat");
        Email mail =
            Email.builder()
                .title("Your password reset link for challenge 7")
                .contents(String.format(TEMPLATE, webGoatURL, resetLink))
                .sender("password-reset@webgoat-cloud.net")
                .recipient(username)
                .time(LocalDateTime.now())
                .build();
        restTemplate.postForEntity(webWolfMailURL, mail, Object.class);
      }
    }
    return success(this).feedback("email.send").feedbackArgs(email).build();
  }

  @GetMapping(value = "/challenge/7/.git", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
  @ResponseBody
  public ClassPathResource git() {
    return new ClassPathResource("lessons/challenges/challenge7/git.zip");
  }
}
