/*
 * SPDX-FileCopyrightText: Copyright © 2018 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.cia;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CIAQuiz implements AssignmentEndpoint {

  private final String[] solutions = {"Solution 3", "Solution 1", "Solution 4", "Solution 2"};
  boolean[] guesses = new boolean[solutions.length];

  @PostMapping("/cia/quiz")
  @ResponseBody
  public AttackResult completed(
      @RequestParam String[] question_0_solution,
      @RequestParam String[] question_1_solution,
      @RequestParam String[] question_2_solution,
      @RequestParam String[] question_3_solution) {
    int correctAnswers = 0;

    String[] givenAnswers = {
      chosen(question_0_solution),
      chosen(question_1_solution),
      chosen(question_2_solution),
      chosen(question_3_solution)
    };

    for (int i = 0; i < solutions.length; i++) {
      if (givenAnswers[i].startsWith(solutions[i] + ":")) {
        // answer correct
        correctAnswers++;
        guesses[i] = true;
      } else {
        // answer incorrect
        guesses[i] = false;
      }
    }

    if (correctAnswers == solutions.length) {
      return success(this).build();
    } else {
      return failed(this).build();
    }
  }

  // The radio value is "Solution <n>: <text>", so an answer only counts for the question it was
  // picked for. A substring test let one string listing every solution pass every question.
  private static String chosen(String[] submitted) {
    return submitted == null || submitted.length == 0 ? "" : submitted[0];
  }

  @GetMapping("/cia/quiz")
  @ResponseBody
  public boolean[] getResults() {
    return this.guesses;
  }
}
