/*
 * MIT License
 *
 * Copyright (c) 2020-present Cloudogu GmbH and Contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.cloudogu.scm.ces.serviceaccount;

import org.apache.shiro.authc.credential.PasswordService;
import sonia.scm.security.AssignedPermission;
import sonia.scm.security.SecuritySystem;
import sonia.scm.user.User;
import sonia.scm.user.UserManager;
import sonia.scm.web.security.AdministrationContext;

import javax.inject.Inject;

import static java.lang.String.format;

class ServiceAccountService {

  private final UserManager userManager;
  private final PasswordService passwordService;
  private final AdministrationContext administrationContext;
  private final SecuritySystem securitySystem;

  @Inject
  public ServiceAccountService(UserManager userManager, PasswordService passwordService, AdministrationContext administrationContext, SecuritySystem securitySystem) {
    this.userManager = userManager;
    this.passwordService = passwordService;
    this.administrationContext = administrationContext;
    this.securitySystem = securitySystem;
  }

  void createUser(String username, String password, String permission) {
    String displayName = format("CES Service Account '%s'", username);
    String encryptedPassword = passwordService.encryptPassword(password);
    User serviceAccount = new User(username, displayName, null, encryptedPassword, "CES", true);
    administrationContext.runAsAdmin(() -> {
      userManager.create(serviceAccount);
      securitySystem.addPermission(new AssignedPermission(username, false, permission));
    });
  }
}
