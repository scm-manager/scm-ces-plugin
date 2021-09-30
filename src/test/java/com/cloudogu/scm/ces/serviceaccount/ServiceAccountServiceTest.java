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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.security.SecuritySystem;
import sonia.scm.user.UserManager;
import sonia.scm.web.security.AdministrationContext;
import sonia.scm.web.security.PrivilegedAction;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ServiceAccountServiceTest {

  @Mock
  private UserManager userManager;
  @Mock
  private PasswordService passwordService;
  @Mock
  private AdministrationContext administrationContext;
  @Mock
  private SecuritySystem securitySystem;

  @InjectMocks
  private ServiceAccountService service;

  @Test
  void shouldCreateAccountWithPermission() {
    doAnswer(invocation -> {
      invocation.getArgument(0, PrivilegedAction.class).run();
      return null;
    }).when(administrationContext).runAsAdmin(any(PrivilegedAction.class));
    when(passwordService.encryptPassword(any()))
      .thenAnswer(invocation -> "enc-" + invocation.getArgument(0));

    service.createUser("marvin", "ouch", "repository:*");

    verify(userManager).create(argThat(
      createdUser -> {
        assertThat(createdUser.getName()).isEqualTo("marvin");
        assertThat(createdUser.getDisplayName()).isEqualTo("CES Service Account 'marvin'");
        assertThat(createdUser.getPassword()).isEqualTo("enc-ouch");
        assertThat(createdUser.isActive()).isTrue();
        return true;
      }
    ));
    verify(securitySystem).addPermission(argThat(
      permission -> {
        assertThat(permission.getName()).isEqualTo("marvin");
        assertThat(permission.getPermission().getValue()).isEqualTo("repository:*");
        assertThat(permission.isGroupPermission()).isFalse();
        return true;
      }
    ));
  }
}
