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

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import sonia.scm.user.User;

import static com.cloudogu.scm.ces.serviceaccount.CesTokenRealm.MARKER;
import static com.cloudogu.scm.ces.serviceaccount.CesTokenRealm.REALM;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doThrow;

@ExtendWith(MockitoExtension.class)
class CesTokenRealmTest {

  @Mock
  private CesAccessValidator validator;
  @InjectMocks
  private CesTokenRealm realm;

  @Test
  void shouldCreateAuthenticationInfo() {
    AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(new CesToken("secret", "127.0.0.1"));

    PrincipalCollection principals = authenticationInfo.getPrincipals();

    assertThat(principals.oneByType(User.class)).isNotNull();
    assertThat(principals.oneByType(CesTokenRealm.CesTokenRealmMarker.class)).isSameAs(MARKER);
  }

  @Test
  void shouldFailForAuthenticationInfoIfValidatorRejectsToken() {
    doThrow(AuthenticationException.class).when(validator).checkToken("wrong");

    CesToken token = new CesToken("wrong", "127.0.0.1");
    assertThrows(AuthenticationException.class, () -> realm.doGetAuthenticationInfo(token));
  }

  @Test
  void shouldFailForAuthenticationInfoIfNotLocalHost() {
    CesToken token = new CesToken("secret", "192.167.2.1");

    AuthenticationInfo authenticationInfo = realm.doGetAuthenticationInfo(token);

    assertThat(authenticationInfo).isNull();
  }

  @Test
  void shouldCreateAuthorizationInfo() {
    SimplePrincipalCollection principals = new SimplePrincipalCollection("ces-service-account", REALM);
    principals.add(MARKER, REALM);
    principals.add(new User("ces-service-account", "CES Service Account User", null), REALM);

    AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(principals);

    assertThat(authorizationInfo.getStringPermissions())
      .contains("user:create", "permission:assign", "permission:read");
  }

  @Test
  void shouldFailForAuthorizationInfoWithWrongMarker() {
    SimplePrincipalCollection principals = new SimplePrincipalCollection("ces-service-account", REALM);
    principals.add(new User("ces-service-account", "CES Service Account User", null), REALM);

    AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(principals);

    assertThat(authorizationInfo).isNull();
  }
}
