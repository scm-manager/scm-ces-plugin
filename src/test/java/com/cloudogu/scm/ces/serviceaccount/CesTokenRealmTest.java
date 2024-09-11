/*
 * Copyright (c) 2020 - present Cloudogu GmbH
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see https://www.gnu.org/licenses/.
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
      .contains(
        "user:list",
        "user:read:*",
        "user:create",
        "user:delete:*",
        "permission:assign",
        "permission:read"
      );
  }

  @Test
  void shouldFailForAuthorizationInfoWithWrongMarker() {
    SimplePrincipalCollection principals = new SimplePrincipalCollection("ces-service-account", REALM);
    principals.add(new User("ces-service-account", "CES Service Account User", null), REALM);

    AuthorizationInfo authorizationInfo = realm.doGetAuthorizationInfo(principals);

    assertThat(authorizationInfo).isNull();
  }
}
