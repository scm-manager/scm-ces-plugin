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
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.plugin.Extension;
import sonia.scm.security.PermissionPermissions;
import sonia.scm.user.User;
import sonia.scm.user.UserPermissions;

import jakarta.inject.Inject;

import static com.google.common.base.Preconditions.checkArgument;
import static java.util.Arrays.asList;

@Extension
public class CesTokenRealm extends AuthorizingRealm {

  static final CesTokenRealmMarker MARKER = new CesTokenRealmMarker();
  static final String REALM = "CES Service Account";

  private static final Logger LOG = LoggerFactory.getLogger(CesTokenRealm.class);

  private final CesAccessValidator validator;

  @Inject
  public CesTokenRealm(CesAccessValidator validator) {
    this.validator = validator;
    setCredentialsMatcher(new AllowAllCredentialsMatcher());
    setAuthenticationTokenClass(CesToken.class);
  }

  @Override
  protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
    CesTokenRealmMarker cesTokenRealmMarker = principals.oneByType(CesTokenRealmMarker.class);
    if (cesTokenRealmMarker == MARKER) {
      LOG.trace("Got authorization from ces realm");
      SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
      authorizationInfo.addStringPermissions(
        asList(
          UserPermissions.list().asShiroString(),
          UserPermissions.create().asShiroString(),
          UserPermissions.read("*").asShiroString(),
          UserPermissions.delete("*").asShiroString(),
          PermissionPermissions.assign().asShiroString(),
          PermissionPermissions.read().asShiroString()
        ));
      return authorizationInfo;
    }
    return null;
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    checkArgument(token instanceof CesToken, "%s is required", CesToken.class);
    CesToken cesToken = (CesToken) token;
    validator.checkToken(cesToken.getCredentials());
    if (!cesToken.getRemoteAddress().equals("127.0.0.1")) {
      LOG.debug("Rejecting ces token from non-localhost");
      return null;
    }
    SimplePrincipalCollection principalCollection = new SimplePrincipalCollection("ces-service-account", REALM);
    principalCollection.add(MARKER, REALM);
    principalCollection.add(new User("ces-service-account", "CES Service Account User", null), REALM);
    LOG.debug("Creating authentication for ces realm");
    return new SimpleAuthenticationInfo(principalCollection, null);
  }

  static class CesTokenRealmMarker {
  }
}
