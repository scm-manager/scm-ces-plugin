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

import javax.inject.Inject;

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
      return null;
    }
    SimplePrincipalCollection principalCollection = new SimplePrincipalCollection("ces-service-account", REALM);
    principalCollection.add(MARKER, REALM);
    principalCollection.add(new User("ces-service-account", "CES Service Account User", null), REALM);
    LOG.info("Creating authentication for ces realm");
    return new SimpleAuthenticationInfo(principalCollection, null);
  }

  static class CesTokenRealmMarker {
  }
}
