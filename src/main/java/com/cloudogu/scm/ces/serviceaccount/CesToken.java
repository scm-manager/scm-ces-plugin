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

import org.apache.shiro.authc.AuthenticationToken;

public class CesToken implements AuthenticationToken {

  private final String credentials;
  private final String remoteAddress;

  public CesToken(String credentials, String remoteAddress) {
    this.credentials = credentials;
    this.remoteAddress = remoteAddress;
  }

  @Override
  public Object getPrincipal() {
    return null;
  }

  @Override
  public String getCredentials() {
    return credentials;
  }

  public String getRemoteAddress() {
    return remoteAddress;
  }
}
