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

import com.google.common.base.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sonia.scm.plugin.Extension;
import sonia.scm.web.WebTokenGenerator;

import javax.servlet.http.HttpServletRequest;

@Extension
class CesTokenGenerator implements WebTokenGenerator {

  private static final Logger LOG = LoggerFactory.getLogger(CesTokenGenerator.class);

  private final String tokenHeader;

  CesTokenGenerator() {
    this(System.getenv("CES_TOKEN_HEADER"));
  }

  CesTokenGenerator(String tokenHeader) {
    this.tokenHeader = tokenHeader;
  }

  @Override
  public CesToken createToken(HttpServletRequest request) {
    LOG.trace("Try to read token");
    if (tokenHeader == null) {
      LOG.warn("Could not read header name for ces token");
      return null;
    }
    String cesToken = request.getHeader(tokenHeader);
    LOG.trace("Got value for header '{}'", tokenHeader);
    if (!Strings.isNullOrEmpty(cesToken)) {
      LOG.debug("Found ces token");
      return new CesToken(cesToken, request.getRemoteAddr());
    }
    return null;
  }
}
