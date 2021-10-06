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
