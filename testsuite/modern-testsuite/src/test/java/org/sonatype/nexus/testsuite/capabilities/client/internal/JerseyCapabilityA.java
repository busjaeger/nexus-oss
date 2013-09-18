/*
 * Sonatype Nexus (TM) Open Source Version
 * Copyright (c) 2007-2013 Sonatype, Inc.
 * All rights reserved. Includes the third-party code listed at http://links.sonatype.com/products/nexus/oss/attributions.
 *
 * This program and the accompanying materials are made available under the terms of the Eclipse Public License Version 1.0,
 * which accompanies this distribution and is available at http://www.eclipse.org/legal/epl-v10.html.
 *
 * Sonatype Nexus (TM) Professional Version is available from Sonatype, Inc. "Sonatype" and "Sonatype Nexus" are trademarks
 * of Sonatype, Inc. Apache Maven is a trademark of the Apache Software Foundation. M2eclipse is a trademark of the
 * Eclipse Foundation. All other trademarks are the property of their respective owners.
 */

package org.sonatype.nexus.testsuite.capabilities.client.internal;

import org.sonatype.nexus.capabilities.client.spi.CapabilityClient;
import org.sonatype.nexus.capabilities.client.support.CapabilityImpl;
import org.sonatype.nexus.capabilities.model.CapabilityStatusXO;
import org.sonatype.nexus.capabilities.model.CapabilityStatusXO;
import org.sonatype.nexus.testsuite.capabilities.client.CapabilityA;

/**
 * @since 2.2
 */
public class JerseyCapabilityA
    extends CapabilityImpl<CapabilityA>
    implements CapabilityA
{

  public JerseyCapabilityA(final CapabilityClient client) {
    super(client, "[a]");
  }

  public JerseyCapabilityA(final CapabilityClient client, final CapabilityStatusXO settings) {
    super(client, settings);
  }

  @Override
  public String propertyA1() {
    return property("a1");
  }

  @Override
  public CapabilityA withPropertyA1(final String value) {
    withProperty("a1", value);
    return this;
  }


}
