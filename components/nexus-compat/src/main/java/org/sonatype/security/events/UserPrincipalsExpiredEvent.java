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

package org.sonatype.security.events;

import org.sonatype.plexus.appevents.AbstractEvent;

/**
 * An event fired when a user is removed from the system, so cached principals can be expired.
 *
 * @since sonatype-security 2.8
 * @deprecated use {@link AuthorizationConfigurationChanged} event via an EventBus handler
 */
@Deprecated
public class UserPrincipalsExpiredEvent
    extends AbstractEvent<Object>
{

  private final String userId;

  private final String source;

  /**
   * Applies to any cached user principals that have the given userId and UserManager source.
   *
   * @param component The sending component
   * @param userId    The removed user's id
   * @param source    The UserManager source
   */
  public UserPrincipalsExpiredEvent(Object component, String userId, String source) {
    super(component);

    this.userId = userId;
    this.source = source;
  }

  /**
   * Applies to all cached user principals that have an invalid userId or UserManager source.
   *
   * @param component The sending component
   */
  public UserPrincipalsExpiredEvent(Object component) {
    this(component, null, null);
  }

  public String getUserId() {
    return userId;
  }

  public String getSource() {
    return source;
  }
}
