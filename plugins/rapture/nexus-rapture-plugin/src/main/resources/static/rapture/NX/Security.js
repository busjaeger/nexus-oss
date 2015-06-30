/*
 * Sonatype Nexus (TM) Open Source Version
 * Copyright (c) 2008-present Sonatype, Inc.
 * All rights reserved. Includes the third-party code listed at http://links.sonatype.com/products/nexus/oss/attributions.
 *
 * This program and the accompanying materials are made available under the terms of the Eclipse Public License Version 1.0,
 * which accompanies this distribution and is available at http://www.eclipse.org/legal/epl-v10.html.
 *
 * Sonatype Nexus (TM) Professional Version is available from Sonatype, Inc. "Sonatype" and "Sonatype Nexus" are trademarks
 * of Sonatype, Inc. Apache Maven is a trademark of the Apache Software Foundation. M2eclipse is a trademark of the
 * Eclipse Foundation. All other trademarks are the property of their respective owners.
 */
/*global Ext, NX*/

/**
 * Helpers to interact with **{@link NX.controller.User}** controller.
 *
 * @since 3.0
 */
Ext.define('NX.Security', {
  singleton: true,
  requires: [
    'NX.controller.User'
  ],

  /**
   * @private
   * @returns {NX.controller.User}
   */
  controller: function () {
    return NX.getApplication().getController('User');
  },

  /**
   * See {@link NX.controller.User#hasUser}
   */
  hasUser: function () {
    var me = this;
    if (me.controller()) {
      return me.controller().hasUser();
    }
  },

  /**
   * See {@link NX.controller.User#askToAuthenticate}
   */
  askToAuthenticate: function (message, options) {
    var me = this;
    if (me.controller()) {
      me.controller().askToAuthenticate(message, options);
    }
  },

  /**
   * See {@link NX.controller.User#doWithAuthenticationToken}
   */
  doWithAuthenticationToken: function (message, options) {
    var me = this;
    if (me.controller()) {
      me.controller().doWithAuthenticationToken(message, options);
    }
  },

  /**
   * See {@link NX.controller.User#signOut}
   */
  signOut: function () {
    var me = this;
    if (me.controller()) {
      me.controller().signOut();
    }
  }

});
