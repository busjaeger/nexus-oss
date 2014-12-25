/*
 * Sonatype Nexus (TM) Open Source Version
 * Copyright (c) 2007-2014 Sonatype, Inc.
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
 * Repository feature panel.
 *
 * @since 3.0
 */
Ext.define('NX.coreui.view.repository.RepositoryFeature', {
  extend: 'NX.view.drilldown.Drilldown',
  alias: 'widget.nx-coreui-repository-feature',

  iconName: 'repository-default',

  masters: { xtype: 'nx-coreui-repository-list' },

  tabs: [
    { xtype: 'nx-coreui-repository-settings', title: NX.I18n.get('ADMIN_REPOSITORIES_DETAILS_SETTINGS_TAB'), weight: 10 }
  ],

  actions: [
    { xtype: 'button', text: NX.I18n.get('ADMIN_REPOSITORIES_DETAILS_DELETE_BUTTON'), glyph: 'xf056@FontAwesome' /* fa-minus-circle */, action: 'delete', disabled: true },
    { xtype: 'button', text: NX.I18n.get('ADMIN_REPOSITORIES_DETAILS_MORE_BUTTON'), glyph: 'xf0ae@FontAwesome' /* fa-tasks */, action: 'more',
      menu: []
    },
    '-',
    { xtype: 'button', text: NX.I18n.get('ADMIN_REPOSITORIES_DETAILS_BROWSE_BUTTON'), glyph: 'xf0e8@FontAwesome' /* fa-sitemap */, action: 'browse' }
  ]
});
