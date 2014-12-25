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
 * Task grid.
 *
 * @since 3.0
 */
Ext.define('NX.coreui.view.task.TaskList', {
  extend: 'NX.view.drilldown.Master',
  alias: 'widget.nx-coreui-task-list',

  store: 'Task',

  columns: [
    {
      xtype: 'nx-iconcolumn',
      width: 36,
      iconVariant: 'x16',
      iconName: function () {
        return 'task-default';
      }
    },
    { header: NX.I18n.get('ADMIN_TASKS_LIST_NAME_COLUMN'), dataIndex: 'name', flex: 1 },
    { header: NX.I18n.get('ADMIN_TASKS_LIST_TYPE_COLUMN'), dataIndex: 'typeName', flex: 1 },
    { header: NX.I18n.get('ADMIN_TASKS_LIST_STATUS_COLUMN'), dataIndex: 'statusDescription' },
    { header: NX.I18n.get('ADMIN_TASKS_LIST_SCHEDULE_COLUMN'), dataIndex: 'schedule' },
    { header: NX.I18n.get('ADMIN_TASKS_LIST_NEXT_RUN_COLUMN'), dataIndex: 'nextRun', flex: 1 },
    { header: NX.I18n.get('ADMIN_TASKS_LIST_LAST_RUN_COLUMN'), dataIndex: 'lastRun', flex: 1 },
    { header: NX.I18n.get('ADMIN_TASKS_LIST_LAST_RESULT_COLUMN'), dataIndex: 'lastRunResult' }
  ],

  viewConfig: {
    emptyText: NX.I18n.get('ADMIN_TASKS_LIST_EMPTY_STATE'),
    deferEmptyText: false
  },

  tbar: [
    { xtype: 'button', text: NX.I18n.get('ADMIN_TASKS_LIST_NEW_BUTTON'), glyph: 'xf055@FontAwesome' /* fa-plus-circle */, action: 'new', disabled: true }
  ],

  plugins: [
    { ptype: 'gridfilterbox', emptyText: 'No scheduled task matched criteria "$filter"' }
  ]

});
