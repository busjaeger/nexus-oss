/*
 * Sonatype Nexus (TM) Open Source Version
 * Copyright (c) 2008-2015 Sonatype, Inc.
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

/*global NX, Ext, Sonatype*/

/**
 * 'combo' factory.
 *
 * @since 3.0
 */
Ext.define('NX.coreui.view.formfield.factory.FormfieldItemSelectorFactory', {
  singleton: true,
  alias: [
    'nx.formfield.factory.itemselector'
  ],
  requires: [
    'Ext.data.Store'
  ],
  mixins: {
    logAware: 'NX.LogAware'
  },

  /**
   * Creates an itemselector.
   * @param formField form field to create itemselector for
   * @returns {*} created itemselector (never null)
   */
  create: function (formField) {
    var item, 
        itemConfig = {
          xtype: 'nx-itemselector',
          fieldLabel: formField.label,
          itemCls: formField.required ? 'required-field' : '',
          helpText: formField.helpText,
          name: formField.id,
          displayField: 'name',
          valueField: 'id',
          editable: false,
          forceSelection: true,
          queryMode: 'local',
          triggerAction: 'all',
          selectOnFocus: false,
          allowBlank: !formField.required,
          buttons: ['up', 'add', 'remove', 'down'],
          fromTitle: formField.fromTitle,
          toTitle: formField.toTitle
        };

    if (formField.initialValue) {
      itemConfig.value = formField.initialValue;
    }
    if (formField['store']) {
      itemConfig.store = formField['store']; 
    }
    
    item = Ext.create('NX.ext.form.field.ItemSelector', itemConfig);
    return item;
  }

});
