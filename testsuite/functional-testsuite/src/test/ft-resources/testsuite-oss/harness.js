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
NX.TestHarness.configure({
  title: 'Nexus FT: OSS'
});

NX.TestHarness.start(
    {
      group: 'Framework',
      items: [
        {
          group: 'UT',
          hostPageUrl: undefined,
          waitForNxAppReady: false,
          preload: [
            NX.TestHarness.resource('static/rapture/baseapp-{mode}.js'),
            NX.TestHarness.resource('static/rapture/extdirect-{mode}.js'),
            'static/rapture/bootstrap.js'
          ],
          items: [
            { url: 'testsuite-oss/framework/statechange.t.js' },
            { url: 'testsuite-oss/framework/validation.t.js' },
            { url: 'testsuite-oss/framework/repository_urls.t.js' }
          ]
        },

        {
          group: 'FT',
          items: [
            { url: 'testsuite-oss/framework/signin_signout.t.js' },
            { url: 'testsuite-oss/framework/mode_button.t.js' },
            { url: 'testsuite-oss/framework/unsupported_browser.t.js' },
            { url: 'testsuite-oss/framework/bookmarking_unauthenticated.t.js' },
            { url: 'testsuite-oss/framework/bookmarking_authenticated.t.js' }
          ]
        }
      ]
    },

    {
      group: 'Repository',
      items: [
        {
          group: 'FT',
          items: [
            { url: 'testsuite-oss/repository/blobstore_crud.t.js' },
            { url: 'testsuite-oss/repository/repository_crud.t.js' }
          ]
        }
      ]
    },

    {
      group: 'Search',
      items: [
        {
          group: 'FT',
          items: [
            { url: 'testsuite-oss/search/search_basic.t.js' }
          ]
        }
      ]
    },

    {
      group: 'Browse',
      items: [
        {
          group: 'FT',
          items: [
            { url: 'testsuite-oss/browse/browse_assets.t.js' }
          ]
        }
      ]
    },

    {
      group: 'Security',
      items: [
        {
          group: 'FT',
          items: [
            { url: 'testsuite-oss/security/security_role.t.js' },
            { url: 'testsuite-oss/security/security_user.t.js' },
            { url: 'testsuite-oss/security/security_anonymous.t.js' },
            { url: 'testsuite-oss/security/security_realms.t.js' },
            { url: 'testsuite-oss/security/security_ssl_certificates.t.js' }
          ]
        }
      ]
    },

    {
      group: 'Support',
      items: [
        {
          group: 'FT',
          items: [
            { url: 'testsuite-oss/support/support_logging.t.js' },
            { url: 'testsuite-oss/support/support_metrics.t.js' },
            { url: 'testsuite-oss/support/support_sysinfo.t.js' },
            { url: 'testsuite-oss/support/support_zip.t.js' }
          ]
        }
      ]
    },

    {
      group: 'System',
      items: [
        {
          group: 'FT',
          items: [
            { url: 'testsuite-oss/system/system_bundles.t.js' },
            { url: 'testsuite-oss/system/system_tasks.t.js' },
            { url: 'testsuite-oss/system/system_email.t.js' },
            { url: 'testsuite-oss/system/http_configuration.t.js' },
            { url: 'testsuite-oss/system/system_capabilities.t.js' }
          ]
        }
      ]
    }
);
