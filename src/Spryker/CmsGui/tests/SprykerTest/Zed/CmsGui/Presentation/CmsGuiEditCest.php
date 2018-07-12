<?php

/**
 * Copyright © 2017-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\CmsGui\Presentation;

use SprykerTest\Zed\CmsGui\CmsGuiPresentationTester;
use SprykerTest\Zed\CmsGui\PageObject\CmsGuiListPage;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group CmsGui
 * @group Presentation
 * @group CmsGuiEditCest
 * Add your own group annotations below this line
 */
class CmsGuiEditCest
{
    /**
     * @param \SprykerTest\Zed\CmsGui\CmsGuiPresentationTester $i
     *
     * @return void
     */
    public function breadcrumbIsVisible(CmsGuiPresentationTester $i)
    {
        $i->amOnPage(CmsGuiListPage::URL);
        $i->clickDataTableLinkInDropDownOfButton('Edit', 'Page');
        $i->seeBreadcrumbNavigation('Dashboard / Content Management / Pages / Edit CMS Page');
    }
}
