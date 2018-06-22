<?php

/**
 * Copyright © 2017-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Dataset\Communication\Controller;

use SprykerTest\Zed\Dataset\DatasetCommunicationTester;
use SprykerTest\Zed\Dataset\DatasetObject\DatasetAddDatasetPage;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Dataset
 * @group Communication
 * @group Controller
 * @group DatasetAddCest
 * Add your own group annotations below this line
 */
class DatasetAddCest
{
    /**
     * @param \SprykerTest\Zed\Dataset\DatasetCommunicationTester $i
     *
     * @return void
     */
    public function breadcrumbIsVisible(DatasetCommunicationTester $i)
    {
        $i->amOnPage(DatasetAddDatasetPage::URL);
        $i->seeBreadcrumbNavigation('Dashboard / Dataset / Add dashboard');
    }
}
