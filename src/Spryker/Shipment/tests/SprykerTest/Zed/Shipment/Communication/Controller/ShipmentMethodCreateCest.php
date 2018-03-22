<?php

/**
 * Copyright © 2017-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Shipment\Communication\Controller;

use SprykerTest\Zed\Shipment\PageObject\ShipmentMethodCreatePage;
use SprykerTest\Zed\Shipment\ShipmentCommunicationTester;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Shipment
 * @group Communication
 * @group Controller
 * @group ShipmentMethodCreateCest
 * Add your own group annotations below this line
 */
class ShipmentMethodCreateCest
{
    /**
     * @param \SprykerTest\Zed\Shipment\ShipmentCommunicationTester $i
     *
     * @return void
     */
    public function breadcrumbIsVisible(ShipmentCommunicationTester $i)
    {
        $i->registerMoneyCollectionFormTypePlugin();

        $i->amOnPage(ShipmentMethodCreatePage::URL);
        $i->seeBreadcrumbNavigation('Dashboard / Shipment / Shipment Methods / Create new Shipment Method');
    }
}
