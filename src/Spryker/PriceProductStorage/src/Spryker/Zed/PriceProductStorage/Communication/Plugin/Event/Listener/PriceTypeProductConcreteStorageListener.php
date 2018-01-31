<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductStorage\Communication\Plugin\Event\Listener;

use Spryker\Zed\Event\Dependency\Plugin\EventBulkHandlerInterface;
use Spryker\Zed\PriceProduct\Dependency\PriceProductEvents;
use Spryker\Zed\PropelOrm\Business\Transaction\DatabaseTransactionHandlerTrait;

/**
 * @method \Spryker\Zed\PriceProductStorage\Persistence\PriceProductStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\PriceProductStorage\Communication\PriceProductStorageCommunicationFactory getFactory()
 */
class PriceTypeProductConcreteStorageListener extends AbstractPriceProductConcreteStorageListener implements EventBulkHandlerInterface
{
    use DatabaseTransactionHandlerTrait;

    /**
     * @api
     *
     * @param \Spryker\Shared\Kernel\Transfer\TransferInterface[] $eventTransfers
     * @param string $eventName
     *
     * @return void
     */
    public function handleBulk(array $eventTransfers, $eventName)
    {
        $this->preventTransaction();
        $priceTypeIds = $this->getFactory()->getEventBehaviorFacade()->getEventTransferIds($eventTransfers);
        $productIds = $this->getQueryContainer()->queryAllProductIdsByPriceTypeIds($priceTypeIds)->find()->getData();

        if ($eventName === PriceProductEvents::ENTITY_SPY_PRICE_TYPE_CREATE || $eventName === PriceProductEvents::ENTITY_SPY_PRICE_TYPE_UPDATE) {
            $this->publish($productIds);
        } elseif ($eventName === PriceProductEvents::ENTITY_SPY_PRICE_TYPE_DELETE) {
            $this->unpublish($productIds);
        }
    }
}
