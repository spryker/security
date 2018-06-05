<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnitStorage\Communication\Plugin\Event\Listener;

use Spryker\Zed\Event\Dependency\Plugin\EventBulkHandlerInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\PriceProduct\Dependency\PriceProductEvents;
use Spryker\Zed\PropelOrm\Business\Transaction\DatabaseTransactionHandlerTrait;

/**
 * @method \Spryker\Zed\ProductPackagingUnitStorage\Persistence\ProductPackagingUnitStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\ProductPackagingUnitStorage\Communication\PriceProductStorageCommunicationFactory getFactory()
 * @method \Spryker\Zed\ProductPackagingUnitStorage\Business\ProductPackagingUnitStorageFacadeInterface getFacade()
 */
class PriceProductConcretePublishStorageListener extends AbstractPlugin implements EventBulkHandlerInterface
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
        $concreteIds = $this->getFactory()->getEventBehaviorFacade()->getEventTransferIds($eventTransfers);

        if ($eventName === PriceProductEvents::ENTITY_SPY_PRICE_TYPE_DELETE ||
            $eventName === PriceProductEvents::ENTITY_SPY_PRICE_PRODUCT_DELETE ||
            $eventName === PriceProductEvents::PRICE_CONCRETE_UNPUBLISH
        ) {
            $this->getFacade()->unpublishPriceProductConcrete($concreteIds);

            return;
        }
        $this->getFacade()->publishProductAbstractPackaging($concreteIds);
    }
}
