<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductCategoryStorage\Communication\Plugin\Event\Listener;

use Orm\Zed\Category\Persistence\Map\SpyCategoryTableMap;
use Spryker\Zed\Category\Dependency\CategoryEvents;
use Spryker\Zed\Event\Dependency\Plugin\EventBulkHandlerInterface;
use Spryker\Zed\PropelOrm\Business\Transaction\DatabaseTransactionHandlerTrait;

/**
 * @method \Spryker\Zed\ProductCategoryStorage\Persistence\ProductCategoryStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\ProductCategoryStorage\Communication\ProductCategoryStorageCommunicationFactory getFactory()
 */
class CategoryStorageListener extends AbstractProductCategoryStorageListener implements EventBulkHandlerInterface
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
        if ($eventName === CategoryEvents::ENTITY_SPY_CATEGORY_DELETE) {
            $categoryIds = $this->getFactory()->getEventBehaviorFacade()->getEventTransferIds($eventTransfers);
        } else {
            $categoryIds = $this->getValidCategoryIds($eventTransfers);
        }

        if (empty($categoryIds)) {
            return;
        }

        $relatedCategoryIds = $this->getRelatedCategoryIds($categoryIds);
        $productAbstractIds = $this->getQueryContainer()->queryProductAbstractIdsByCategoryIds($relatedCategoryIds)->find()->getData();

        $this->publish($productAbstractIds);
    }

    /**
     * @param array $eventTransfers
     *
     * @return array
     */
    protected function getValidCategoryIds(array $eventTransfers)
    {
        $validEventTransfers = $this->getFactory()->getEventBehaviorFacade()->getEventTransfersByModifiedColumns(
            $eventTransfers,
            [
                SpyCategoryTableMap::COL_IS_ACTIVE,
                SpyCategoryTableMap::COL_CATEGORY_KEY,
            ]
        );

        return $this->getFactory()->getEventBehaviorFacade()->getEventTransferIds($validEventTransfers);
    }
}
