<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CategoryPageSearch\Communication\Plugin\Event\Listener;

use Spryker\Zed\Event\Dependency\Plugin\EventBulkHandlerInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\PropelOrm\Business\Transaction\DatabaseTransactionHandlerTrait;

/**
 * @method \Spryker\Zed\CategoryPageSearch\Persistence\CategoryPageSearchQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\CategoryPageSearch\Communication\CategoryPageSearchCommunicationFactory getFactory()
 * @method \Spryker\Zed\CategoryPageSearch\Business\CategoryPageSearchFacadeInterface getFacade()
 * @method \Spryker\Zed\CategoryPageSearch\CategoryPageSearchConfig getConfig()
 */
class CategoryNodeCategoryPageSearchPublishListener extends AbstractPlugin implements EventBulkHandlerInterface
{
    use DatabaseTransactionHandlerTrait;

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\EventEntityTransfer[] $eventTransfers
     * @param string $eventName
     *
     * @return void
     */
    public function handleBulk(array $eventTransfers, $eventName)
    {
        $this->preventTransaction();
        $categoryIds = $this->getFactory()->getEventBehaviorFacade()->getEventTransferIds($eventTransfers);
        $categoryNodeIds = $this->getQueryContainer()->queryCategoryNodeIdsByCategoryIds($categoryIds)->find()->getData();

        $this->getFacade()->publish($categoryNodeIds);
    }
}
