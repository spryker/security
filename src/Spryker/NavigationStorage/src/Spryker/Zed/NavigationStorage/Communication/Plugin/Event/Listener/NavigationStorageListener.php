<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\NavigationStorage\Communication\Plugin\Event\Listener;

use Spryker\Zed\Navigation\Dependency\NavigationEvents;
use Spryker\Zed\PropelOrm\Business\Transaction\DatabaseTransactionHandlerTrait;

/**
 * @method \Spryker\Zed\NavigationStorage\Persistence\NavigationStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\NavigationStorage\Communication\NavigationStorageCommunicationFactory getFactory()
 */
class NavigationStorageListener extends AbstractNavigationStorageListener
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
        $navigationIds = $this->getFactory()->getEventBehaviorFacade()->getEventTransferIds($eventTransfers);

        if ($eventName === NavigationEvents::ENTITY_SPY_NAVIGATION_DELETE ||
            $eventName === NavigationEvents::NAVIGATION_KEY_UNPUBLISH
        ) {
            $this->unpublish($navigationIds);
        } else {
            $this->publish($navigationIds);
        }
    }
}
