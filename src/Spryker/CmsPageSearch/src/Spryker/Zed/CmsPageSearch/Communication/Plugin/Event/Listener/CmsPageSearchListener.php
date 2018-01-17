<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CmsPageSearch\Communication\Plugin\Event\Listener;

use Spryker\Zed\Cms\Dependency\CmsEvents;
use Spryker\Zed\Event\Dependency\Plugin\EventBulkHandlerInterface;

/**
 * @method \Spryker\Zed\CmsPageSearch\Communication\CmsPageSearchCommunicationFactory getFactory()
 * @method \Spryker\Zed\CmsPageSearch\Persistence\CmsPageSearchQueryContainerInterface getQueryContainer()
 */
class CmsPageSearchListener extends AbstractCmsPageSearchListener implements EventBulkHandlerInterface
{
    /**
     * @param array $eventTransfers
     * @param string $eventName
     *
     * @return void
     */
    public function handleBulk(array $eventTransfers, $eventName)
    {
        $this->preventTransaction();
        $cmsPageIds = $this->getFactory()->getEventBehaviorFacade()->getEventTransferIds($eventTransfers);

        if ($eventName === CmsEvents::ENTITY_SPY_CMS_PAGE_UPDATE ||
            $eventName === CmsEvents::CMS_VERSION_PUBLISH
        ) {
            $this->publish($cmsPageIds);
        } elseif ($eventName === CmsEvents::ENTITY_SPY_CMS_PAGE_DELETE ||
            $eventName === CmsEvents::CMS_VERSION_UNPUBLISH
        ) {
            $this->unpublish($cmsPageIds);
        }
    }
}
