<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPackagingUnitStorage\Communication\Plugin\Event\Subscriber;

use Spryker\Zed\Event\Dependency\EventCollectionInterface;
use Spryker\Zed\Event\Dependency\Plugin\EventSubscriberInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\ProductPackagingUnit\Dependency\ProductPackagingUnitEvents;
use Spryker\Zed\ProductPackagingUnitStorage\Communication\Plugin\Event\Listener\ProductAbstractPackagingStoragePublishListener;
use Spryker\Zed\ProductPackagingUnitStorage\Communication\Plugin\Event\Listener\ProductAbstractPackagingStorageUnpublishListener;
use Spryker\Zed\ProductPackagingUnitStorage\Communication\Plugin\Event\Listener\ProductPackagingLeadProductStoragePublishListener;
use Spryker\Zed\ProductPackagingUnitStorage\Communication\Plugin\Event\Listener\ProductPackagingLeadProductStorageUnpublishListener;
use Spryker\Zed\ProductPackagingUnitStorage\Communication\Plugin\Event\Listener\ProductPackagingUnitTypePublishStoragePublishListener;
use Spryker\Zed\ProductPackagingUnitStorage\Communication\Plugin\Event\Listener\ProductPackagingUnitTypePublishStorageUnpublishListener;

/**
 * @method \Spryker\Zed\ProductPackagingUnitStorage\Communication\ProductPackagingUnitStorageCommunicationFactory getFactory()
 * @method \Spryker\Zed\ProductPackagingUnitStorage\Business\ProductPackagingUnitStorageFacadeInterface getFacade()
 * @method \Spryker\Zed\ProductPackagingUnitStorage\ProductPackagingUnitStorageConfig getConfig()
 */
class ProductPackagingUnitStorageEventSubscriber extends AbstractPlugin implements EventSubscriberInterface
{
    /**
     * @api
     *
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return \Spryker\Zed\Event\Dependency\EventCollectionInterface
     */
    public function getSubscribedEvents(EventCollectionInterface $eventCollection): EventCollectionInterface
    {
        $this->addProductAbstractPublishStorageListener($eventCollection);
        $this->addProductAbstractUnpublishStorageListener($eventCollection);

        return $eventCollection;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return void
     */
    protected function addProductAbstractPublishStorageListener(EventCollectionInterface $eventCollection): void
    {
        $eventCollection->addListenerQueued(ProductPackagingUnitEvents::PRODUCT_ABSTRACT_PACKAGING_PUBLISH, new ProductAbstractPackagingStoragePublishListener());

        $eventCollection->addListenerQueued(ProductPackagingUnitEvents::ENTITY_SPY_PRODUCT_PACKAGING_UNIT_TYPE_CREATE, new ProductPackagingUnitTypePublishStoragePublishListener());
        $eventCollection->addListenerQueued(ProductPackagingUnitEvents::ENTITY_SPY_PRODUCT_PACKAGING_UNIT_TYPE_UPDATE, new ProductPackagingUnitTypePublishStoragePublishListener());

        $eventCollection->addListenerQueued(ProductPackagingUnitEvents::ENTITY_SPY_PRODUCT_PACKAGING_LEAD_PRODUCT_CREATE, new ProductPackagingLeadProductStoragePublishListener());
        $eventCollection->addListenerQueued(ProductPackagingUnitEvents::ENTITY_SPY_PRODUCT_PACKAGING_LEAD_PRODUCT_UPDATE, new ProductPackagingLeadProductStoragePublishListener());
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return void
     */
    protected function addProductAbstractUnpublishStorageListener(EventCollectionInterface $eventCollection): void
    {
        $eventCollection->addListenerQueued(ProductPackagingUnitEvents::PRODUCT_ABSTRACT_PACKAGING_UNPUBLISH, new ProductAbstractPackagingStorageUnpublishListener());

        $eventCollection->addListenerQueued(ProductPackagingUnitEvents::ENTITY_SPY_PRODUCT_PACKAGING_UNIT_TYPE_DELETE, new ProductPackagingUnitTypePublishStorageUnpublishListener());

        $eventCollection->addListenerQueued(ProductPackagingUnitEvents::ENTITY_SPY_PRODUCT_PACKAGING_LEAD_PRODUCT_DELETE, new ProductPackagingLeadProductStorageUnpublishListener());
    }
}
