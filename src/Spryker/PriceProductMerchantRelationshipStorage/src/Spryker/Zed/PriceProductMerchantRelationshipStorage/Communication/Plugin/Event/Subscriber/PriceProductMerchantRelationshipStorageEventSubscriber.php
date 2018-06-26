<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductMerchantRelationshipStorage\Communication\Plugin\Event\Subscriber;

use Spryker\Zed\Event\Dependency\EventCollectionInterface;
use Spryker\Zed\Event\Dependency\Plugin\EventSubscriberInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\PriceProductMerchantRelationship\Dependency\PriceProductMerchantRelationshipEvents;
use Spryker\Zed\PriceProductMerchantRelationshipStorage\Communication\Plugin\Event\Listener\PriceProductMerchantRelationshipAbstractListener;
use Spryker\Zed\PriceProductMerchantRelationshipStorage\Communication\Plugin\Event\Listener\PriceProductMerchantRelationshipConcreteListener;
use Spryker\Zed\PriceProductMerchantRelationshipStorage\Communication\Plugin\Event\Listener\PriceProductStoreAbstractListener;
use Spryker\Zed\PriceProductMerchantRelationshipStorage\Communication\Plugin\Event\Listener\PriceProductStoreConcreteListener;

/**
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Business\PriceProductMerchantRelationshipStorageFacadeInterface getFacade()
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Communication\PriceProductMerchantRelationshipStorageCommunicationFactory getFactory()
 */
class PriceProductMerchantRelationshipStorageEventSubscriber extends AbstractPlugin implements EventSubscriberInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return \Spryker\Zed\Event\Dependency\EventCollectionInterface
     */
    public function getSubscribedEvents(EventCollectionInterface $eventCollection): EventCollectionInterface
    {
        $this->addConcretePriceProductStoreCreateListener($eventCollection)
            ->addConcretePriceProductStoreUpdateListener($eventCollection)
            ->addConcretePriceProductStoreDeleteListener($eventCollection)
            ->addConcretePriceProductMerchantRelationshipCreateListener($eventCollection)
            ->addConcretePriceProductMerchantRelationshipUpdateListener($eventCollection)
            ->addConcretePriceProductMerchantRelationshipDeleteListener($eventCollection)
            ->addAbstractPriceProductStoreCreateListener($eventCollection)
            ->addAbstractPriceProductStoreUpdateListener($eventCollection)
            ->addAbstractPriceProductStoreDeleteListener($eventCollection)
            ->addAbstractPriceProductMerchantRelationshipCreateListener($eventCollection)
            ->addAbstractPriceProductMerchantRelationshipUpdateListener($eventCollection)
            ->addAbstractPriceProductMerchantRelationshipDeleteListener($eventCollection);

        return $eventCollection;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addConcretePriceProductStoreCreateListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_STORE_CREATE,
            new PriceProductStoreConcreteListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addConcretePriceProductStoreUpdateListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_STORE_UPDATE,
            new PriceProductStoreConcreteListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addConcretePriceProductStoreDeleteListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_STORE_DELETE,
            new PriceProductStoreConcreteListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addConcretePriceProductMerchantRelationshipCreateListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_MERCHANT_RELATIONSHIP_CREATE,
            new PriceProductMerchantRelationshipConcreteListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addConcretePriceProductMerchantRelationshipUpdateListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_MERCHANT_RELATIONSHIP_UPDATE,
            new PriceProductMerchantRelationshipConcreteListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addConcretePriceProductMerchantRelationshipDeleteListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_MERCHANT_RELATIONSHIP_DELETE,
            new PriceProductMerchantRelationshipConcreteListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addAbstractPriceProductStoreCreateListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_STORE_CREATE,
            new PriceProductStoreAbstractListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addAbstractPriceProductStoreUpdateListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_STORE_UPDATE,
            new PriceProductStoreAbstractListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addAbstractPriceProductStoreDeleteListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_STORE_DELETE,
            new PriceProductStoreAbstractListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addAbstractPriceProductMerchantRelationshipCreateListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_MERCHANT_RELATIONSHIP_CREATE,
            new PriceProductMerchantRelationshipAbstractListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addAbstractPriceProductMerchantRelationshipUpdateListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_MERCHANT_RELATIONSHIP_UPDATE,
            new PriceProductMerchantRelationshipAbstractListener()
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Event\Dependency\EventCollectionInterface $eventCollection
     *
     * @return $this
     */
    protected function addAbstractPriceProductMerchantRelationshipDeleteListener(EventCollectionInterface $eventCollection): self
    {
        $eventCollection->addListenerQueued(
            PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_MERCHANT_RELATIONSHIP_DELETE,
            new PriceProductMerchantRelationshipAbstractListener()
        );

        return $this;
    }
}
