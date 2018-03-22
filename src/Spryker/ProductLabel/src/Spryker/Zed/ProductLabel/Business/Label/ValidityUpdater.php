<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductLabel\Business\Label;

use Propel\Runtime\Collection\ObjectCollection;
use Spryker\Zed\ProductLabel\Business\Touch\LabelDictionaryTouchManagerInterface;
use Spryker\Zed\ProductLabel\Persistence\ProductLabelQueryContainerInterface;
use Spryker\Zed\PropelOrm\Business\Transaction\DatabaseTransactionHandlerTrait;

class ValidityUpdater implements ValidityUpdaterInterface
{
    use DatabaseTransactionHandlerTrait;

    /**
     * @var \Spryker\Zed\ProductLabel\Persistence\ProductLabelQueryContainerInterface
     */
    protected $queryContainer;

    /**
     * @var \Spryker\Zed\ProductLabel\Business\Touch\LabelDictionaryTouchManagerInterface
     */
    protected $dictionaryTouchManager;

    /**
     * @param \Spryker\Zed\ProductLabel\Persistence\ProductLabelQueryContainerInterface $queryContainer
     * @param \Spryker\Zed\ProductLabel\Business\Touch\LabelDictionaryTouchManagerInterface $dictionaryTouchManager
     */
    public function __construct(
        ProductLabelQueryContainerInterface $queryContainer,
        LabelDictionaryTouchManagerInterface $dictionaryTouchManager
    ) {
        $this->queryContainer = $queryContainer;
        $this->dictionaryTouchManager = $dictionaryTouchManager;
    }

    /**
     * @return void
     */
    public function checkAndTouchAllLabels()
    {
        $productLabelsBecomingActive = $this->findLabelsBecomingActive();
        $productLabelsBecomingInactive = $this->findLabelsBecomingInactive();

        if (!$productLabelsBecomingActive->count() && !$productLabelsBecomingInactive->count()) {
            return;
        }

        $this->handleDatabaseTransaction(function () use ($productLabelsBecomingActive, $productLabelsBecomingInactive) {
            $this->executeTransaction($productLabelsBecomingActive, $productLabelsBecomingInactive);
        });
    }

    /**
     * @return \Orm\Zed\ProductLabel\Persistence\SpyProductLabel[]|\Propel\Runtime\Collection\ObjectCollection
     */
    protected function findLabelsBecomingActive()
    {
        return $this
            ->queryContainer
            ->queryUnpublishedProductLabelsBecomingValid()
            ->find();
    }

    /**
     * @return \Orm\Zed\ProductLabel\Persistence\SpyProductLabel[]|\Propel\Runtime\Collection\ObjectCollection
     */
    protected function findLabelsBecomingInactive()
    {
        return $this
            ->queryContainer
            ->queryPublishedProductLabelsBecomingInvalid()
            ->find();
    }

    /**
     * @param \Orm\Zed\ProductLabel\Persistence\SpyProductLabel[]|\Propel\Runtime\Collection\ObjectCollection $productLabelsBecomingActive
     * @param \Orm\Zed\ProductLabel\Persistence\SpyProductLabel[]|\Propel\Runtime\Collection\ObjectCollection $productLabelsBecomingInactive
     *
     * @return void
     */
    protected function executeTransaction($productLabelsBecomingActive, $productLabelsBecomingInactive)
    {
        $this->setPublished($productLabelsBecomingActive);
        $this->setUnpublished($productLabelsBecomingInactive);

        $this->dictionaryTouchManager->touchActive();
    }

    /**
     * @param \Orm\Zed\ProductLabel\Persistence\SpyProductLabel[]|\Propel\Runtime\Collection\ObjectCollection $productLabelEntities
     *
     * @return void
     */
    protected function setPublished(ObjectCollection $productLabelEntities)
    {
        foreach ($productLabelEntities as $productLabelEntity) {
            $productLabelEntity->setIsPublished(true);
            $productLabelEntity->save();
        }
    }

    /**
     * @param \Orm\Zed\ProductLabel\Persistence\SpyProductLabel[]|\Propel\Runtime\Collection\ObjectCollection $productLabelEntities
     *
     * @return void
     */
    protected function setUnpublished(ObjectCollection $productLabelEntities)
    {
        foreach ($productLabelEntities as $productLabelEntity) {
            $productLabelEntity->setIsPublished(false);
            $productLabelEntity->save();
        }
    }
}
