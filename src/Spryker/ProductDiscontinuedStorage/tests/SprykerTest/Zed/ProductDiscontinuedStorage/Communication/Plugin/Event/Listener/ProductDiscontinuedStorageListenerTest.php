<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\ProductDiscontinuedStorage\Communication\Plugin\Event\Listener;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\EventEntityTransfer;
use Generated\Shared\Transfer\ProductDiscontinueRequestTransfer;
use Spryker\Zed\ProductDiscontinued\Dependency\ProductDiscontinuedEvents;
use Spryker\Zed\ProductDiscontinuedStorage\Communication\Plugin\Event\Listener\ProductDiscontinuedStorageListener;
use Spryker\Zed\ProductDiscontinuedStorage\Communication\Plugin\Event\Listener\ProductDiscontinuedStoragePublishListener;
use Spryker\Zed\ProductDiscontinuedStorage\Communication\Plugin\Event\Listener\ProductDiscontinuedStorageUnpublishListener;
use Spryker\Zed\ProductDiscontinuedStorage\Persistence\ProductDiscontinuedStorageRepository;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group ProductDiscontinuedStorage
 * @group Communication
 * @group Plugin
 * @group Event
 * @group Listener
 * @group ProductDiscontinuedStorageListenerTest
 * Add your own group annotations below this line
 */
class ProductDiscontinuedStorageListenerTest extends Unit
{
    /**
     * @var \SprykerTest\Zed\ProductDiscontinuedStorage\ProductDiscontinuedStorageBusinessTester
     */
    protected $tester;

    /**
     * @var \Spryker\Zed\ProductDiscontinuedStorage\Persistence\ProductDiscontinuedStorageRepository
     */
    protected $productDiscontinuedStorageRepository;

    /**
     * @var \Spryker\Zed\ProductDiscontinuedStorage\Communication\Plugin\Event\Listener\ProductDiscontinuedStorageListener
     */
    protected $productDiscontinuedStorageListener;

    /**
     * @var \Generated\Shared\Transfer\ProductDiscontinuedTransfer
     */
    protected $productDiscontinuedTransfer;

    /**
     * @return void
     */
    protected function setUp()
    {
        parent::setUp();

        $this->productDiscontinuedStorageRepository = new ProductDiscontinuedStorageRepository();

        $this->productDiscontinuedStorageListener = new ProductDiscontinuedStorageListener();
        $this->productDiscontinuedStorageListener->setFacade($this->tester->getFacade());

        $productConcrete = $this->tester->haveProduct();
        $productDiscontinuedRequestTransfer = (new ProductDiscontinueRequestTransfer())
            ->setIdProduct($productConcrete->getIdProductConcrete());
        $this->productDiscontinuedTransfer = $this->tester->getProductDiscontinuedFacade()->markProductAsDiscontinued(
            $productDiscontinuedRequestTransfer
        )
            ->getProductDiscontinued();
    }

    /**
     * @return void
     */
    public function testProductDiscontinuedStorageEntityCanBePublished()
    {
        $this->markTestSkipped('No availability to skip entity transfer sending to Queue');
        // Arrange
        $eventTransfers = [
            (new EventEntityTransfer())->setId($this->productDiscontinuedTransfer->getIdProductDiscontinued()),
        ];

        // Act
        $this->productDiscontinuedStorageListener->handleBulk(
            $eventTransfers,
            ProductDiscontinuedEvents::PRODUCT_DISCONTINUED_PUBLISH
        );
        $productDiscontinuedEntityTransfers = $this->productDiscontinuedStorageRepository
            ->findProductDiscontinuedStorageEntitiesByIds(
                [$this->productDiscontinuedTransfer->getIdProductDiscontinued()]
            );

        // Assert
        $this->assertCount(1, $productDiscontinuedEntityTransfers);
    }

    /**
     * @return void
     */
    public function testProductDiscontinuedStorageEntityCanBeUnpublished()
    {
        $this->markTestSkipped('No availability to skip entity transfer sending to Queue');
        // Arrange
        $eventTransfers = [
            (new EventEntityTransfer())->setId($this->productDiscontinuedTransfer->getIdProductDiscontinued()),
        ];

        // Act
        $this->productDiscontinuedStorageListener->handleBulk(
            $eventTransfers,
            ProductDiscontinuedEvents::PRODUCT_DISCONTINUED_PUBLISH
        );
        $this->productDiscontinuedStorageListener->handleBulk(
            $eventTransfers,
            ProductDiscontinuedEvents::PRODUCT_DISCONTINUED_UNPUBLISH
        );
        $productDiscontinuedEntityTransfers = $this->productDiscontinuedStorageRepository
            ->findProductDiscontinuedStorageEntitiesByIds(
                [$this->productDiscontinuedTransfer->getIdProductDiscontinued()]
            );

        // Assert
        $this->assertCount(0, $productDiscontinuedEntityTransfers);
    }

    /**
     * @return void
     */
    public function testProductDiscontinuedStorageEntityPublish(): void
    {
        $this->markTestSkipped('No availability to skip entity transfer sending to Queue');

        // Arrange
        $eventTransfers = [
            (new EventEntityTransfer())->setId($this->productDiscontinuedTransfer->getIdProductDiscontinued()),
        ];

        // Act
        $productDiscontinuedStoragePublishListener = new ProductDiscontinuedStoragePublishListener();
        $productDiscontinuedStoragePublishListener->setFacade($this->tester->getFacade());

        $productDiscontinuedStoragePublishListener->handleBulk(
            $eventTransfers,
            ProductDiscontinuedEvents::PRODUCT_DISCONTINUED_PUBLISH
        );

        $productDiscontinuedEntityTransfers = $this->productDiscontinuedStorageRepository
            ->findProductDiscontinuedStorageEntitiesByIds(
                [$this->productDiscontinuedTransfer->getIdProductDiscontinued()]
            );

        // Assert
        $this->assertCount(1, $productDiscontinuedEntityTransfers);
    }

    /**
     * @return void
     */
    public function testProductDiscontinuedStorageEntityUnpublish(): void
    {
        $this->markTestSkipped('No availability to skip entity transfer sending to Queue');
        // Arrange
        $eventTransfers = [
            (new EventEntityTransfer())->setId($this->productDiscontinuedTransfer->getIdProductDiscontinued()),
        ];

        // Act
        $productDiscontinuedStorageUnpublishListener = new ProductDiscontinuedStorageUnpublishListener();
        $productDiscontinuedStorageUnpublishListener->setFacade($this->tester->getFacade());

        $productDiscontinuedStorageUnpublishListener->handleBulk(
            $eventTransfers,
            ProductDiscontinuedEvents::PRODUCT_DISCONTINUED_UNPUBLISH
        );
        $productDiscontinuedEntityTransfers = $this->productDiscontinuedStorageRepository
            ->findProductDiscontinuedStorageEntitiesByIds(
                [$this->productDiscontinuedTransfer->getIdProductDiscontinued()]
            );

        // Assert
        $this->assertCount(0, $productDiscontinuedEntityTransfers);
    }
}
