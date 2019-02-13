<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Availability\Business\Model;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\StoreTransfer;
use Orm\Zed\Availability\Persistence\SpyAvailability;
use Orm\Zed\Availability\Persistence\SpyAvailabilityAbstract;
use Orm\Zed\Availability\Persistence\SpyAvailabilityAbstractQuery;
use Orm\Zed\Availability\Persistence\SpyAvailabilityQuery;
use Spryker\Zed\Availability\Business\Model\AvailabilityHandler;
use Spryker\Zed\Availability\Business\Model\SellableInterface;
use Spryker\Zed\Availability\Dependency\Facade\AvailabilityToEventFacadeInterface;
use Spryker\Zed\Availability\Dependency\Facade\AvailabilityToOmsInterface;
use Spryker\Zed\Availability\Dependency\Facade\AvailabilityToProductInterface;
use Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStockInterface;
use Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStoreFacadeInterface;
use Spryker\Zed\Availability\Dependency\Facade\AvailabilityToTouchInterface;
use Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Availability
 * @group Business
 * @group Model
 * @group AvailabilityHandlerTest
 * Add your own group annotations below this line
 */
class AvailabilityHandlerTest extends Unit
{
    public const PRODUCT_SKU = 'sku-123-321';

    /**
     * @return void
     */
    public function testUpdateAvailabilityShouldTouchWhenStockUpdated()
    {
        $availabilityContainerMock = $this->createAvailabilityQueryContainerMock(0);

        $sellableMock = $this->createSellableMock();
        $sellableMock->method('calculateStockForProductWithStore')->willReturn(15);

        $touchFacadeMock = $this->createTouchFacadeMock();
        $touchFacadeMock->expects($this->once())->method('touchActive');

        $availabilityHandler = $this->createAvailabilityHandler(
            $sellableMock,
            null,
            $touchFacadeMock,
            $availabilityContainerMock
        );

        $availabilityHandler->updateAvailability(self::PRODUCT_SKU);
    }

    /**
     * @return void
     */
    public function testUpdateAvailabilityShouldTouchAndUpdateNewStock()
    {
        $availabilityContainerMock = $this->createAvailabilityQueryContainerMock(5);

        $sellableMock = $this->createSellableMock();
        $sellableMock->method('calculateStockForProductWithStore')->willReturn(0);

        $touchFacadeMock = $this->createTouchFacadeMock();
        $touchFacadeMock->expects($this->once())->method('touchActive');

        $availabilityHandler = $this->createAvailabilityHandler(
            $sellableMock,
            null,
            $touchFacadeMock,
            $availabilityContainerMock
        );

        $availabilityHandler->updateAvailability(self::PRODUCT_SKU);
    }

    /**
     * @param \Spryker\Zed\Availability\Business\Model\SellableInterface|null $sellable
     * @param \Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStockInterface|null $stockFacade
     * @param \Spryker\Zed\Availability\Dependency\Facade\AvailabilityToTouchInterface|null $touchFacade
     * @param \Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface|null $availabilityQueryContainer
     * @param \Spryker\Zed\Availability\Dependency\Facade\AvailabilityToProductInterface|null $availabilityToProductFacade
     * @param \Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStoreFacadeInterface|null $availabilityToStoreFacade
     * @param \Spryker\Zed\Availability\Dependency\Facade\AvailabilityToEventFacadeInterface|null $availabilityToEventFacade
     *
     * @return \Spryker\Zed\Availability\Business\Model\AvailabilityHandler
     */
    protected function createAvailabilityHandler(
        ?SellableInterface $sellable = null,
        ?AvailabilityToStockInterface $stockFacade = null,
        ?AvailabilityToTouchInterface $touchFacade = null,
        ?AvailabilityQueryContainerInterface $availabilityQueryContainer = null,
        ?AvailabilityToProductInterface $availabilityToProductFacade = null,
        ?AvailabilityToStoreFacadeInterface $availabilityToStoreFacade = null,
        ?AvailabilityToEventFacadeInterface $availabilityToEventFacade = null
    ) {

        if ($sellable === null) {
            $sellable = $this->createSellableMock();
        }

        if ($stockFacade === null) {
            $stockFacade = $this->createStockFacadeMock();
        }

        if ($touchFacade === null) {
            $touchFacade = $this->createTouchFacadeMock();
        }

        if ($availabilityQueryContainer === null) {
            $availabilityQueryContainer = $this->createAvailabilityQueryContainerMock();
        }

        if ($availabilityToProductFacade === null) {
            $availabilityToProductFacade = $this->createAvailabilityToProductFacade();
        }

        if ($availabilityToStoreFacade === null) {
            $availabilityToStoreFacade = $this->createStoreFacade();
            $availabilityToStoreFacade->method('getCurrentStore')
                ->willReturn($this->createStoreTransfer());
        }

        if ($availabilityToEventFacade === null) {
            $availabilityToEventFacade = $this->createAvailabilityToEventFacade();
        }

        return new AvailabilityHandler(
            $sellable,
            $stockFacade,
            $touchFacade,
            $availabilityQueryContainer,
            $availabilityToProductFacade,
            $availabilityToStoreFacade,
            $availabilityToEventFacade
        );
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStockInterface
     */
    protected function createStockFacadeMock()
    {
        return $this->getMockBuilder(AvailabilityToStockInterface::class)
            ->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Zed\Availability\Dependency\Facade\AvailabilityToOmsInterface
     */
    protected function createOmsFacadeMock()
    {
        return $this->getMockBuilder(AvailabilityToOmsInterface::class)
            ->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Zed\Availability\Dependency\Facade\AvailabilityToTouchInterface
     */
    protected function createTouchFacadeMock()
    {
        return $this->getMockBuilder(AvailabilityToTouchInterface::class)
            ->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Zed\Availability\Business\Model\SellableInterface
     */
    protected function createSellableMock()
    {
        return $this->getMockBuilder(SellableInterface::class)
            ->getMock();
    }

    /**
     * @param int $availabilityQuantity
     *
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Zed\Availability\Persistence\AvailabilityQueryContainerInterface
     */
    protected function createAvailabilityQueryContainerMock($availabilityQuantity = 0)
    {
        $availabilityContainerMock = $this->getMockBuilder(AvailabilityQueryContainerInterface::class)
            ->getMock();

        $availabilityQueryMock = $this->getMockBuilder(SpyAvailabilityQuery::class)->getMock();
        $availabilityAbstractQueryMock = $this->getMockBuilder(SpyAvailabilityAbstractQuery::class)->getMock();

        $availabilityEntity = $this->createAvailabilityEntityMock();
        $availabilityEntity->method('getQuantity')
            ->willReturn($availabilityQuantity);

        $availabilityQueryMock->method('findOne')
            ->willReturn($availabilityEntity);

        $availabilityEntity = $this->createAvailabilityEntityMock();
        $availabilityQueryMock->method('findOneOrCreate')
            ->willReturn($availabilityEntity);

        $availabilityEntity = $this->createAvailabilityEntityMock();
        $availabilityQueryMock->method('findOneOrCreate')
            ->willReturn($availabilityEntity);

        $availabilityContainerMock->method('queryAvailabilityBySkuAndIdStore')
            ->willReturn($availabilityQueryMock);

        $availabilityAbstractEntityMock = $this->createAvailabilityAbstractEntityMock();
        $availabilityAbstractQueryMock->method('findOne')->willReturn($availabilityAbstractEntityMock);

        $availabilityContainerMock->method('queryAvailabilityAbstractByIdAvailabilityAbstract')
            ->willReturn($availabilityAbstractQueryMock);

        $availabilityContainerMock->method('querySumQuantityOfAvailabilityAbstract')
            ->willReturn($availabilityEntity);

        return $availabilityContainerMock;
    }

    /**
     * @return \Generated\Shared\Transfer\StoreTransfer
     */
    protected function createStoreTransfer()
    {
        return new StoreTransfer();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Orm\Zed\Availability\Persistence\SpyAvailability
     */
    protected function createAvailabilityEntityMock()
    {
        return $this->getMockBuilder(SpyAvailability::class)
            ->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Orm\Zed\Availability\Persistence\SpyAvailabilityAbstract
     */
    protected function createAvailabilityAbstractEntityMock()
    {
        return $this->getMockBuilder(SpyAvailabilityAbstract::class)
            ->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Zed\Availability\Dependency\Facade\AvailabilityToProductInterface
     */
    protected function createAvailabilityToProductFacade()
    {
        return $this->getMockBuilder(AvailabilityToProductInterface::class)
            ->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Zed\Availability\Dependency\Facade\AvailabilityToStoreFacadeInterface
     */
    protected function createStoreFacade()
    {
        return $this->getMockBuilder(AvailabilityToStoreFacadeInterface::class)
            ->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\Spryker\Zed\Availability\Dependency\Facade\AvailabilityToEventFacadeInterface
     */
    protected function createAvailabilityToEventFacade()
    {
        return $this->getMockBuilder(AvailabilityToEventFacadeInterface::class)
            ->getMock();
    }
}
