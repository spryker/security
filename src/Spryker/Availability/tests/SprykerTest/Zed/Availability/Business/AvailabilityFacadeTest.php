<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Availability\Business;

use Codeception\Test\Unit;
use Generated\Shared\DataBuilder\ProductConcreteAvailabilityRequestBuilder;
use Generated\Shared\DataBuilder\StoreBuilder;
use Generated\Shared\Transfer\CheckoutResponseTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\ProductConcreteAvailabilityRequestTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\StoreTransfer;
use Orm\Zed\Availability\Persistence\SpyAvailability;
use Orm\Zed\Availability\Persistence\SpyAvailabilityAbstract;
use Orm\Zed\Availability\Persistence\SpyAvailabilityQuery;
use Orm\Zed\Product\Persistence\SpyProduct;
use Orm\Zed\Product\Persistence\SpyProductAbstract;
use Orm\Zed\Stock\Persistence\SpyStockProduct;
use Orm\Zed\Stock\Persistence\SpyStockQuery;
use Spryker\Service\UtilQuantity\UtilQuantityConfig;
use Spryker\Service\UtilQuantity\UtilQuantityService;
use Spryker\Service\UtilQuantity\UtilQuantityServiceFactory;
use Spryker\Service\UtilQuantity\UtilQuantityServiceInterface;
use Spryker\Zed\Availability\AvailabilityDependencyProvider;
use Spryker\Zed\Availability\Dependency\Service\AvailabilityToUtilQuantityServiceBridge;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Availability
 * @group Business
 * @group Facade
 * @group AvailabilityFacadeTest
 * Add your own group annotations below this line
 */
class AvailabilityFacadeTest extends Unit
{
    public const ABSTRACT_SKU = '123_availability_test';
    public const CONCRETE_SKU = '123_availability_test-concrete';
    public const ID_STORE = 1;

    /**
     * @var \SprykerTest\Zed\Availability\AvailabilityBusinessTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function testIsProductSellableWhenNeverOutOfStockShouldReturnSuccess()
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['is_never_out_of_stock' => true]);

        $isProductSellable = $availabilityFacade->isProductSellable(self::CONCRETE_SKU, self::ID_STORE);

        $this->assertTrue($isProductSellable);
    }

    /**
     * @return void
     */
    public function testIsProductSellableWhenStockIsEmptyShouldReturnFailure()
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['quantity' => 0]);

        $isProductSellable = $availabilityFacade->isProductSellable(self::CONCRETE_SKU, self::ID_STORE);

        $this->assertFalse($isProductSellable);
    }

    /**
     * @return void
     */
    public function testIsProductSellableWhenStockFulfilledShouldReturnSuccess()
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['quantity' => 5]);

        $isProductSellable = $availabilityFacade->isProductSellable(self::CONCRETE_SKU, self::ID_STORE);

        $this->assertTrue($isProductSellable);
    }

    /**
     * @dataProvider calculateStockForProductShouldReturnPersistedStockProvider
     *
     * @param int|float $quantity
     *
     * @return void
     */
    public function testCalculateStockForProductShouldReturnPersistedStock($quantity): void
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['quantity' => $quantity]);

        $calculatedQuantity = $availabilityFacade->calculateStockForProduct(self::CONCRETE_SKU);

        $this->assertSame((float)$quantity, $calculatedQuantity);
    }

    /**
     * @return array
     */
    public function calculateStockForProductShouldReturnPersistedStockProvider(): array
    {
        return [
            'int stock' => [5],
            'float stock' => [5.5],
        ];
    }

    /**
     * @return void
     */
    public function testCheckAvailabilityPrecoditionShouldNotWriteErrorsWhenAvailabilityIsSatisfied()
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['quantity' => 5]);

        $quoteTransfer = $this->createQuoteTransfer();

        $checkoutResponseTransfer = new CheckoutResponseTransfer();

        $availabilityFacade->checkoutAvailabilityPreCondition($quoteTransfer, $checkoutResponseTransfer);

        $this->assertEmpty($checkoutResponseTransfer->getErrors());
    }

    /**
     * @return void
     */
    public function testCheckAvailabilityPrecoditionShouldWriteErrorWhenAvailabilityIsNotSatisfied()
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['quantity' => 0]);

        $quoteTransfer = $this->createQuoteTransfer();

        $checkoutResponseTransfer = new CheckoutResponseTransfer();

        $availabilityFacade->checkoutAvailabilityPreCondition($quoteTransfer, $checkoutResponseTransfer);

        $this->assertNotEmpty($checkoutResponseTransfer->getErrors());
    }

    /**
     * @dataProvider updateAvailabilityShouldStoreNewQuantityProvider
     *
     * @param int|float $quantity
     *
     * @return void
     */
    public function testUpdateAvailabilityShouldStoreNewQuantity($quantity): void
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $stockProductEntity = $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['quantity' => 5]);

        $stockProductEntity->setQuantity($quantity);
        $stockProductEntity->save();

        $availabilityFacade->updateAvailability(self::CONCRETE_SKU);

        $availabilityEntity = SpyAvailabilityQuery::create()->findOneBySku(self::CONCRETE_SKU);

        $this->assertSame((float)$quantity, $availabilityEntity->getQuantity());
    }

    /**
     * @return array
     */
    public function updateAvailabilityShouldStoreNewQuantityProvider(): array
    {
        return [
            'int stock' => [50],
            'float stock' => [55.0],
        ];
    }

    /**
     * @dataProvider updateAvailabilityWhenItsEmptyShouldStoreNewQuantityProvider
     *
     * @param int|float $quantity
     *
     * @return void
     */
    public function testUpdateAvailabilityWhenItsEmptyShouldStoreNewQuantity($quantity): void
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['quantity' => $quantity]);

        $this->createProductAvailability();

        $availabilityFacade->updateAvailability(self::CONCRETE_SKU);

        $availabilityEntity = SpyAvailabilityQuery::create()->findOneBySku(self::CONCRETE_SKU);

        $this->assertSame((float)$quantity, $availabilityEntity->getQuantity());
    }

    /**
     * @return array
     */
    public function updateAvailabilityWhenItsEmptyShouldStoreNewQuantityProvider(): array
    {
        return [
            'int stock' => [50],
            'float stock' => [50.5],
        ];
    }

    /**
     * @dataProvider updateAvailabilityWhenSetToEmptyShouldStoreEmptyQuantityProvider
     *
     * @param int|float $quantity
     *
     * @return void
     */
    public function testUpdateAvailabilityWhenSetToEmptyShouldStoreEmptyQuantity($quantity): void
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['quantity' => 0]);

        $availabilityEntity = $this->createProductAvailability($quantity);

        $this->assertSame((float)$quantity, $availabilityEntity->getQuantity());

        $availabilityFacade->updateAvailability(self::CONCRETE_SKU);

        $availabilityEntity = SpyAvailabilityQuery::create()
            ->findOneBySku(self::CONCRETE_SKU);

        $this->assertSame(0.0, $availabilityEntity->getQuantity());
    }

    /**
     * @return array
     */
    public function updateAvailabilityWhenSetToEmptyShouldStoreEmptyQuantityProvider(): array
    {
        return [
            'int stock' => [5],
            'float stock' => [5.5],
        ];
    }

    /**
     * @dataProvider saveProductAvailabilityForStoreShouldStoreAvailabilityProvider
     *
     * @param int|float $quantity
     *
     * @return void
     */
    public function testSaveProductAvailabilityForStoreShouldStoreAvailability($quantity)
    {
        $availabilityFacade = $this->createAvailabilityFacade();

        $storeTransfer = (new StoreBuilder([StoreTransfer::NAME => 'DE', StoreTransfer::ID_STORE => self::ID_STORE]))->build();

        $this->createProductWithStock(self::ABSTRACT_SKU, self::CONCRETE_SKU, ['quantity' => 0]);

        $availabilityFacade->saveProductAvailabilityForStore(self::CONCRETE_SKU, $quantity, $storeTransfer);

        $productConcreteAvailabilityRequestTransfer = (new ProductConcreteAvailabilityRequestBuilder([
            ProductConcreteAvailabilityRequestTransfer::SKU => self::CONCRETE_SKU,
        ]))->build();

        $productConcreteAvailabilityTransfer = $availabilityFacade->findProductConcreteAvailability($productConcreteAvailabilityRequestTransfer);

        $this->assertSame((float)$quantity, $productConcreteAvailabilityTransfer->getAvailability());
    }

    /**
     * @return array
     */
    public function saveProductAvailabilityForStoreShouldStoreAvailabilityProvider(): array
    {
        return [
            'int stock' => [2],
            'float stock' => [2.5],
        ];
    }

    /**
     * @return \Spryker\Service\UtilQuantity\UtilQuantityServiceInterface
     */
    protected function createUtilQuantityService(): UtilQuantityServiceInterface
    {
        $utilQuantityConfigMock = $this->getMockBuilder(UtilQuantityConfig::class)->setMethods([
            'getQuantityRoundingPrecision',
        ])->getMock();
        $utilQuantityConfigMock->method('getQuantityRoundingPrecision')->willReturn(2);
        $utilQuantityFactory = new UtilQuantityServiceFactory();
        $utilQuantityFactory->setConfig($utilQuantityConfigMock);
        $utilQuantityService = new UtilQuantityService();
        $utilQuantityService->setFactory($utilQuantityFactory);

        return $utilQuantityService;
    }

    /**
     * @return \Spryker\Zed\Availability\Business\AvailabilityFacade
     */
    protected function createAvailabilityFacade()
    {
        $utilQuantityService = new AvailabilityToUtilQuantityServiceBridge($this->createUtilQuantityService());
        $this->tester->setDependency(AvailabilityDependencyProvider::SERVICE_UTIL_QUANTITY, $utilQuantityService);

        return $this->tester->getFacade();
    }

    /**
     * @param string $abstractSku
     * @param string $concreteSku
     * @param array $stockData
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockProduct
     */
    protected function createProductWithStock($abstractSku, $concreteSku, array $stockData)
    {
        $productAbstractEntity = new SpyProductAbstract();
        $productAbstractEntity->setSku($abstractSku);
        $productAbstractEntity->setAttributes('');
        $productAbstractEntity->save();

        $productEntity = new SpyProduct();
        $productEntity->setSku($concreteSku);
        $productEntity->setAttributes('');
        $productEntity->setIsActive(true);
        $productEntity->setFkProductAbstract($productAbstractEntity->getIdProductAbstract());
        $productEntity->save();

        $stockEntity = (new SpyStockQuery())
            ->filterByName('Warehouse1')
            ->findOneOrCreate();

        $stockEntity->save();

        $stockProductEntity = new SpyStockProduct();
        $stockProductEntity->fromArray($stockData);
        $stockProductEntity->setFkProduct($productEntity->getIdProduct());
        $stockProductEntity->setFkStock($stockEntity->getIdStock());
        $stockProductEntity->save();

        return $stockProductEntity;
    }

    /**
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function createQuoteTransfer()
    {
        $quoteTransfer = new QuoteTransfer();
        $quoteTransfer->setStore((new StoreTransfer())->setName('DE'));
        $itemTransfer = new ItemTransfer();
        $itemTransfer->setSku(self::CONCRETE_SKU);
        $itemTransfer->setQuantity(self::ID_STORE);
        $quoteTransfer->addItem($itemTransfer);

        return $quoteTransfer;
    }

    /**
     * @param int $quantity
     *
     * @return \Orm\Zed\Availability\Persistence\SpyAvailability
     */
    protected function createProductAvailability($quantity = 0)
    {
        $availabilityAbstractEntity = new SpyAvailabilityAbstract();
        $availabilityAbstractEntity->setAbstractSku(self::ABSTRACT_SKU);
        $availabilityAbstractEntity->setQuantity($quantity);
        $availabilityAbstractEntity->setFkStore(static::ID_STORE);
        $availabilityAbstractEntity->save();

        $availabilityEntity = new SpyAvailability();
        $availabilityEntity->setFkAvailabilityAbstract($availabilityAbstractEntity->getIdAvailabilityAbstract());
        $availabilityEntity->setQuantity($quantity);
        $availabilityEntity->setFkStore(static::ID_STORE);
        $availabilityEntity->setSku(self::CONCRETE_SKU);
        $availabilityEntity->save();

        return $availabilityEntity;
    }
}
