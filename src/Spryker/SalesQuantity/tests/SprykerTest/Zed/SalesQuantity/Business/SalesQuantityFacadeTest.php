<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\SalesQuantity\Business;

use ArrayObject;
use Codeception\Test\Unit;
use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\DiscountableItemTransfer;
use Generated\Shared\Transfer\DiscountableItemTransformerTransfer;
use Generated\Shared\Transfer\DiscountTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Orm\Zed\Product\Persistence\SpyProduct;
use Orm\Zed\Product\Persistence\SpyProductAbstract;
use Orm\Zed\Product\Persistence\SpyProductAbstractQuery;
use Orm\Zed\Product\Persistence\SpyProductQuery;
use Spryker\Zed\SalesQuantity\Business\SalesQuantityBusinessFactory;
use Spryker\Zed\SalesQuantity\SalesQuantityConfig;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group SalesQuantity
 * @group Business
 * @group Facade
 * @group SalesQuantityFacadeTest
 * Add your own group annotations below this line
 */
class SalesQuantityFacadeTest extends Unit
{
    protected const ABSTRACT_PRODUCT_SKU = 'ABSTRACT_PRODUCT_SKU';
    protected const CONCRETE_PRODUCT_SKU = 'CONCRETE_PRODUCT_SKU';
    protected const QUANTITY = 5;

    /**
     * @var \SprykerTest\Zed\SalesQuantity\SalesQuantityBusinessTester
     */
    protected $tester;

    /**
     * @var \PHPUnit\Framework\MockObject\MockObject|\Spryker\Zed\SalesQuantity\SalesQuantityConfig
     */
    protected $configMock;

    /**
     * @var \Spryker\Zed\SalesQuantity\Business\SalesQuantityFacadeInterface|\Spryker\Zed\Kernel\Business\AbstractFacade
     */
    protected $facade;

    /**
     * @return void
     */
    public function setUp()
    {
        parent::setUp();

        $this->configMock = $this->getMockBuilder(SalesQuantityConfig::class)->getMock();

        $this->facade = $this->tester->getFacade();

        $this->facade->setFactory(
            (new SalesQuantityBusinessFactory())
                ->setConfig($this->configMock)
        );
    }

    /**
     * @dataProvider transformNonSplittableItemShouldNotSplitItemsProvider
     *
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return void
     */
    public function testTransformNonSplittableItemShouldNotSplitItems(ItemTransfer $itemTransfer): void
    {
        $itemCollectionTransfer = $this->facade->transformNonSplittableItem($itemTransfer);

        $this->assertSame($itemCollectionTransfer->getItems()->count(), 1);

        foreach ($itemCollectionTransfer->getItems() as $dstItemTransfer) {
            $this->assertSame($dstItemTransfer->getQuantity(), $itemTransfer->getQuantity());
        }
    }

    /**
     * @return array
     */
    public function transformNonSplittableItemShouldNotSplitItemsProvider(): array
    {
        return [
            'int stock' => [$this->transformNonSplittableItemShouldNotSplitItemsData(static::QUANTITY)],
            'float stock' => [$this->transformNonSplittableItemShouldNotSplitItemsData(5.5)],
        ];
    }

    /**
     * @param int|float $quantity
     *
     * @return \Generated\Shared\Transfer\ItemTransfer
     */
    protected function transformNonSplittableItemShouldNotSplitItemsData($quantity): ItemTransfer
    {
        $itemTransfer = (new ItemTransfer())
            ->setQuantity($quantity);

        return $itemTransfer;
    }

    /**
     * @return void
     */
    public function testExpandItemsShouldPreSetBdValuesToItemTransfer(): void
    {
        $this->setData(true);
        $item = (new ItemTransfer())->setSku(static::CONCRETE_PRODUCT_SKU);
        $cartChangeTransfer = (new CartChangeTransfer())->setItems(new ArrayObject($item));

        $resultCartChangeTransfer = $this->facade->expandCartChangeWithIsQuantitySplittable($cartChangeTransfer);

        foreach ($resultCartChangeTransfer->getItems() as $itemTransfer) {
            $this->assertSame($itemTransfer->getIsQuantitySplittable(), true);
        }

        $this->setData(false);

        $resultCartChangeTransfer = $this->facade->expandCartChangeWithIsQuantitySplittable($cartChangeTransfer);

        foreach ($resultCartChangeTransfer->getItems() as $itemTransfer) {
            $this->assertSame($itemTransfer->getIsQuantitySplittable(), false);
        }
    }

    /**
     * @dataProvider transformDiscountableItemShouldBeUsedNonSplitTransformationProvider
     *
     * @param \Generated\Shared\Transfer\DiscountableItemTransformerTransfer $discountableItemTransformerTransfer
     * @param \Generated\Shared\Transfer\DiscountableItemTransfer $discountableItemTransfer
     *
     * @return void
     */
    public function testTransformDiscountableItemShouldBeUsedNonSplitTransformation(
        DiscountableItemTransformerTransfer $discountableItemTransformerTransfer,
        DiscountableItemTransfer $discountableItemTransfer
    ): void {
        $this->facade->transformNonSplittableDiscountableItem($discountableItemTransformerTransfer);

        $this->assertSame($discountableItemTransfer->getOriginalItemCalculatedDiscounts()->count(), 1);

        foreach ($discountableItemTransfer->getOriginalItemCalculatedDiscounts() as $resultedDiscountableItemTransfer) {
            $this->assertSame($resultedDiscountableItemTransfer->getUnitAmount(), 10);
            $this->assertSame($resultedDiscountableItemTransfer->getSumAmount(), (int)($discountableItemTransfer->getQuantity() * $discountableItemTransformerTransfer->getTotalDiscountAmount()));
            $this->assertSame($resultedDiscountableItemTransfer->getQuantity(), $discountableItemTransformerTransfer->getQuantity());
        }
    }

    /**
     * @return array
     */
    public function transformDiscountableItemShouldBeUsedNonSplitTransformationProvider(): array
    {
        return [
            'int stock' => $this->transformDiscountableItemShouldBeUsedNonSplitTransformationData(static::QUANTITY),
            'float stock' => $this->transformDiscountableItemShouldBeUsedNonSplitTransformationData(5.5),
        ];
    }

    /**
     * @param int|float $quantity
     *
     * @return array
     */
    protected function transformDiscountableItemShouldBeUsedNonSplitTransformationData($quantity): array
    {
        $discountableItemTransfer = $this->createDiscountableItemTransfer();
        $discountableItemTransfer->setQuantity($quantity);
        $discountableItemTransformerTransfer = $this->createDiscountableItemTransformerTransfer($discountableItemTransfer);
        $discountableItemTransformerTransfer->setQuantity($quantity);

        return [$discountableItemTransformerTransfer, $discountableItemTransfer];
    }

    /**
     * @see SalesQuantityConfig::findItemQuantityThreshold()
     *
     * @return void
     */
    public function testIsItemQuantitySplittableReturnsTrueForItemsWithBundleItemIdentifier()
    {
        // Assign
        $threshold = 5;
        $this->configMock->expects($this->any())->method('findItemQuantityThreshold')->willReturn($threshold);

        $expectedResult = true;

        $itemTransfer = new ItemTransfer();
        $itemTransfer->setIsQuantitySplittable(false);
        $itemTransfer->setBundleItemIdentifier('test-id');
        $itemTransfer->setQuantity($threshold);

        // Act
        $actualResult = $this->facade->isItemQuantitySplittable($itemTransfer);

        // Assert
        $this->assertSame($expectedResult, $actualResult);
    }

    /**
     * @see SalesQuantityConfig::findItemQuantityThreshold()
     *
     * @return void
     */
    public function testIsItemQuantitySplittableReturnsTrueForItemsWithRelatedBundleItemIdentifier()
    {
        // Assign
        $threshold = 5;
        $this->configMock->expects($this->any())->method('findItemQuantityThreshold')->willReturn($threshold);
        $expectedResult = true;

        $itemTransfer = new ItemTransfer();
        $itemTransfer->setIsQuantitySplittable(false);
        $itemTransfer->setRelatedBundleItemIdentifier('test-id');
        $itemTransfer->setQuantity($threshold);

        // Act
        $actualResult = $this->facade->isItemQuantitySplittable($itemTransfer);

        // Assert
        $this->assertSame($expectedResult, $actualResult);
    }

    /**
     * @see SalesQuantityConfig::findItemQuantityThreshold()
     *
     * @return void
     */
    public function testIsItemQuantitySplittableReturnsFalseForNonSplittableItems()
    {
        // Assign
        $threshold = null;
        $this->configMock->expects($this->any())->method('findItemQuantityThreshold')->willReturn($threshold);
        $expectedResult = false;

        $itemTransfer = new ItemTransfer();
        $itemTransfer->setIsQuantitySplittable(false);

        // Act
        $actualResult = $this->facade->isItemQuantitySplittable($itemTransfer);

        // Assert
        $this->assertSame($expectedResult, $actualResult);
    }

    /**
     * @see SalesQuantityConfig::findItemQuantityThreshold()
     *
     * @dataProvider thresholds
     *
     * @param bool $expectedResult
     * @param int $quantity
     * @param int|null $threshold
     *
     * @return void
     */
    public function testIsItemQuantitySplittableRespectsThreshold($expectedResult, $quantity, $threshold)
    {
        // Assign
        $this->configMock->expects($this->any())->method('findItemQuantityThreshold')->willReturn($threshold);

        $itemTransfer = new ItemTransfer();
        $itemTransfer->setQuantity($quantity);

        // Act
        $actualResult = $this->facade->isItemQuantitySplittable($itemTransfer);

        // Assert
        $this->assertSame($expectedResult, $actualResult);
    }

    /**
     * @return array
     */
    public function thresholds()
    {
        return [
            [true,  5, null],
            [true,  5, 6],
            [false, 5, 5],
            [false, 5, 4],
        ];
    }

    /**
     * @param \Generated\Shared\Transfer\DiscountableItemTransfer $discountableItemTransfer
     *
     * @return \Generated\Shared\Transfer\DiscountableItemTransformerTransfer
     */
    protected function createDiscountableItemTransformerTransfer(DiscountableItemTransfer $discountableItemTransfer)
    {
        $discountTransfer = (new DiscountTransfer())->setIdDiscount(1);
        $totalDiscountAmount = 10;
        $totalAmount = 100;

        $discountableItemTransformerTransfer = new DiscountableItemTransformerTransfer();
        $discountableItemTransformerTransfer->setDiscountableItem($discountableItemTransfer)
            ->setDiscount($discountTransfer)
            ->setTotalDiscountAmount($totalDiscountAmount)
            ->setTotalAmount($totalAmount)
            ->setQuantity(static::QUANTITY);

        return $discountableItemTransformerTransfer;
    }

    /**
     * @return \Generated\Shared\Transfer\DiscountableItemTransfer
     */
    protected function createDiscountableItemTransfer(): DiscountableItemTransfer
    {
        $discountableItemTransfer = new DiscountableItemTransfer();
        $discountableItemTransfer->setUnitPrice(100)
            ->setQuantity(static::QUANTITY);

        return $discountableItemTransfer;
    }

    /**
     * @param bool $isQuantitySplittable
     *
     * @return void
     */
    protected function setData(bool $isQuantitySplittable): void
    {
        $productAbstract = SpyProductAbstractQuery::create()
            ->filterBySku(static::ABSTRACT_PRODUCT_SKU)
            ->findOne();

        if ($productAbstract === null) {
            $productAbstract = new SpyProductAbstract();

            $productAbstract
                ->setAttributes('{}')
                ->setSku(static::ABSTRACT_PRODUCT_SKU);
        }

        $productAbstract->save();

        $product = SpyProductQuery::create()
            ->filterBySku(static::CONCRETE_PRODUCT_SKU)
            ->findOne();

        if ($product === null) {
            $product = new SpyProduct();
            $product->setAttributes('{}')
                ->setSku(static::CONCRETE_PRODUCT_SKU);
        }

        $product->setFkProductAbstract($productAbstract->getIdProductAbstract())
            ->setIsQuantitySplittable($isQuantitySplittable)
            ->save();
    }
}
