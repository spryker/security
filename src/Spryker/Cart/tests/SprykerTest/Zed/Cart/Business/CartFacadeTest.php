<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Cart\Business;

use Codeception\Test\Unit;
use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Orm\Zed\Price\Persistence\SpyPriceProductQuery;
use Orm\Zed\Price\Persistence\SpyPriceTypeQuery;
use Orm\Zed\Product\Persistence\SpyProductAbstractQuery;
use Orm\Zed\Product\Persistence\SpyProductQuery;
use Spryker\Zed\Cart\Business\CartFacade;
use Spryker\Zed\Cart\CartDependencyProvider;
use Spryker\Zed\Kernel\Container;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Cart
 * @group Business
 * @group Facade
 * @group CartFacadeTest
 * Add your own group annotations below this line
 */
class CartFacadeTest extends Unit
{
    const PRICE_TYPE_DEFAULT = 'DEFAULT';
    const DUMMY_1_SKU_ABSTRACT_PRODUCT = 'ABSTRACT1';
    const DUMMY_1_SKU_CONCRETE_PRODUCT = 'CONCRETE1';
    const DUMMY_1_PRICE = 99;
    const DUMMY_2_SKU_ABSTRACT_PRODUCT = 'ABSTRACT2';
    const DUMMY_2_SKU_CONCRETE_PRODUCT = 'CONCRETE2';
    const DUMMY_2_PRICE = 100;

    /**
     * @var \Spryker\Zed\Cart\Business\CartFacadeInterface
     */
    private $cartFacade;

    /**
     * @return void
     */
    public function setUp()
    {
        parent::setUp();

        $container = new Container();

        $dependencyProvider = new CartDependencyProvider();
        $dependencyProvider->provideBusinessLayerDependencies($container);
        $dependencyProvider->provideCommunicationLayerDependencies($container);
        $dependencyProvider->providePersistenceLayerDependencies($container);

        $this->cartFacade = new CartFacade();

        $this->setTestData();
    }

    /**
     * @return void
     */
    public function testAddToCart()
    {
        $this->markTestSkipped('Tried to retrieve a concrete product with sku CONCRETE2, but it does not exist');
        $quoteTransfer = new QuoteTransfer();
        $cartItem = new ItemTransfer();
        $cartItem->setSku(self::DUMMY_1_SKU_CONCRETE_PRODUCT);
        $cartItem->setQuantity(3);
        $cartItem->setUnitGrossPrice(1);

        $quoteTransfer->addItem($cartItem);

        $newItem = new ItemTransfer();
        $newItem->setSku(self::DUMMY_2_SKU_CONCRETE_PRODUCT);
        $newItem->setQuantity(1);
        $newItem->setUnitGrossPrice(1);

        $cartChange = new CartChangeTransfer();
        $cartChange->setQuote($quoteTransfer);
        $cartChange->addItem($newItem);

        $changedCart = $this->cartFacade->addToCart($cartChange);

        $this->assertCount(2, $changedCart->getItems());

        /** @var \Generated\Shared\Transfer\ItemTransfer $item */
        foreach ($quoteTransfer->getItems() as $item) {
            if ($item->getSku() === $cartItem->getSku()) {
                $this->assertEquals($cartItem->getQuantity(), $item->getQuantity());
            } elseif ($newItem->getSku() === $item->getSku()) {
                $this->assertEquals($newItem->getQuantity(), $item->getQuantity());
            } else {
                $this->fail('Cart has a unknown item inside');
            }
        }
    }

    /**
     * @return void
     */
    public function testIncreaseCartQuantity()
    {
        $this->markTestSkipped('Tried to retrieve a concrete product with sku CONCRETE1, but it does not exist');
        $quoteTransfer = new QuoteTransfer();
        $cartItem = new ItemTransfer();
        $cartItem->setSku(self::DUMMY_1_SKU_CONCRETE_PRODUCT);
        $cartItem->setQuantity(3);
        $cartItem->setUnitGrossPrice(1);

        $quoteTransfer->addItem($cartItem);

        $newItem = new ItemTransfer();
        $newItem->setId(self::DUMMY_1_SKU_CONCRETE_PRODUCT);
        $newItem->setSku(self::DUMMY_1_SKU_CONCRETE_PRODUCT);
        $newItem->setQuantity(1);
        $newItem->setUnitGrossPrice(1);

        $cartChange = new CartChangeTransfer();
        $cartChange->setQuote($quoteTransfer);
        $cartChange->addItem($newItem);

        $changedCart = $this->cartFacade->increaseQuantity($cartChange);
        $cartItems = $changedCart->getItems();
        $this->assertCount(2, $cartItems);

        /** @var \Generated\Shared\Transfer\ItemTransfer $changedItem */
        $changedItem = $cartItems[1];
        $this->assertEquals(3, $changedItem->getQuantity());

        $changedItem = $cartItems[2];
        $this->assertEquals(1, $changedItem->getQuantity());
    }

    /**
     * @return void
     */
    public function testRemoveFromCart()
    {
        $this->markTestSkipped('Tried to retrieve a concrete product with sku CONCRETE2, but it does not exist');
        $quoteTransfer = new QuoteTransfer();
        $cartItem = new ItemTransfer();
        $cartItem->setId(self::DUMMY_2_SKU_CONCRETE_PRODUCT);
        $cartItem->setSku(self::DUMMY_2_SKU_CONCRETE_PRODUCT);
        $cartItem->setQuantity(1);
        $cartItem->setUnitGrossPrice(1);

        $quoteTransfer->addItem($cartItem);

        $newItem = new ItemTransfer();
        $newItem->setId(self::DUMMY_2_SKU_CONCRETE_PRODUCT);
        $newItem->setSku(self::DUMMY_2_SKU_CONCRETE_PRODUCT);
        $newItem->setQuantity(1);
        $newItem->setUnitGrossPrice(1);

        $cartChange = new CartChangeTransfer();
        $cartChange->setQuote($quoteTransfer);
        $cartChange->addItem($newItem);

        $changedCart = $this->cartFacade->removeFromCart($cartChange);

        $this->assertCount(0, $changedCart->getItems());
    }

    /**
     * @return void
     */
    public function testDecreaseCartItem()
    {
        $this->markTestSkipped('Tried to retrieve a concrete product with sku CONCRETE1, but it does not exist');
        $quoteTransfer = new QuoteTransfer();
        $cartItem = new ItemTransfer();
        $cartItem->setSku(self::DUMMY_1_SKU_CONCRETE_PRODUCT);
        $cartItem->setQuantity(3);
        $cartItem->setUnitGrossPrice(1);

        $quoteTransfer->addItem($cartItem);

        $newItem = new ItemTransfer();
        $newItem->setSku(self::DUMMY_1_SKU_CONCRETE_PRODUCT);
        $newItem->setQuantity(1);
        $newItem->setUnitGrossPrice(1);

        $cartChange = new CartChangeTransfer();
        $cartChange->setQuote($quoteTransfer);
        $cartChange->addItem($newItem);

        $changedCart = $this->cartFacade->decreaseQuantity($cartChange);
        $cartItems = $changedCart->getItems();
        $this->assertCount(1, $cartItems);
        /** @var \Generated\Shared\Transfer\ItemTransfer $changedItem */
        $changedItem = $cartItems[0];
        $this->assertEquals(2, $changedItem->getQuantity());
    }

    /**
     * @return void
     */
    protected function setTestData()
    {
        $defaultPriceType = SpyPriceTypeQuery::create()->filterByName(self::PRICE_TYPE_DEFAULT)->findOneOrCreate();
        $defaultPriceType->setName(self::PRICE_TYPE_DEFAULT)->save();

        $abstractProduct1 = SpyProductAbstractQuery::create()
            ->filterBySku(self::DUMMY_1_SKU_ABSTRACT_PRODUCT)
            ->findOneOrCreate();

        $abstractProduct1->setSku(self::DUMMY_1_SKU_ABSTRACT_PRODUCT)
            ->setAttributes('{}')
            ->save();

        $concreteProduct1 = SpyProductQuery::create()
            ->filterBySku(self::DUMMY_1_SKU_CONCRETE_PRODUCT)
            ->findOneOrCreate();

        $concreteProduct1
            ->setSku(self::DUMMY_1_SKU_CONCRETE_PRODUCT)
            ->setSpyProductAbstract($abstractProduct1)
            ->setAttributes('{}')
            ->save();

        $abstractProduct2 = SpyProductAbstractQuery::create()
            ->filterBySku(self::DUMMY_2_SKU_ABSTRACT_PRODUCT)
            ->findOneOrCreate();

        $abstractProduct2
            ->setSku(self::DUMMY_2_SKU_ABSTRACT_PRODUCT)
            ->setAttributes('{}')
            ->save();

        $concreteProduct2 = SpyProductQuery::create()
            ->filterBySku(self::DUMMY_2_SKU_CONCRETE_PRODUCT)
            ->findOneOrCreate();

        $concreteProduct2
            ->setSku(self::DUMMY_2_SKU_CONCRETE_PRODUCT)
            ->setSpyProductAbstract($abstractProduct2)
            ->setAttributes('{}')
            ->save();

        SpyPriceProductQuery::create()
            ->filterByProduct($concreteProduct1)
            ->filterBySpyProductAbstract($abstractProduct1)
            ->filterByPriceType($defaultPriceType)
            ->findOneOrCreate()
            ->setPrice(100)
            ->save();

        SpyPriceProductQuery::create()
            ->filterByProduct($concreteProduct2)
            ->filterBySpyProductAbstract($abstractProduct2)
            ->filterByPriceType($defaultPriceType)
            ->findOneOrCreate()
            ->setPrice(100)
            ->save();
    }
}
