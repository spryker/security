<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Product\Business;

use Generated\Shared\Transfer\ProductConcreteTransfer;
use Orm\Zed\Touch\Persistence\Map\SpyTouchTableMap;
use Spryker\Shared\Product\ProductConfig;
use Spryker\Zed\Product\Business\Exception\MissingProductException;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Product
 * @group Business
 * @group ConcreteManagementTest
 * Add your own group annotations below this line
 */
class ConcreteManagementTest extends FacadeTestAbstract
{
    /**
     * @return void
     */
    protected function a222setupDefaultProducts()
    {
        $idProductAbstract = $this->productAbstractManager->createProductAbstract($this->productAbstractTransfer);
        $this->productConcreteTransfer->setFkProductAbstract($idProductAbstract);

        $idProductConcrete = $this->productConcreteManager->createProductConcrete($this->productConcreteTransfer);
        $this->productConcreteTransfer->setIdProductConcrete($idProductConcrete);
    }

    /**
     * @return void
     */
    public function testCreateProductConcreteShouldCreateProductConcrete()
    {
        $idProductAbstract = $this->productAbstractManager->createProductAbstract($this->productAbstractTransfer);
        $this->productConcreteTransfer->setFkProductAbstract($idProductAbstract);

        $idProductConcrete = $this->productFacade->createProductConcrete($this->productConcreteTransfer);

        $this->productConcreteTransfer->setIdProductConcrete($idProductConcrete);
        $this->assertTrue($this->productConcreteTransfer->getIdProductConcrete() > 0);
        $this->assertCreateProductConcrete($this->productConcreteTransfer);
    }

    /**
     * @return void
     */
    public function testSaveProductAbstractShouldUpdateProductAbstract()
    {
        $this->setupDefaultProducts();

        foreach ($this->productConcreteTransfer->getLocalizedAttributes() as $localizedAttribute) {
            $localizedAttribute->setName(
                self::UPDATED_PRODUCT_ABSTRACT_NAME[$localizedAttribute->getLocale()->getLocaleName()]
            );
        }

        $idProductConcrete = $this->productFacade->saveProductConcrete($this->productConcreteTransfer);

        $this->assertEquals($this->productConcreteTransfer->getIdProductConcrete(), $idProductConcrete);
        $this->assertSaveProductConcrete($this->productConcreteTransfer);
    }

    /**
     * @return void
     */
    public function testHasProductConcreteShouldReturnTrue()
    {
        $this->setupDefaultProducts();

        $exists = $this->productFacade->hasProductConcrete($this->productConcreteTransfer->getSku());
        $this->assertTrue($exists);
    }

    /**
     * @return void
     */
    public function testHasProductConcreteShouldReturnFalse()
    {
        $exists = $this->productFacade->hasProductConcrete('INVALIDSKU');
        $this->assertFalse($exists);
    }

    /**
     * @return void
     */
    public function testTouchProductConcreteShouldAlsoTouchItsAbstract()
    {
        $this->createNewProductAndAssertNoTouchExists();

        $this->productFacade->touchProductConcrete($this->productConcreteTransfer->getIdProductConcrete());

        $this->assertTouchEntry($this->productConcreteTransfer->getIdProductConcrete(), ProductConfig::RESOURCE_TYPE_PRODUCT_CONCRETE, SpyTouchTableMap::COL_ITEM_EVENT_ACTIVE);
        $this->assertTouchEntry($this->productConcreteTransfer->getFkProductAbstract(), ProductConfig::RESOURCE_TYPE_PRODUCT_ABSTRACT, SpyTouchTableMap::COL_ITEM_EVENT_ACTIVE);
        $this->assertTouchEntry($this->productConcreteTransfer->getFkProductAbstract(), ProductConfig::RESOURCE_TYPE_ATTRIBUTE_MAP, SpyTouchTableMap::COL_ITEM_EVENT_ACTIVE);
    }

    /**
     * @return void
     */
    public function testTouchProductActiveShouldTouchActiveLogic()
    {
        $this->createNewProductAndAssertNoTouchExists();

        $this->productFacade->touchProductConcreteActive($this->productAbstractTransfer->getIdProductAbstract());

        $this->assertTouchEntry(
            $this->productAbstractTransfer->getIdProductAbstract(),
            ProductConfig::RESOURCE_TYPE_PRODUCT_CONCRETE,
            SpyTouchTableMap::COL_ITEM_EVENT_ACTIVE
        );
    }

    /**
     * @return void
     */
    public function testTouchProductInactiveShouldTouchInactiveLogic()
    {
        $this->createNewProductAndAssertNoTouchExists();

        $this->productFacade->touchProductConcreteActive($this->productAbstractTransfer->getIdProductAbstract());
        $this->assertTouchEntry(
            $this->productAbstractTransfer->getIdProductAbstract(),
            ProductConfig::RESOURCE_TYPE_PRODUCT_CONCRETE,
            SpyTouchTableMap::COL_ITEM_EVENT_ACTIVE
        );

        $this->productFacade->touchProductConcreteInactive($this->productAbstractTransfer->getIdProductAbstract());
        $this->assertTouchEntry(
            $this->productAbstractTransfer->getIdProductAbstract(),
            ProductConfig::RESOURCE_TYPE_PRODUCT_CONCRETE,
            SpyTouchTableMap::COL_ITEM_EVENT_INACTIVE
        );
    }

    /**
     * @return void
     */
    public function testTouchProductDeletedShouldTouchDeletedLogic()
    {
        $this->createNewProductAndAssertNoTouchExists();

        $this->productFacade->touchProductConcreteDelete($this->productAbstractTransfer->getIdProductAbstract());

        $this->assertTouchEntry(
            $this->productAbstractTransfer->getIdProductAbstract(),
            ProductConfig::RESOURCE_TYPE_PRODUCT_CONCRETE,
            SpyTouchTableMap::COL_ITEM_EVENT_DELETED
        );
    }

    /**
     * @return void
     */
    public function testGetProductConcreteByIdShouldReturnConcreteTransfer()
    {
        $this->setupDefaultProducts();

        $productConcreteTransfer = $this->productFacade->findProductConcreteById(
            $this->productConcreteTransfer->getIdProductConcrete()
        );

        $this->assertCreateProductConcrete($productConcreteTransfer);
        $this->assertInstanceOf(ProductConcreteTransfer::class, $productConcreteTransfer);
    }

    /**
     * @return void
     */
    public function testGetProductConcreteByIdShouldReturnNull()
    {
        $productConcreteTransfer = $this->productFacade->findProductConcreteById(101001);

        $this->assertNull($productConcreteTransfer);
    }

    /**
     * @return void
     */
    public function testGetProductConcreteIdBySkuShouldReturnId()
    {
        $this->setupDefaultProducts();

        $id = $this->productFacade->findProductConcreteIdBySku($this->productConcreteTransfer->getSku());

        $this->assertEquals($this->productConcreteTransfer->getIdProductConcrete(), $id);
    }

    /**
     * @return void
     */
    public function testGetProductConcreteIdBySkuShouldReturnNull()
    {
        $id = $this->productFacade->findProductConcreteIdBySku('INVALIDSKU');

        $this->assertNull($id);
    }

    /**
     * @return void
     */
    public function testGetProductConcreteShouldReturnConcreteTransfer()
    {
        $this->setupDefaultProducts();

        $productConcrete = $this->productFacade->getProductConcrete($this->productConcreteTransfer->getSku());

        $this->assertInstanceOf(ProductConcreteTransfer::class, $productConcrete);
    }

    /**
     * @return void
     */
    public function testGetProductConcreteShouldThrowException()
    {
        $this->expectException(MissingProductException::class);

        $productConcrete = $this->productFacade->getProductConcrete('INVALIDSKU');
    }

    /**
     * @return void
     */
    public function testGetConcreteProductsByAbstractProductIdShouldReturnConcreteCollection()
    {
        $this->setupDefaultProducts();

        $productConcreteCollection = $this->productFacade->getConcreteProductsByAbstractProductId(
            $this->productAbstractTransfer->getIdProductAbstract()
        );

        foreach ($productConcreteCollection as $productConcrete) {
            $this->assertInstanceOf(ProductConcreteTransfer::class, $productConcrete);
            $this->assertEquals($this->productConcreteTransfer->getSku(), $productConcrete->getSku());
        }
    }

    /**
     * @return void
     */
    public function testGetProductAbstractIdByConcreteSku()
    {
        $this->setupDefaultProducts();

        $idProductAbstract = $this->productFacade->getProductAbstractIdByConcreteSku($this->productConcreteTransfer->getSku());

        $this->assertEquals($this->productAbstractTransfer->getIdProductAbstract(), $idProductAbstract);
    }

    /**
     * @return void
     */
    public function testGetProductAbstractIdByConcreteSkuShouldThrowException()
    {
        $this->expectException(MissingProductException::class);

        $this->setupDefaultProducts();

        $this->productFacade->getProductAbstractIdByConcreteSku('INVALIDSKU');
    }

    /**
     * @return void
     */
    public function testGetConcreteProductsByAbstractProductIdShouldReturnEmptyArray()
    {
        $productConcreteCollection = $this->productFacade->getConcreteProductsByAbstractProductId(
            121231
        );

        $this->assertEmpty($productConcreteCollection);
    }

    /**
     * @return void
     */
    public function testGetLocalizedProductConcreteName()
    {
        $this->setupDefaultProducts();

        $productNameEN = $this->productFacade->getLocalizedProductConcreteName(
            $this->productConcreteTransfer,
            $this->locales['en_US']
        );

        $productNameDE = $this->productFacade->getLocalizedProductConcreteName(
            $this->productConcreteTransfer,
            $this->locales['de_DE']
        );

        $this->assertEquals(self::PRODUCT_CONCRETE_NAME['en_US'], $productNameEN);
        $this->assertEquals(self::PRODUCT_CONCRETE_NAME['de_DE'], $productNameDE);
    }

    /**
     * @return void
     */
    protected function createNewProductAndAssertNoTouchExists()
    {
        $idProductAbstract = $this->productAbstractManager->createProductAbstract($this->productAbstractTransfer);

        $this->productConcreteTransfer->setFkProductAbstract($idProductAbstract);
        $idProductConcrete = $this->productConcreteManager->createProductConcrete($this->productConcreteTransfer);
        $this->productConcreteTransfer->setIdProductConcrete($idProductConcrete);

        $this->assertNoTouchEntry($this->productConcreteTransfer->getIdProductConcrete(), ProductConfig::RESOURCE_TYPE_PRODUCT_CONCRETE);
    }

    /**
     * @param int $idProductAbstract
     * @param string $touchType
     *
     * @return void
     */
    protected function assertNoTouchEntry($idProductAbstract, $touchType)
    {
        $touchEntity = $this->getProductTouchEntity($touchType, $idProductAbstract);

        $this->assertNull($touchEntity);
    }

    /**
     * @param int $idProductAbstract
     * @param string $touchType
     * @param string $status
     *
     * @return void
     */
    protected function assertTouchEntry($idProductAbstract, $touchType, $status)
    {
        $touchEntity = $this->getProductTouchEntity($touchType, $idProductAbstract);

        $this->assertEquals($touchType, $touchEntity->getItemType());
        $this->assertEquals($idProductAbstract, $touchEntity->getItemId());
        $this->assertEquals($status, $touchEntity->getItemEvent());
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return void
     */
    protected function assertCreateProductConcrete(ProductConcreteTransfer $productConcreteTransfer)
    {
        $createdProductEntity = $this->getProductConcreteEntityById($productConcreteTransfer->getIdProductConcrete());

        $this->assertNotNull($createdProductEntity);
        $this->assertEquals($productConcreteTransfer->getSku(), $createdProductEntity->getSku());
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return void
     */
    protected function assertSaveProductConcrete(ProductConcreteTransfer $productConcreteTransfer)
    {
        $updatedProductEntity = $this->getProductConcreteEntityById($productConcreteTransfer->getIdProductConcrete());

        $this->assertNotNull($updatedProductEntity);
        $this->assertEquals($this->productConcreteTransfer->getSku(), $updatedProductEntity->getSku());

        foreach ($productConcreteTransfer->getLocalizedAttributes() as $localizedAttribute) {
            $expectedProductName = self::UPDATED_PRODUCT_ABSTRACT_NAME[$localizedAttribute->getLocale()->getLocaleName()];

            $this->assertEquals($expectedProductName, $localizedAttribute->getName());
        }
    }

    /**
     * @param int $idProductConcrete
     *
     * @return \Orm\Zed\Product\Persistence\SpyProduct
     */
    protected function getProductConcreteEntityById($idProductConcrete)
    {
        return $this->productQueryContainer
            ->queryProduct()
            ->filterByIdProduct($idProductConcrete)
            ->findOne();
    }

    /**
     * @param string $touchType
     * @param int $idProductAbstract
     *
     * @return \Orm\Zed\Touch\Persistence\SpyTouch
     */
    protected function getProductTouchEntity($touchType, $idProductAbstract)
    {
        return $this->touchQueryContainer
            ->queryTouchEntriesByItemTypeAndItemIds($touchType, [$idProductAbstract])
            ->findOne();
    }
}
