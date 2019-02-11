<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Shared\Product\Helper;

use ArrayObject;
use Codeception\Module;
use Generated\Shared\DataBuilder\ProductAbstractBuilder;
use Generated\Shared\DataBuilder\ProductConcreteBuilder;
use Generated\Shared\Transfer\LocaleTransfer;
use Generated\Shared\Transfer\LocalizedAttributesTransfer;
use Generated\Shared\Transfer\ProductAbstractTransfer;
use Generated\Shared\Transfer\ProductConcreteTransfer;
use Generated\Shared\Transfer\StoreRelationTransfer;
use Generated\Shared\Transfer\StoreTransfer;
use Spryker\Zed\Locale\Business\LocaleFacadeInterface;
use Spryker\Zed\Store\Business\StoreFacadeInterface;
use SprykerTest\Shared\Testify\Helper\DataCleanupHelperTrait;
use SprykerTest\Shared\Testify\Helper\LocatorHelperTrait;

class ProductDataHelper extends Module
{
    use DataCleanupHelperTrait;
    use LocatorHelperTrait;

    /**
     * @param array $productConcreteOverride
     * @param array $productAbstractOverride
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function haveProduct(array $productConcreteOverride = [], array $productAbstractOverride = [])
    {
        /** @var \Generated\Shared\Transfer\ProductAbstractTransfer $productAbstractTransfer */
        $productAbstractTransfer = (new ProductAbstractBuilder($productAbstractOverride))->build();

        $productFacade = $this->getProductFacade();
        $abstractProductId = $productFacade->createProductAbstract($productAbstractTransfer);

        /** @var \Generated\Shared\Transfer\ProductConcreteTransfer $productAbstractTransfer */
        $productConcreteTransfer = (new ProductConcreteBuilder(['fkProductAbstract' => $abstractProductId]))
            ->seed($productConcreteOverride)
            ->build();

        $productConcreteTransfer->setAbstractSku($productAbstractTransfer->getSku());
        $productFacade->createProductConcrete($productConcreteTransfer);

        $this->debug(sprintf(
            'Inserted AbstractProduct: %d, Concrete Product: %d',
            $abstractProductId,
            $productConcreteTransfer->getIdProductConcrete()
        ));

        $this->getDataCleanupHelper()->_addCleanup(function () use ($productConcreteTransfer) {
            $this->cleanupProductConcrete($productConcreteTransfer->getIdProductConcrete());
            $this->cleanupProductAbstract($productConcreteTransfer->getFkProductAbstract());
        });

        return $productConcreteTransfer;
    }

    /**
     * @param array $productConcreteOverride
     * @param array $productAbstractOverride
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function haveRandomPublishedProduct(
        array $productConcreteOverride = [],
        array $productAbstractOverride = []
    ): ProductConcreteTransfer {

        $productConcreteOverride = array_replace([
            ProductConcreteTransfer::SKU => uniqid('cp-', true),
        ], $productConcreteOverride);

        $productAbstractOverride = array_replace([
            ProductConcreteTransfer::SKU => uniqid('ap-', true),
        ], $productAbstractOverride);

        $allStoresRelation = $this->getAllStoresRelation()->toArray();
        $localizedAttributes = (new LocalizedAttributesTransfer())
            ->setName(uniqid('Product #', true))
            ->setLocale($this->getCurrentLocale())->toArray();

        /** @var \Generated\Shared\Transfer\ProductAbstractTransfer $productAbstractTransfer */
        $productAbstractTransfer = (new ProductAbstractBuilder($productAbstractOverride))
            ->withLocalizedAttributes($localizedAttributes)
            ->withStoreRelation($allStoresRelation)
            ->build();

        $productFacade = $this->getProductFacade();
        $abstractProductId = $productFacade->createProductAbstract($productAbstractTransfer);

        /** @var \Generated\Shared\Transfer\ProductConcreteTransfer $productAbstractTransfer */
        $productConcreteTransfer = (new ProductConcreteBuilder(['fkProductAbstract' => $abstractProductId]))
            ->seed($productConcreteOverride)
            ->withLocalizedAttributes($localizedAttributes)
            ->withStores($allStoresRelation)
            ->build();

        $productConcreteTransfer->setAbstractSku($productAbstractTransfer->getSku());
        $productFacade->createProductConcrete($productConcreteTransfer);

        $productFacade->createProductUrl(
            $productAbstractTransfer->setIdProductAbstract($productConcreteTransfer->getFkProductAbstract())
        );

        $this->debug(sprintf(
            'Inserted AbstractProduct: %d, Concrete Product: %d',
            $abstractProductId,
            $productConcreteTransfer->getIdProductConcrete()
        ));

        $this->getDataCleanupHelper()->_addCleanup(function () use ($productConcreteTransfer) {
            $this->cleanupProductConcrete($productConcreteTransfer->getIdProductConcrete());
            $this->cleanupProductAbstract($productConcreteTransfer->getFkProductAbstract());
        });

        return $productConcreteTransfer;
    }

    /**
     * @param array $productAbstractOverride
     *
     * @return \Generated\Shared\Transfer\ProductAbstractTransfer
     */
    public function haveProductAbstract(array $productAbstractOverride = [])
    {
        $productAbstractTransfer = (new ProductAbstractBuilder($productAbstractOverride))->build();

        $productFacade = $this->getProductFacade();
        $abstractProductId = $productFacade->createProductAbstract($productAbstractTransfer);

        $this->debug(sprintf(
            'Inserted AbstractProduct: %d',
            $abstractProductId
        ));

        $this->getDataCleanupHelper()->_addCleanup(function () use ($productAbstractTransfer) {
            $this->cleanupProductAbstract($productAbstractTransfer->getIdProductAbstract());
        });

        return $productAbstractTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductAbstractTransfer $productAbstractTransfer
     * @param \Generated\Shared\Transfer\LocalizedAttributesTransfer[] $localizedAttributes
     *
     * @return void
     */
    public function addLocalizedAttributesToProductAbstract(ProductAbstractTransfer $productAbstractTransfer, array $localizedAttributes): void
    {
        $productAbstractTransfer->setLocalizedAttributes(
            new ArrayObject($localizedAttributes)
        );

        $this->getProductFacade()->saveProductAbstract($productAbstractTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     * @param \Generated\Shared\Transfer\LocalizedAttributesTransfer[] $localizedAttributes
     *
     * @return void
     */
    public function addLocalizedAttributesToProductConcrete(ProductConcreteTransfer $productConcreteTransfer, array $localizedAttributes): void
    {
        $productConcreteTransfer->setLocalizedAttributes(
            new ArrayObject($localizedAttributes)
        );

        $this->getProductFacade()->saveProductConcrete($productConcreteTransfer);
    }

    /**
     * @return \Spryker\Zed\Product\Business\ProductFacadeInterface
     */
    protected function getProductFacade()
    {
        return $this->getLocator()->product()->facade();
    }

    /**
     * @return \Spryker\Zed\Product\Persistence\ProductQueryContainerInterface
     */
    protected function getProductQuery()
    {
        return $this->getLocator()->product()->queryContainer();
    }

    /**
     * @return \Generated\Shared\Transfer\StoreRelationTransfer
     */
    protected function getAllStoresRelation(): StoreRelationTransfer
    {
        $stores = $this->getStoreFacade()->getAllStores();

        return (new StoreRelationTransfer())
            ->setIdStores(array_map(function (StoreTransfer $storeTransfer) {
                return $storeTransfer->getIdStore();
            }, $stores))
            ->setStores(new ArrayObject($stores));
    }

    /**
     * @return \Spryker\Zed\Store\Business\StoreFacadeInterface
     */
    protected function getStoreFacade(): StoreFacadeInterface
    {
        return $this->getLocator()->store()->facade();
    }

    /**
     * @return \Generated\Shared\Transfer\LocaleTransfer
     */
    protected function getCurrentLocale(): LocaleTransfer
    {
        return $this->getLocaleFacade()->getCurrentLocale();
    }

    /**
     * @return \Spryker\Zed\Locale\Business\LocaleFacadeInterface
     */
    protected function getLocaleFacade(): LocaleFacadeInterface
    {
        return $this->getLocator()->locale()->facade();
    }

    /**
     * @param int $idProductConcrete
     *
     * @return void
     */
    protected function cleanupProductConcrete($idProductConcrete)
    {
        $this->debug(sprintf('Deleting Concrete Product: %d', $idProductConcrete));

        $this->getProductQuery()
            ->queryProduct()
            ->findByIdProduct($idProductConcrete)
            ->delete();
    }

    /**
     * @param int $idProductAbstract
     *
     * @return void
     */
    protected function cleanupProductAbstract($idProductAbstract)
    {
        $this->debug(sprintf('Deleting Abstract Product: %d', $idProductAbstract));

        $this->getProductQuery()
            ->queryProductAbstract()
            ->findByIdProductAbstract($idProductAbstract)
            ->delete();
    }
}
