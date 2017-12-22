<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductCategoryFilter\Business\Model;

use Generated\Shared\Transfer\ProductCategoryFilterTransfer;
use Orm\Zed\ProductCategoryFilter\Persistence\SpyProductCategoryFilter;
use Spryker\Zed\PropelOrm\Business\Transaction\DatabaseTransactionHandlerTrait;

class ProductCategoryFilterCreator implements ProductCategoryFilterCreatorInterface
{
    use DatabaseTransactionHandlerTrait;

    /**
     * @var \Spryker\Zed\ProductCategoryFilter\Business\Model\ProductCategoryFilterTouchInterface
     */
    protected $productCategoryFilterTouch;

    /**
     * @param \Spryker\Zed\ProductCategoryFilter\Business\Model\ProductCategoryFilterTouchInterface $productCategoryFilterTouch
     */
    public function __construct(ProductCategoryFilterTouchInterface $productCategoryFilterTouch)
    {
        $this->productCategoryFilterTouch = $productCategoryFilterTouch;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductCategoryFilterTransfer $productCategoryFilterTransfer
     *
     * @return \Generated\Shared\Transfer\ProductCategoryFilterTransfer
     */
    public function createProductCategoryFilter(ProductCategoryFilterTransfer $productCategoryFilterTransfer)
    {
        return $this->handleDatabaseTransaction(function () use ($productCategoryFilterTransfer) {
            return $this->executeCreateProductCategoryFilterTransaction($productCategoryFilterTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\ProductCategoryFilterTransfer $productCategoryFilterTransfer
     *
     * @return \Generated\Shared\Transfer\ProductCategoryFilterTransfer
     */
    protected function executeCreateProductCategoryFilterTransaction(ProductCategoryFilterTransfer $productCategoryFilterTransfer)
    {
        $productCategoryFilterEntity = $this->createProductCategoryFilterEntity($productCategoryFilterTransfer);
        $productCategoryFilterTransfer->setIdProductCategoryFilter($productCategoryFilterEntity->getIdProductCategoryFilter());

        $this->productCategoryFilterTouch->touchProductCategoryFilterActive($productCategoryFilterTransfer);

        return $productCategoryFilterTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductCategoryFilterTransfer $productCategoryFilterTransfer
     *
     * @return \Orm\Zed\ProductCategoryFilter\Persistence\SpyProductCategoryFilter
     */
    protected function createProductCategoryFilterEntity(ProductCategoryFilterTransfer $productCategoryFilterTransfer)
    {
        $productCategoryFilterEntity = new SpyProductCategoryFilter();
        $productCategoryFilterEntity->fromArray($productCategoryFilterTransfer->toArray());

        $productCategoryFilterEntity->save();

        return $productCategoryFilterEntity;
    }
}
