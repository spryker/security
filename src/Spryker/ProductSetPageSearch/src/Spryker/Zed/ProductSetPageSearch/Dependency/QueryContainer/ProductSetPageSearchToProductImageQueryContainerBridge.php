<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSetPageSearch\Dependency\QueryContainer;

class ProductSetPageSearchToProductImageQueryContainerBridge implements ProductSetPageSearchToProductImageQueryContainerInterface
{
    /**
     * @var \Spryker\Zed\ProductImage\Persistence\ProductImageQueryContainerInterface
     */
    protected $productImageQueryContainer;

    /**
     * @param \Spryker\Zed\ProductImage\Persistence\ProductImageQueryContainerInterface $productImageQueryContainer
     */
    public function __construct($productImageQueryContainer)
    {
        $this->productImageQueryContainer = $productImageQueryContainer;
    }

    /**
     * @param int $idProductImageSet
     *
     * @return \Orm\Zed\ProductImage\Persistence\SpyProductImageSetToProductImageQuery
     */
    public function queryImagesByIdProductImageSet($idProductImageSet)
    {
        return $this->productImageQueryContainer->queryImagesByIdProductImageSet($idProductImageSet);
    }

    /**
     * @return \Orm\Zed\ProductImage\Persistence\SpyProductImageSetToProductImageQuery
     */
    public function queryProductImageSetToProductImage()
    {
        return $this->productImageQueryContainer->queryProductImageSetToProductImage();
    }
}
