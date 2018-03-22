<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductAttribute\Business\Model\Product;

use Spryker\Zed\ProductAttribute\Business\Model\Exception\ProductAbstractNotFoundException;
use Spryker\Zed\ProductAttribute\Business\Model\Exception\ProductConcreteNotFoundException;
use Spryker\Zed\ProductAttribute\Dependency\Facade\ProductAttributeToProductInterface;

class ProductReader implements ProductReaderInterface
{
    /**
     * @var \Spryker\Zed\ProductAttribute\Dependency\Facade\ProductAttributeToProductInterface
     */
    protected $productFacade;

    /**
     * @param \Spryker\Zed\ProductAttribute\Dependency\Facade\ProductAttributeToProductInterface $productFacade
     */
    public function __construct(ProductAttributeToProductInterface $productFacade)
    {
        $this->productFacade = $productFacade;
    }

    /**
     * @param int $idProductAbstract
     *
     * @throws \Spryker\Zed\ProductAttribute\Business\Model\Exception\ProductAbstractNotFoundException
     *
     * @return \Generated\Shared\Transfer\ProductAbstractTransfer
     */
    public function getProductAbstractTransfer($idProductAbstract)
    {
        $productAbstractTransfer = $this->productFacade->findProductAbstractById($idProductAbstract);

        if (!$productAbstractTransfer) {
            throw new ProductAbstractNotFoundException(sprintf(
                'Product abstract with id "%s" not found',
                $idProductAbstract
            ));
        }

        return $productAbstractTransfer;
    }

    /**
     * @param int $idProduct
     *
     * @throws \Spryker\Zed\ProductAttribute\Business\Model\Exception\ProductConcreteNotFoundException
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function getProductTransfer($idProduct)
    {
        $productConcreteTransfer = $this->productFacade->findProductConcreteById($idProduct);

        if (!$productConcreteTransfer) {
            throw new ProductConcreteNotFoundException(sprintf(
                'Product concrete with id "%s" not found',
                $idProduct
            ));
        }

        return $productConcreteTransfer;
    }
}
