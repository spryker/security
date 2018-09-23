<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProduct\Communication\Plugin\ProductConcrete;

use ArrayObject;
use Generated\Shared\Transfer\PriceProductCriteriaTransfer;
use Generated\Shared\Transfer\PriceProductDimensionTransfer;
use Generated\Shared\Transfer\ProductConcreteTransfer;
use Spryker\Shared\PriceProduct\PriceProductConfig;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\Product\Dependency\Plugin\ProductConcretePluginReadInterface;

/**
 * @method \Spryker\Zed\PriceProduct\Business\PriceProductFacadeInterface getFacade()
 * @method \Spryker\Zed\PriceProduct\Communication\PriceProductCommunicationFactory getFactory()
 */
class PriceProductConcreteReadPlugin extends AbstractPlugin implements ProductConcretePluginReadInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function read(ProductConcreteTransfer $productConcreteTransfer)
    {
        $priceProductCriteria = (new PriceProductCriteriaTransfer())->setPriceDimension(
            (new PriceProductDimensionTransfer())
                ->setType(PriceProductConfig::PRICE_DIMENSION_DEFAULT)
        );
        $priceProductTransfers = $this->getFacade()->findProductConcretePrices(
            $productConcreteTransfer->getIdProductConcrete(),
            $productConcreteTransfer->getFkProductAbstract(),
            $priceProductCriteria
        );
        if ($priceProductTransfers) {
            $productConcreteTransfer->setPrices(new ArrayObject($priceProductTransfers));
        }

        return $productConcreteTransfer;
    }
}
