<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductStorage\Dependency\Facade;

use Generated\Shared\Transfer\RawProductAttributesTransfer;

class ProductStorageToProductBridge implements ProductStorageToProductInterface
{
    /**
     * @var \Spryker\Zed\Product\Business\ProductFacadeInterface
     */
    protected $productFacade;

    /**
     * @param \Spryker\Zed\Product\Business\ProductFacadeInterface $productFacade
     */
    public function __construct($productFacade)
    {
        $this->productFacade = $productFacade;
    }

    /**
     * @param string $attributes
     *
     * @return array
     */
    public function decodeProductAttributes($attributes)
    {
        return $this->productFacade->decodeProductAttributes($attributes);
    }

    /**
     * @param \Generated\Shared\Transfer\RawProductAttributesTransfer $rawProductAttributesTransfer
     *
     * @return array
     */
    public function combineRawProductAttributes(RawProductAttributesTransfer $rawProductAttributesTransfer)
    {
        return $this->productFacade->combineRawProductAttributes($rawProductAttributesTransfer);
    }

    /**
     * @param array $superAttributes
     * @param int $idProductConcrete
     *
     * @return array
     */
    public function generateAttributePermutations(array $superAttributes, $idProductConcrete)
    {
        return $this->productFacade->generateAttributePermutations($superAttributes, $idProductConcrete);
    }
}
