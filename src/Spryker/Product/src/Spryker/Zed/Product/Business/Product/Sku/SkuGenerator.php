<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Product\Business\Product\Sku;

use Generated\Shared\Transfer\ProductAbstractTransfer;
use Generated\Shared\Transfer\ProductConcreteTransfer;
use Spryker\Zed\Product\Dependency\Service\ProductToUtilTextInterface;

class SkuGenerator implements SkuGeneratorInterface
{
    const SKU_ABSTRACT_SEPARATOR = '-';
    const SKU_TYPE_SEPARATOR = '-';
    const SKU_VALUE_SEPARATOR = '_';

    /**
     * @var \Spryker\Zed\Product\Dependency\Service\ProductToUtilTextInterface
     */
    protected $utilTextService;

    /**
     * @param \Spryker\Zed\Product\Dependency\Service\ProductToUtilTextInterface $utilTextService
     */
    public function __construct(ProductToUtilTextInterface $utilTextService)
    {
        $this->utilTextService = $utilTextService;
    }

    /**
     * @param \Generated\Shared\Transfer\ProductAbstractTransfer $productAbstractTransfer
     *
     * @return string
     */
    public function generateProductAbstractSku(ProductAbstractTransfer $productAbstractTransfer)
    {
        return $productAbstractTransfer->getSku();
    }

    /**
     * @param \Generated\Shared\Transfer\ProductAbstractTransfer $productAbstractTransfer
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return string
     */
    public function generateProductConcreteSku(
        ProductAbstractTransfer $productAbstractTransfer,
        ProductConcreteTransfer $productConcreteTransfer
    ) {
        $concreteSku = $this->generateConcreteSkuFromAttributes($productConcreteTransfer->getAttributes());
        $concreteSku = $this->formatConcreteSku($productAbstractTransfer->getSku(), $concreteSku);

        return $concreteSku;
    }

    /**
     * @param string $abstractSku
     * @param string $concreteSku
     *
     * @return string
     */
    protected function formatConcreteSku($abstractSku, $concreteSku)
    {
        return $this->utilTextService->generateSlug(sprintf(
            '%s%s%s',
            $abstractSku,
            static::SKU_ABSTRACT_SEPARATOR,
            $concreteSku
        ));
    }

    /**
     * @param array $attributes
     *
     * @return string
     */
    protected function generateConcreteSkuFromAttributes(array $attributes)
    {
        $sku = '';
        foreach ($attributes as $type => $value) {
            $sku .= $type . static::SKU_TYPE_SEPARATOR . $value . static::SKU_VALUE_SEPARATOR;
        }

        return rtrim($sku, static::SKU_VALUE_SEPARATOR);
    }
}
