<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */
namespace Spryker\Zed\Product\Business\Product\Sku;

interface SkuIncrementGeneratorInterface
{
    /**
     * @param string $idProductAbstract
     *
     * @return string
     */
    public function generateProductConcreteSkuIncrement(string $idProductAbstract): string;
}
