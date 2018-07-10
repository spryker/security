<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductAlternativeProductLabelConnector\Persistence;

use Orm\Zed\ProductLabel\Persistence\SpyProductLabel;

interface ProductAlternativeProductLabelConnectorRepositoryInterface
{
    /**
     * @param string $labelName
     *
     * @return null|\Orm\Zed\ProductLabel\Persistence\SpyProductLabel
     */
    public function findProductLabelByName(string $labelName): ?SpyProductLabel;

    /**
     * @return array
     */
    public function getProductConcreteIds(): array;
}
