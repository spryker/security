<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductDiscontinuedProductLabelConnector\Dependency\Facade;

interface ProductDiscontinuedProductLabelConnectorToProductInterface
{
    /**
     * @param int $idProduct
     *
     * @return null|int
     */
    public function findProductAbstractIdByConcreteId(int $idProduct): ?int;

    /**
     * @param int $idProduct
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer[]
     */
    public function getConcreteProductsByAbstractProductId(int $idProduct): array;
}
