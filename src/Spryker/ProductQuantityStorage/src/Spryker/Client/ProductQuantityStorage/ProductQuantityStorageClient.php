<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductQuantityStorage;

use Generated\Shared\Transfer\ProductQuantityStorageTransfer;
use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\ProductQuantityStorage\ProductQuantityStorageFactory getFactory()
 */
class ProductQuantityStorageClient extends AbstractClient implements ProductQuantityStorageClientInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProduct
     *
     * @return \Generated\Shared\Transfer\ProductQuantityStorageTransfer|null
     */
    public function findProductQuantityStorage(int $idProduct): ?ProductQuantityStorageTransfer
    {
        return $this->getFactory()
            ->createProductQuantityStorageReader()
            ->findProductQuantityStorage($idProduct);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProduct
     * @param int $quantity
     *
     * @return int
     */
    public function getNearestQuantity(int $idProduct, int $quantity): int
    {
        return $this->getFactory()
            ->createProductQuantityResolver()
            ->getNearestQuantity($idProduct, $quantity);
    }
}
