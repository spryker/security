<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductQuantityStorage;

use Generated\Shared\Transfer\ItemValidationTransfer;
use Generated\Shared\Transfer\ProductQuantityStorageTransfer;
use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\ProductQuantityStorage\ProductQuantityStorageFactory getFactory()
 */
class ProductQuantityStorageClient extends AbstractClient implements ProductQuantityStorageClientInterface
{
    /**
     * @deprecated use getProductQuantityStorage instead.
     *
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
     *
     * @return \Generated\Shared\Transfer\ProductQuantityStorageTransfer
     */
    public function getProductQuantityStorage(int $idProduct): ProductQuantityStorageTransfer
    {
        return $this->getFactory()
            ->createProductQuantityStorageReader()
            ->getProductQuantityStorage($idProduct);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProduct
     * @param float $quantity
     *
     * @return float
     */
    public function getNearestQuantity(int $idProduct, float $quantity): float
    {
        return $this->getFactory()
            ->createProductQuantityResolver()
            ->getNearestQuantity($idProduct, $quantity);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ItemValidationTransfer $itemValidationTransfer
     *
     * @return \Generated\Shared\Transfer\ItemValidationTransfer
     */
    public function validateItemProductQuantity(ItemValidationTransfer $itemValidationTransfer): ItemValidationTransfer
    {
        return $this->getFactory()
            ->createProductQuantityItemTransferValidator()
            ->validate($itemValidationTransfer);
    }
}
