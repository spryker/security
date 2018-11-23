<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\ProductListStorage;

use Generated\Shared\Transfer\ProductAbstractProductListStorageTransfer;
use Generated\Shared\Transfer\ProductConcreteProductListStorageTransfer;
use Spryker\Client\Kernel\AbstractClient;

/**
 * @method \Spryker\Client\ProductListStorage\ProductListStorageFactory getFactory()
 */
class ProductListStorageClient extends AbstractClient implements ProductListStorageClientInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProductAbstract
     *
     * @return \Generated\Shared\Transfer\ProductAbstractProductListStorageTransfer|null
     */
    public function findProductAbstractProductListStorage(int $idProductAbstract): ?ProductAbstractProductListStorageTransfer
    {
        return $this->getFactory()
            ->createProductListProductAbstractStorageReader()
            ->findProductAbstractProductListStorage($idProductAbstract);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProduct
     *
     * @return \Generated\Shared\Transfer\ProductConcreteProductListStorageTransfer|null
     */
    public function findProductConcreteProductListStorage(int $idProduct): ?ProductConcreteProductListStorageTransfer
    {
        return $this->getFactory()
            ->createProductListProductConcreteStorageReader()
            ->findProductConcreteProductListStorage($idProduct);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProductAbstract
     *
     * @return bool
     */
    public function isProductAbstractRestricted(int $idProductAbstract): bool
    {
        return $this->getFactory()
            ->createProductAbstractRestrictionReader()
            ->isProductAbstractRestricted($idProductAbstract);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProduct
     *
     * @return bool
     */
    public function isProductConcreteRestricted(int $idProduct): bool
    {
        return $this->getFactory()
            ->createProductConcreteRestrictionReader()
            ->isProductConcreteRestricted($idProduct);
    }
}
