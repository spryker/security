<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductQuantityStorage\Business;

use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\ProductQuantityStorage\Business\ProductQuantityStorageBusinessFactory getFactory()
 */
class ProductQuantityStorageFacade extends AbstractFacade implements ProductQuantityStorageFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $productIds
     *
     * @return void
     */
    public function publishProductQuantity(array $productIds): void
    {
        $this->getFactory()->createProductQuantityStorageWriter()->publish($productIds);
    }

    /**
     * Specification:
     * - Retrieves all product quantity transfers.
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\ProductQuantityTransfer[]|\Spryker\Shared\Kernel\Transfer\AbstractEntityTransfer[]
     */
    public function findProductQuantityTransfers(): array
    {
        return $this->getFactory()->getProductQuantityFacade()->findProductQuantityTransfers();
    }

    /**
     * Specification:
     * - Retrieves product quantity transfers by product ids.
     *
     * @api
     *
     * @param int[] $productIds
     *
     * @return \Generated\Shared\Transfer\ProductQuantityTransfer[]|\Spryker\Shared\Kernel\Transfer\AbstractEntityTransfer[]
     */
    public function findProductQuantityByProductIdsTransfers(array $productIds): array
    {
        return $this->getFactory()->getProductQuantityFacade()->findProductQuantityTransfersByProductIds($productIds);
    }
}
