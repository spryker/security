<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationshipProductList\Communication\Plugin\MerchantRelationship;

use Generated\Shared\Transfer\MerchantRelationshipTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\MerchantRelationshipExtension\Dependency\Plugin\MerchantRelationshipPreDeletePluginInterface;

/**
 * @method \Spryker\Zed\MerchantRelationshipProductList\Business\MerchantRelationshipProductListFacadeInterface getFacade()
 * @method \Spryker\Zed\MerchantRelationshipProductList\MerchantRelationshipProductListConfig getConfig()
 */
class ProductListMerchantRelationshipPreDeletePlugin extends AbstractPlugin implements MerchantRelationshipPreDeletePluginInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationshipTransfer
     *
     * @return void
     */
    public function execute(MerchantRelationshipTransfer $merchantRelationshipTransfer): void
    {
        $productListCollection = $this->getFacade()->findProductListCollectionByMerchantRelationship($merchantRelationshipTransfer);

        if (!$productListCollection->getProductLists()->count()) {
            return;
        }

        foreach ($productListCollection->getProductLists() as $productListTransfer) {
            $this->getFacade()->clearMerchantRelationshipFromProductList($productListTransfer);
        }
    }
}
