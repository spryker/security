<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantRelationshipProductList\Communication\Plugin\MerchantRelationship;

use Generated\Shared\Transfer\MerchantRelationshipDeleteResponseTransfer;
use Generated\Shared\Transfer\MerchantRelationshipTransfer;
use Generated\Shared\Transfer\MessageTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\MerchantRelationshipExtension\Dependency\Plugin\MerchantRelationshipPreDeletePluginInterface;

/**
 * @method \Spryker\Zed\MerchantRelationshipProductList\Business\MerchantRelationshipProductListFacadeInterface getFacade()
 * @method \Spryker\Zed\MerchantRelationshipProductList\MerchantRelationshipProductListConfig getConfig()
 */
class ProductListMerchantRelationshipPreDeletePlugin extends AbstractPlugin implements MerchantRelationshipPreDeletePluginInterface
{
    public const ERROR_MESSAGE = 'merchant.relationship.product.list.pre.delete.check';

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\MerchantRelationshipTransfer $merchantRelationshipTransfer
     *
     * @return \Generated\Shared\Transfer\MerchantRelationshipDeleteResponseTransfer
     */
    public function execute(MerchantRelationshipTransfer $merchantRelationshipTransfer): MerchantRelationshipDeleteResponseTransfer
    {
        $merchantRelationshipDeleteResponseTransfer = (new MerchantRelationshipDeleteResponseTransfer())->setIsSuccess(false);
        $productListCollection = $this->getFacade()->getProductListCollectionByMerchantRelationship($merchantRelationshipTransfer);

        if (!$productListCollection->getProductLists()->count()) {
            return $merchantRelationshipDeleteResponseTransfer->setIsSuccess(true);
        }

        if ($productListCollection->getProductLists()->count()) {
            foreach ($productListCollection->getProductLists() as $productListTransfer) {
                $merchantRelationshipDeleteResponseTransfer = $this->getFacade()->deleteMerchantRelationshipFromProductList($productListTransfer);
            }

            return $merchantRelationshipDeleteResponseTransfer;
        }

        $message = (new MessageTransfer())->setValue(static::ERROR_MESSAGE);
        $merchantRelationshipDeleteResponseTransfer->setIsSuccess(false);
        $merchantRelationshipDeleteResponseTransfer->addMessage($message);

        return $merchantRelationshipDeleteResponseTransfer;
    }
}
