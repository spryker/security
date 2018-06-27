<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\PriceProductMerchantRelationshipStorage\Plugin\PriceProductStorageExtension;

use Generated\Shared\Transfer\PriceProductStorageTransfer;
use Spryker\Client\Kernel\AbstractPlugin;
use Spryker\Client\PriceProductStorageExtension\Dependency\Plugin\PriceProductStoragePriceDimensionPluginInterface;

/**
 * @method \Spryker\Client\PriceProductMerchantRelationshipStorage\PriceProductMerchantRelationshipStorageClientInterface getClient()
 * @method \Spryker\Client\PriceProductMerchantRelationshipStorage\PriceProductMerchantRelationshipStorageFactory getFactory()
 * @method \Spryker\Client\PriceProductMerchantRelationshipStorage\PriceProductMerchantRelationshipStorageConfig getConfig()
 */
class PriceProductMerchantRelationshipStorageDimensionPlugin extends AbstractPlugin implements PriceProductStoragePriceDimensionPluginInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProductConcrete
     *
     * @return \Generated\Shared\Transfer\PriceProductStorageTransfer|null
     */
    public function findProductConcretePrices(int $idProductConcrete): array
    {
        $idBusinessUnitFromCurrentCustomer = 1;

        return $this->getFactory()
            ->createPriceProductMerchantRelationshipConcreteReader()
            ->findPriceMerchantRelationshipConcrete(
                $idProductConcrete,
                $idBusinessUnitFromCurrentCustomer
            );


//        $merchantRelationshipIds = $this->getFactory()
//            ->createMerchantRelationshipFinder()
//            ->findCurrentCustomerMerchantRelationshipIds();
//
//        if (!$merchantRelationshipIds) {
//            return null;
//        }


//        foreach ($merchantRelationshipIds as $idMerchantRelationship) {
//            $priceProductStorageTransfer = $this->getFactory()
//            ->createPriceProductMerchantRelationshipConcreteReader()
//            ->findPriceMerchantRelationshipConcrete(
//                $idProductConcrete,
//                $idMerchantRelationship
//            );
//            if ($priceProductStorageTransfer) {
//                return $priceProductStorageTransfer;
//            }
//        }

        return null;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProductAbstract
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer[]
     */
    public function findProductAbstractPrices(int $idProductAbstract): array
    {
        // todo
        $idBusinessUnitFromCurrentCustomer = 1;

        return $this->getFactory()
            ->createPriceProductMerchantRelationshipAbstractReader()
            ->findProductAbstractPrices(
                $idProductAbstract,
                $idBusinessUnitFromCurrentCustomer
            );

//        $merchantRelationshipIds = $this->getFactory()
//            ->createMerchantRelationshipFinder()
//            ->findCurrentCustomerMerchantRelationshipIds();
//
//        if (!$merchantRelationshipIds) {
//            return null;
//        }

//
//        foreach ($merchantRelationshipIds as $idMerchantRelationship) {
//            $priceProductStorageTransfer = $this->getFactory()
//                ->createPriceProductMerchantRelationshipAbstractReader()
//                ->findPriceMerchantRelationshipAbstract(
//                    $idProductAbstract,
//                    $idMerchantRelationship
//                );
//            if ($priceProductStorageTransfer) {
//                return $priceProductStorageTransfer;
//            }
//        }

        return null;
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return string
     */
    public function getDimensionName(): string
    {
        return $this->getConfig()->getPriceDimensionMerchantRelationship();
    }
}
