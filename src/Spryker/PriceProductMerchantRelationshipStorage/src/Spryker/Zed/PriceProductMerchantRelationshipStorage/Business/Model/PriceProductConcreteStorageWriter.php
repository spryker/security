<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductMerchantRelationshipStorage\Business\Model;

use Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageEntityManagerInterface;
use Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageRepositoryInterface;

class PriceProductConcreteStorageWriter implements PriceProductConcreteStorageWriterInterface
{
    /**
     * @var \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageEntityManagerInterface
     */
    protected $priceProductMerchantRelationshipStorageEntityManager;

    /**
     * @var \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageRepositoryInterface
     */
    protected $priceProductMerchantRelationshipStorageRepository;

    /**
     * @var \Spryker\Zed\PriceProductMerchantRelationshipStorage\Business\Model\PriceGrouperInterface
     */
    protected $priceGrouper;

    /**
     * @param \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageEntityManagerInterface $priceProductMerchantRelationshipStorageEntityManager
     * @param \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageRepositoryInterface $priceProductMerchantRelationshipStorageRepository
     * @param \Spryker\Zed\PriceProductMerchantRelationshipStorage\Business\Model\PriceGrouperInterface $priceGrouper
     */
    public function __construct(
        PriceProductMerchantRelationshipStorageEntityManagerInterface $priceProductMerchantRelationshipStorageEntityManager,
        PriceProductMerchantRelationshipStorageRepositoryInterface $priceProductMerchantRelationshipStorageRepository,
        PriceGrouperInterface $priceGrouper
    ) {
        $this->priceProductMerchantRelationshipStorageEntityManager = $priceProductMerchantRelationshipStorageEntityManager;
        $this->priceProductMerchantRelationshipStorageRepository = $priceProductMerchantRelationshipStorageRepository;
        $this->priceGrouper = $priceGrouper;
    }

    /**
     * @deprecated Will be removed without replacement.
     *
     * @param array $businessUnitProducts
     *
     * @return void
     */
    public function publishByBusinessUnitProducts(array $businessUnitProducts): void
    {
        $this->publishByBusinessUnits(array_keys($businessUnitProducts));
    }

    /**
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    public function publishByBusinessUnits(array $companyBusinessUnitIds): void
    {
        $priceProductMerchantRelationshipStorageTransfers = $this->priceProductMerchantRelationshipStorageRepository
            ->getProductConcretePriceDataByCompanyBusinessUnitIds($companyBusinessUnitIds);

        $this->write($priceProductMerchantRelationshipStorageTransfers, $companyBusinessUnitIds);
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductMerchantRelationshipStorageTransfer[] $priceProductMerchantRelationshipStorageTransfers
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    protected function write(array $priceProductMerchantRelationshipStorageTransfers, array $companyBusinessUnitIds): void
    {
        /** @var \Orm\Zed\PriceProductMerchantRelationshipStorage\Persistence\SpyPriceProductConcreteMerchantRelationshipStorage[] $mappedPriceProductMerchantRelationshipStorageEntities */
        $mappedPriceProductMerchantRelationshipStorageEntities = $this->createExistingPriceProductMerchantRelationshipStorageEntitiesMap($companyBusinessUnitIds);
        $priceProductMerchantRelationshipStorageTransfers = $this->priceGrouper->groupPrices(
            $priceProductMerchantRelationshipStorageTransfers
        );

        foreach ($priceProductMerchantRelationshipStorageTransfers as $merchantRelationshipStorageTransfer) {
            if (isset($mappedPriceProductMerchantRelationshipStorageEntities[$merchantRelationshipStorageTransfer->getPriceKey()])) {
                $this->priceProductMerchantRelationshipStorageEntityManager->updatePriceProductConcrete(
                    $mappedPriceProductMerchantRelationshipStorageEntities[$merchantRelationshipStorageTransfer->getPriceKey()],
                    $merchantRelationshipStorageTransfer
                );

                unset($mappedPriceProductMerchantRelationshipStorageEntities[$merchantRelationshipStorageTransfer->getPriceKey()]);
                continue;
            }

            $this->priceProductMerchantRelationshipStorageEntityManager->createPriceProductConcrete(
                $merchantRelationshipStorageTransfer
            );
        }

        // Delete the rest of the entites
        foreach ($mappedPriceProductMerchantRelationshipStorageEntities as $priceProductMerchantRelationshipStorageEntity) {
            $priceProductMerchantRelationshipStorageEntity->delete();
        }

        unset($mappedPriceProductMerchantRelationshipStorageEntities);
    }

    /**
     * @param int[] $companyBusinessUnitIds
     *
     * @return array
     */
    protected function createExistingPriceProductMerchantRelationshipStorageEntitiesMap(array $companyBusinessUnitIds)
    {
        $existingPriceProductMerchantRelationshipStorageEntities = $this->priceProductMerchantRelationshipStorageRepository
            ->findExistingPriceProductConcreteMerchantRelationshipStorageEntities($companyBusinessUnitIds);

        $mappedPriceProductMerchantRelationshipStorageEntities = [];
        foreach ($existingPriceProductMerchantRelationshipStorageEntities as $priceProductMerchantRelationshipStorageEntity) {
            $mappedPriceProductMerchantRelationshipStorageEntities[$priceProductMerchantRelationshipStorageEntity->getPriceKey()] =
                $priceProductMerchantRelationshipStorageEntity;
        }

        unset($existingPriceProductMerchantRelationshipStorageEntities);

        return $mappedPriceProductMerchantRelationshipStorageEntities;
    }
}
