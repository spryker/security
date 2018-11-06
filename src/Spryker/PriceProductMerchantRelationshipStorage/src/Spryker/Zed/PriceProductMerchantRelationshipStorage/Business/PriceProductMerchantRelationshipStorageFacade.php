<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductMerchantRelationshipStorage\Business;

use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Business\PriceProductMerchantRelationshipStorageBusinessFactory getFactory()
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageRepositoryInterface getRepository()
 */
class PriceProductMerchantRelationshipStorageFacade extends AbstractFacade implements PriceProductMerchantRelationshipStorageFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param array $businessUnitProducts
     *
     * @return void
     */
    public function publishConcretePriceProductByBusinessUnitProducts(array $businessUnitProducts): void
    {
        $this->getFactory()->createPriceProductConcreteStorageWriter()->publishByBusinessUnitProducts($businessUnitProducts);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param array $businessUnitProducts
     *
     * @return void
     */
    public function publishAbstractPriceProductByBusinessUnitProducts(array $businessUnitProducts): void
    {
        $this->getFactory()->createPriceProductAbstractStorageWriter()->publishByBusinessUnitProducts($businessUnitProducts);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param array $businessUnitIds
     *
     * @return void
     */
    public function publishAbstractPriceProductByBusinessUnits(array $businessUnitIds): void
    {
        $this->getFactory()->createPriceProductAbstractStorageWriter()->publishByBusinessUnits($businessUnitIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param array $businessUnitIds
     *
     * @return void
     */
    public function publishConcretePriceProductByBusinessUnits(array $businessUnitIds): void
    {
        $this->getFactory()->createPriceProductConcreteStorageWriter()->publishByBusinessUnits($businessUnitIds);
    }
}
