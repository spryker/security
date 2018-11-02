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
 */
class PriceProductMerchantRelationshipStorageFacade extends AbstractFacade implements PriceProductMerchantRelationshipStorageFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @deprecated Will be removed without replacement.
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
     * @deprecated Will be removed without replacement
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
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    public function publishAbstractPriceProductByBusinessUnits(array $companyBusinessUnitIds): void
    {
        $this->getFactory()->createPriceProductAbstractStorageWriter()->publishByCompanyBusinessUnitIds($companyBusinessUnitIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    public function unpublishAbstractPriceProductByBusinessUnits(array $companyBusinessUnitIds): void
    {
        $this->getFactory()->createPriceProductAbstractStorageWriter()->unpublishByCompanyBusinessUnitIds($companyBusinessUnitIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    public function publishConcretePriceProductByBusinessUnits(array $companyBusinessUnitIds): void
    {
        $this->getFactory()->createPriceProductConcreteStorageWriter()->publishByCompanyBusinessUnitIds($companyBusinessUnitIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    public function unpublishConcretePriceProductByBusinessUnits(array $companyBusinessUnitIds): void
    {
        $this->getFactory()->createPriceProductConcreteStorageWriter()->unpublishByCompanyBusinessUnitIds($companyBusinessUnitIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $priceProductMerchantRelationshipIds
     *
     * @return void
     */
    public function publishAbstractPriceProductMerchantRelationship(array $priceProductMerchantRelationshipIds): void
    {
        $this->getFactory()->createPriceProductAbstractStorageWriter()->publishAbstractPriceProductMerchantRelationship($priceProductMerchantRelationshipIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $priceProductMerchantRelationshipIds
     *
     * @return void
     */
    public function unpublishAbstractPriceProductMerchantRelationship(array $priceProductMerchantRelationshipIds): void
    {
        $this->getFactory()->createPriceProductAbstractStorageWriter()->unpublishAbstractPriceProductMerchantRelationship($priceProductMerchantRelationshipIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $priceProductMerchantRelationshipIds
     *
     * @return void
     */
    public function publishConcretePriceProductMerchantRelationship(array $priceProductMerchantRelationshipIds): void
    {
        $this->getFactory()->createPriceProductConcreteStorageWriter()->publishConcretePriceProductMerchantRelationship($priceProductMerchantRelationshipIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $priceProductMerchantRelationshipIds
     *
     * @return void
     */
    public function unpublishConcretePriceProductMerchantRelationship(array $priceProductMerchantRelationshipIds): void
    {
        $this->getFactory()->createPriceProductConcreteStorageWriter()->unpublishConcretePriceProductMerchantRelationship($priceProductMerchantRelationshipIds);
    }
}
