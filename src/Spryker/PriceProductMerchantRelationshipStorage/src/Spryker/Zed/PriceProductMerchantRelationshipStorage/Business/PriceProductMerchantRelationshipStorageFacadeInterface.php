<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductMerchantRelationshipStorage\Business;

/**
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Business\PriceProductMerchantRelationshipStorageBusinessFactory getFactory()
 */
interface PriceProductMerchantRelationshipStorageFacadeInterface
{
    /**
     * Specification:
     *  -
     *
     * @api
     *
     * @deprecated Will be removed without replacement.
     *
     * @param array $businessUnitProducts
     *
     * @return void
     */
    public function publishConcretePriceProductByBusinessUnitProducts(array $businessUnitProducts): void;

    /**
     * Specification:
     *  -
     *
     * @api
     *
     * @deprecated Will be removed without replacement.
     *
     * @param array $businessUnitProducts
     *
     * @return void
     */
    public function publishAbstractPriceProductByBusinessUnitProducts(array $businessUnitProducts): void;

    /**
     * Specification:
     *  - TODO
     *
     * @api
     *
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    public function publishAbstractPriceProductByBusinessUnits(array $companyBusinessUnitIds): void;

    /**
     * Specification:
     *  - TODO
     *
     * @api
     *
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    public function unpublishAbstractPriceProductByBusinessUnits(array $companyBusinessUnitIds): void;

    /**
     * Specification:
     *  - TODO
     *
     * @api
     *
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    public function publishConcretePriceProductByBusinessUnits(array $companyBusinessUnitIds): void;

    /**
     * Specification:
     *  - TODO
     *
     * @api
     *
     * @param int[] $companyBusinessUnitIds
     *
     * @return void
     */
    public function unpublishConcretePriceProductByBusinessUnits(array $companyBusinessUnitIds): void;

    /**
     * Specification:
     *  - TODO
     *
     * @api
     *
     * @param int[] $priceProductMerchantRelationshipIds
     *
     * @return void
     */
    public function publishAbstractPriceProductMerchantRelationship(array $priceProductMerchantRelationshipIds): void;

    /**
     * Specification:
     *  - TODO
     *
     * @api
     *
     * @param int[] $priceProductMerchantRelationshipIds
     *
     * @return void
     */
    public function unpublishAbstractPriceProductMerchantRelationship(array $priceProductMerchantRelationshipIds): void;

    /**
     * Specification:
     *  - TODO
     *
     * @api
     *
     * @param int[] $priceProductMerchantRelationshipIds
     *
     * @return void
     */
    public function publishConcretePriceProductMerchantRelationship(array $priceProductMerchantRelationshipIds): void;

    /**
     * Specification:
     *  - TODO
     *
     * @api
     *
     * @param int[] $priceProductMerchantRelationshipIds
     *
     * @return void
     */
    public function unpublishConcretePriceProductMerchantRelationship(array $priceProductMerchantRelationshipIds): void;
}
