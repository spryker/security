<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\PriceProductMerchantRelationshipStorage;

/**
 * Declares global environment configuration keys. Do not use it for other class constants.
 */
class PriceProductMerchantRelationshipStorageConstants
{
    /**
     * Specification:
     * - Resource name, it's used for key generating.
     *
     * @api
     */
    public const PRICE_PRODUCT_ABSTRACT_MERCHANT_RELATIONSHIP_RESOURCE_NAME = 'price_product_abstract_merchant_relationship';

    /**
     * Specification:
     * - Resource name, it's used for key generating.
     *
     * @api
     */
    public const PRICE_PRODUCT_CONCRETE_MERCHANT_RELATIONSHIP_RESOURCE_NAME = 'price_product_concrete_merchant_relationship';

    /**
     * @deprecated Use the constants in PriceProductMerchantRelationshipStorageConfig instead.
     *
     * @uses \Orm\Zed\PriceProduct\Persistence\Map\SpyPriceProductStoreTableMap::COL_FK_STORE
     */
    public const COL_PRICE_PRODUCT_STORE_FK_STORE = 'spy_price_product_store.fk_store';

    /**
     * @deprecated Use the constants in PriceProductMerchantRelationshipStorageConfig instead.
     *
     * @uses \Orm\Zed\PriceProductMerchantRelationship\Persistence\Map\SpyPriceProductMerchantRelationshipTableMap::COL_FK_MERCHANT_RELATIONSHIP
     */
    public const COL_FK_MERCHANT_RELATIONSHIP = 'spy_price_product_merchant_relationship.fk_merchant_relationship';

    /**
     * @deprecated Use the constants in PriceProductMerchantRelationshipStorageConfig instead.
     *
     * @uses \Orm\Zed\MerchantRelationship\Persistence\Map\SpyMerchantRelationshipToCompanyBusinessUnitTableMap::COL_FK_COMPANY_BUSINESS_UNIT
     */
    public const COL_FK_COMPANY_BUSINESS_UNIT = 'spy_merchant_relationship_to_company_business_unit.fk_company_business_unit';
}
