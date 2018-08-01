<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\PriceProductMerchantRelationshipDataImport;

/**
 * Declares global environment configuration keys. Do not use it for other class constants.
 */
interface PriceProductMerchantRelationshipDataImportConstants
{
    /**
     * @uses \Spryker\Zed\PriceProductMerchantRelationship\Dependency\PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_STORE_CREATE
     */
    public const ENTITY_SPY_PRICE_PRODUCT_STORE_CREATE = 'Entity.spy_price_product_store.create';

    /**
     * @uses \Spryker\Zed\PriceProductMerchantRelationship\Dependency\PriceProductMerchantRelationshipEvents::ENTITY_SPY_PRICE_PRODUCT_STORE_UPDATE
     */
    public const ENTITY_SPY_PRICE_PRODUCT_STORE_UPDATE = 'Entity.spy_price_product_store.update';

    public const ENTITY_SPY_PRICE_PRODUCT_MERCHANT_RELATIONSHIP_CREATE = 'Entity.spy_price_product_merchant_relationship.create';

    public const ENTITY_SPY_PRICE_PRODUCT_MERCHANT_RELATIONSHIP_UPDATE = 'Entity.spy_price_product_merchant_relationship.update';
}
