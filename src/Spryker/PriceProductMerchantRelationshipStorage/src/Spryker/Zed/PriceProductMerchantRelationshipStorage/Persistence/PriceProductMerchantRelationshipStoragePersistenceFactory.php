<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence;

use Orm\Zed\MerchantRelationship\Persistence\SpyMerchantRelationshipToCompanyBusinessUnitQuery;
use Orm\Zed\PriceProduct\Persistence\SpyPriceProductStoreQuery;
use Orm\Zed\PriceProductMerchantRelationship\Persistence\SpyPriceProductMerchantRelationshipQuery;
use Orm\Zed\PriceProductMerchantRelationshipStorage\Persistence\SpyPriceProductAbstractMerchantRelationshipStorageQuery;
use Orm\Zed\PriceProductMerchantRelationshipStorage\Persistence\SpyPriceProductConcreteMerchantRelationshipStorageQuery;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;
use Spryker\Zed\PriceProductMerchantRelationshipStorage\PriceProductMerchantRelationshipStorageDependencyProvider;

/**
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\PriceProductMerchantRelationshipStorageConfig getConfig()
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\PriceProductMerchantRelationshipStorage\Persistence\PriceProductMerchantRelationshipStorageRepositoryInterface getRepository()
 */
class PriceProductMerchantRelationshipStoragePersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\PriceProduct\Persistence\SpyPriceProductStoreQuery
     */
    public function getPropelPriceProductStoreQuery(): SpyPriceProductStoreQuery
    {
        return $this->getProvidedDependency(PriceProductMerchantRelationshipStorageDependencyProvider::PROPEL_QUERY_PRICE_PRODUCT_STORE);
    }

    /**
     * @return \Orm\Zed\PriceProductMerchantRelationship\Persistence\SpyPriceProductMerchantRelationshipQuery
     */
    public function getPropelPriceProductMerchantRelationshipQuery(): SpyPriceProductMerchantRelationshipQuery
    {
        return $this->getProvidedDependency(PriceProductMerchantRelationshipStorageDependencyProvider::PROPEL_QUERY_PRICE_PRODUCT_MERCHANT_RELATIONSHIP);
    }

    /**
     * @return \Orm\Zed\MerchantRelationship\Persistence\SpyMerchantRelationshipToCompanyBusinessUnitQuery
     */
    public function getPropelMerchantRelationshipToCompanyBusinessUnitQuery(): SpyMerchantRelationshipToCompanyBusinessUnitQuery
    {
        return $this->getProvidedDependency(PriceProductMerchantRelationshipStorageDependencyProvider::PROPEL_QUERY_MERCHANT_RELATIONSHIP_TO_COMPANY_BUSINESS_UNIT);
    }

    /**
     * @return \Orm\Zed\PriceProductMerchantRelationshipStorage\Persistence\SpyPriceProductConcreteMerchantRelationshipStorageQuery
     */
    public function createPriceProductConcreteMerchantRelationshipStorageQuery(): SpyPriceProductConcreteMerchantRelationshipStorageQuery
    {
        return SpyPriceProductConcreteMerchantRelationshipStorageQuery::create();
    }

    /**
     * @return \Orm\Zed\PriceProductMerchantRelationshipStorage\Persistence\SpyPriceProductAbstractMerchantRelationshipStorageQuery
     */
    public function createPriceProductAbstractMerchantRelationshipStorageQuery(): SpyPriceProductAbstractMerchantRelationshipStorageQuery
    {
        return SpyPriceProductAbstractMerchantRelationshipStorageQuery::create();
    }
}
