<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductPageSearch\Persistence;

use Generated\Shared\Transfer\LocaleTransfer;
use Orm\Zed\Category\Persistence\Map\SpyCategoryNodeTableMap;
use Orm\Zed\PriceProduct\Persistence\Map\SpyPriceProductTableMap;
use Orm\Zed\Product\Persistence\Map\SpyProductAbstractLocalizedAttributesTableMap;
use Orm\Zed\Product\Persistence\Map\SpyProductTableMap;
use Orm\Zed\ProductCategory\Persistence\Map\SpyProductCategoryTableMap;
use Orm\Zed\ProductImage\Persistence\Map\SpyProductImageSetTableMap;
use Orm\Zed\Url\Persistence\Map\SpyUrlTableMap;
use Propel\Runtime\ActiveQuery\ModelCriteria;
use Spryker\Zed\Kernel\Persistence\AbstractQueryContainer;
use Spryker\Zed\PropelOrm\Business\Runtime\ActiveQuery\Criteria;

/**
 * @method \Spryker\Zed\ProductPageSearch\Persistence\ProductPageSearchPersistenceFactory getFactory()
 */
class ProductPageSearchQueryContainer extends AbstractQueryContainer implements ProductPageSearchQueryContainerInterface
{
    const FK_PRODUCT_ABSTRACT = 'fkProductAbstract';
    const FK_CATEGORY = 'fkCategory';

    /**
     * TODO locale condition does not work here for SpyProducts
     *
     * @api
     *
     * @param array $productAbstractIds
     *
     * @return \Orm\Zed\Product\Persistence\SpyProductAbstractLocalizedAttributesQuery
     */
    public function queryProductAbstractByIds(array $productAbstractIds)
    {
        $query = $this
            ->getFactory()
            ->getProductQueryContainer()
            ->queryAllProductAbstractLocalizedAttributes()
            ->joinWithLocale()
            ->joinWithSpyProductAbstract()
            ->joinWith('SpyProductAbstract.SpyProduct')
            ->joinWith('SpyProduct.SpyProductLocalizedAttributes')
            ->joinWith('SpyProductAbstract.SpyProductCategory')
            ->joinWith('SpyProductCategory.SpyCategory')
            ->joinWith('SpyCategory.Node')
            ->join('SpyProductAbstract.SpyUrl')
            ->join('SpyProductAbstract.SpyProductImageSet', Criteria::LEFT_JOIN)
            ->addJoinCondition('SpyUrl', 'spy_url.fk_locale = ' . SpyProductAbstractLocalizedAttributesTableMap::COL_FK_LOCALE)
            ->addJoinCondition('SpyProductImageSet', sprintf('(spy_product_image_set.fk_locale = %s or spy_product_image_set.fk_locale is null)', SpyProductAbstractLocalizedAttributesTableMap::COL_FK_LOCALE))
            ->addJoinCondition('SpyProductLocalizedAttributes', 'SpyProductLocalizedAttributes.fk_locale = ' . SpyProductAbstractLocalizedAttributesTableMap::COL_FK_LOCALE)
            ->filterByFkProductAbstract_In($productAbstractIds)
            ->setFormatter(ModelCriteria::FORMAT_ARRAY)
            ->withColumn(SpyUrlTableMap::COL_URL, 'url')
            ->withColumn(SpyProductImageSetTableMap::COL_ID_PRODUCT_IMAGE_SET, 'id_image_set');

        return $query;
    }

    /**
     * @api
     *
     * @param array $productAbstractIds
     *
     * @return \Orm\Zed\ProductPageSearch\Persistence\SpyProductAbstractPageSearchQuery
     */
    public function queryProductAbstractSearchPageByIds(array $productAbstractIds)
    {
        return $this->getFactory()
            ->createProductAbstractPageSearch()
            ->filterByFkProductAbstract_In($productAbstractIds);
    }

    /**
     * @api
     *
     * @param array $productIds
     *
     * @return \Orm\Zed\Product\Persistence\SpyProductQuery
     */
    public function queryProductAbstractIdsByProductIds(array $productIds)
    {
        return $this->getFactory()
            ->getProductQueryContainer()
            ->queryProduct()
            ->select(SpyProductTableMap::COL_FK_PRODUCT_ABSTRACT)
            ->filterByIdProduct_In($productIds);
    }

    /**
     * @api
     *
     * @param array $priceTypeIds
     *
     * @return \Orm\Zed\PriceStorage\Persistence\SpyPriceAbstractStorageQuery|\Propel\Runtime\ActiveQuery\ModelCriteria
     */
    public function queryAllProductAbstractIdsByPriceTypeIds(array $priceTypeIds)
    {
        return $this->getFactory()
            ->getPriceQueryContainer()
            ->queryPriceProduct()
            ->select([SpyPriceProductTableMap::COL_FK_PRODUCT_ABSTRACT])
            ->addAnd(SpyPriceProductTableMap::COL_FK_PRODUCT_ABSTRACT, null, Criteria::NOT_EQUAL)
            ->filterByFkPriceType_In($priceTypeIds);
    }

    /**
     * @api
     *
     * @param array $priceProductIds
     *
     * @return \Orm\Zed\PriceStorage\Persistence\SpyPriceAbstractStorageQuery|\Propel\Runtime\ActiveQuery\ModelCriteria
     */
    public function queryAllProductAbstractIdsByPriceProductIds(array $priceProductIds)
    {
        return $this->getFactory()
            ->getPriceQueryContainer()
            ->queryPriceProduct()
            ->select([SpyPriceProductTableMap::COL_FK_PRODUCT_ABSTRACT])
            ->addAnd(SpyPriceProductTableMap::COL_FK_PRODUCT_ABSTRACT, null, Criteria::NOT_EQUAL)
            ->filterByIdPriceProduct_In($priceProductIds);
    }

    /**
     * @api
     *
     * @param array $productImageSetToProductImageIds
     *
     * @return \Orm\Zed\ProductImage\Persistence\SpyProductImageSetToProductImageQuery
     */
    public function queryProductAbstractIdsByProductImageSetToProductImageIds(array $productImageSetToProductImageIds)
    {
        $query = $this->getFactory()->getProductImageQueryContainer()
            ->queryProductImageSetToProductImage()
            ->filterByIdProductImageSetToProductImage_In($productImageSetToProductImageIds)
            ->innerJoinSpyProductImageSet()
            ->withColumn('DISTINCT ' . SpyProductImageSetTableMap::COL_FK_PRODUCT_ABSTRACT, static::FK_PRODUCT_ABSTRACT)
            ->select([static::FK_PRODUCT_ABSTRACT])
            ->addAnd(SpyProductImageSetTableMap::COL_FK_PRODUCT_ABSTRACT, null, ModelCriteria::NOT_EQUAL);

        return $query;
    }

    /**
     * @api
     *
     * @param array $productImageIds
     *
     * @return \Orm\Zed\ProductImage\Persistence\SpyProductImageSetToProductImageQuery
     */
    public function queryProductAbstractIdsByProductImageIds(array $productImageIds)
    {
        return $this->getFactory()->getProductImageQueryContainer()
            ->queryProductImageSetToProductImage()
            ->filterByFkProductImage_In($productImageIds)
            ->innerJoinSpyProductImageSet()
            ->withColumn('DISTINCT ' . SpyProductImageSetTableMap::COL_FK_PRODUCT_ABSTRACT, static::FK_PRODUCT_ABSTRACT)
            ->select([static::FK_PRODUCT_ABSTRACT])
            ->addAnd(SpyProductImageSetTableMap::COL_FK_PRODUCT_ABSTRACT, null, ModelCriteria::NOT_EQUAL);
    }

    /**
     * @api
     *
     * @param int $idNode
     *
     * @return \Orm\Zed\Category\Persistence\SpyCategoryClosureTableQuery
     */
    public function queryAllCategoryIdsByNodeId($idNode)
    {
        return $this->getFactory()
            ->getCategoryQueryContainer()
            ->queryClosureTableByNodeId($idNode)
            ->joinDescendantNode()
            ->withColumn(SpyCategoryNodeTableMap::COL_FK_CATEGORY, static::FK_CATEGORY)
            ->select([static::FK_CATEGORY]);
    }

    /**
     * @api
     *
     * @param array $categoryIds
     *
     * @return \Orm\Zed\ProductCategory\Persistence\SpyProductCategoryQuery
     */
    public function queryProductAbstractIdsByCategoryIds(array $categoryIds)
    {
        return $this->getFactory()
            ->getProductCategoryQueryContainer()
            ->queryProductCategoryMappings()
            ->filterByFkCategory_In($categoryIds)
            ->select(SpyProductCategoryTableMap::COL_FK_PRODUCT_ABSTRACT);
    }

    /**
     * @api
     *
     * @param \Generated\Shared\Transfer\LocaleTransfer $localeTransfer
     *
     * @return \Orm\Zed\Category\Persistence\SpyCategoryAttributeQuery
     */
    public function queryCategoryAttributesByLocale(LocaleTransfer $localeTransfer)
    {
        return $this->getFactory()
            ->getCategoryAttributeQuery()
            ->queryAllCategoryAttributes()
            ->filterByFkLocale($localeTransfer->getIdLocale());
    }
}
