<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Stock\Persistence;

use Orm\Zed\Product\Persistence\Map\SpyProductTableMap;
use Orm\Zed\Stock\Persistence\Map\SpyStockProductTableMap;
use Orm\Zed\Stock\Persistence\Map\SpyStockTableMap;
use Spryker\Zed\Kernel\Persistence\AbstractQueryContainer;

/**
 * @method \Spryker\Zed\Stock\Persistence\StockPersistenceFactory getFactory()
 */
class StockQueryContainer extends AbstractQueryContainer implements StockQueryContainerInterface
{
    /**
     * @api
     *
     * @param int $idProduct
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockProductQuery
     */
    public function queryStockByNeverOutOfStockAllTypes($idProduct)
    {
        return $this->getFactory()->createStockProductQuery()
            ->filterByIsNeverOutOfStock(true)
            ->filterByFkProduct($idProduct);
    }

    /**
     * @api
     *
     * @param int $idProduct
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockProductQuery
     */
    public function queryStockByProducts($idProduct)
    {
        return $this->getFactory()->createStockProductQuery()
            ->filterByFkProduct($idProduct);
    }

    /**
     * @api
     *
     * @param int $idStock
     * @param int $idProduct
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockProductQuery
     */
    public function queryStockProductByStockAndProduct($idStock, $idProduct)
    {
        return $this->getFactory()->createStockProductQuery()
            ->filterByFkStock($idStock)
            ->filterByFkProduct($idProduct);
    }

    /**
     * @api
     *
     * @param string $sku
     * @param string $type
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockProductQuery
     */
    public function queryStockProductBySkuAndType($sku, $type)
    {
        $query = $this->queryAllStockProducts();
        $query
            ->useSpyProductQuery()
            ->filterBySku($sku)
            ->endUse()
            ->useStockQuery()
            ->filterByName($type)
            ->endUse();

        return $query;
    }

    /**
     * @api
     *
     * @param string $name
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockQuery
     */
    public function queryStockByName($name)
    {
        return $this->getFactory()->createStockQuery()
            ->filterByName($name);
    }

    /**
     * @api
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockQuery
     */
    public function queryAllStockTypes()
    {
        return $this->getFactory()->createStockQuery();
    }

    /**
     * @api
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockProductQuery
     */
    public function queryAllStockProducts()
    {
        return $this->getFactory()->createStockProductQuery();
    }

    /**
     * @api
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockProductQuery
     */
    public function queryAllStockProductsJoinedStockJoinedProduct()
    {
        $query = $this->getFactory()->createStockProductQuery()
            ->withColumn(SpyStockProductTableMap::COL_ID_STOCK_PRODUCT, 'id_stock_product')
            ->withColumn(SpyProductTableMap::COL_SKU, 'sku')
            ->withColumn(SpyStockTableMap::COL_ID_STOCK, 'id_stock')
            ->withColumn(SpyStockTableMap::COL_NAME, 'name')
            ->joinStock()
            ->joinSpyProduct();

        return $query;
    }

    /**
     * @api
     *
     * @param int $idStockProduct
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockProductQuery
     */
    public function queryStockProductByIdStockProduct($idStockProduct)
    {
        return $this->getFactory()->createStockProductQuery()
            ->filterByIdStockProduct($idStockProduct);
    }

    /**
     * @api
     *
     * @param int $idProduct
     *
     * @return \Orm\Zed\Stock\Persistence\SpyStockProductQuery
     */
    public function queryStockByIdProduct($idProduct)
    {
        return $this->queryStockByProducts($idProduct)
              ->useStockQuery()
                  ->withColumn(SpyStockTableMap::COL_NAME, 'stockType')
              ->endUse()
                ->useSpyProductQuery()
                ->withColumn(SpyProductTableMap::COL_SKU, 'sku')
            ->endUse();
    }
}
