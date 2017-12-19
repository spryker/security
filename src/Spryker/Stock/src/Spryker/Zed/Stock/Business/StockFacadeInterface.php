<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Stock\Business;

use Generated\Shared\Transfer\ProductConcreteTransfer;
use Generated\Shared\Transfer\StockProductTransfer;
use Generated\Shared\Transfer\StoreTransfer;
use Generated\Shared\Transfer\TypeTransfer;

interface StockFacadeInterface
{
    /**
     * Specification:
     * - Checks if the concrete product with the provided SKU has any stock type that is set as "never out of stock".
     *
     * @api
     *
     * @param $skum
     * @param \Generated\Shared\Transfer\StoreTransfer|null $storeTransfer
     *
     * @return bool
     */
    public function isNeverOutOfStock($skum,  StoreTransfer $storeTransfer = null);

    /**
     * Specification:
     * - Returns the total stock amount of the concrete product for all its available stock types.
     *
     * @api
     *
     * @param string $sku
     *
     * @return int
     */
    public function calculateStockForProduct($sku);

    /**
     * @api
     *
     * @param string $sku
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     *
     * @return int
     */
    public function calculateProductStockForStore($sku,  StoreTransfer $storeTransfer);

    /**
     * Specification:
     * - Persists a new stock type entity to database.
     * - Touches the newly created stock type.
     * - Returns the ID of the new stock type entity.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\TypeTransfer $stockTypeTransfer
     *
     * @return int
     */
    public function createStockType(TypeTransfer $stockTypeTransfer);

    /**
     * Specification:
     * - Persists a new stock product entity in database for the given product and stock type.
     * - If the product already have stock assigned in the given stock type, then it throws an exception.
     * - Touches the newly created stock product.
     * - Returns the ID of the new stock product entity.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\StockProductTransfer $transferStockProduct
     *
     * @return int
     */
    public function createStockProduct(StockProductTransfer $transferStockProduct);

    /**
     * Specification:
     * - Updates an existing stock product entity with the provided stock data.
     * - Touches the stock product.
     * - Returns the ID of the stock product entity.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\StockProductTransfer $stockProductTransfer
     *
     * @return int
     */
    public function updateStockProduct(StockProductTransfer $stockProductTransfer);

    /**
     * Specification:
     * - Decrements stock amount of the given concrete product for the given stock type.
     * - Touches the stock product.
     *
     * @api
     *
     * @param string $sku
     * @param string $stockType
     * @param int $decrementBy
     *
     * @return void
     */
    public function decrementStockProduct($sku, $stockType, $decrementBy = 1);

    /**
     * Specification:
     * - Increments stock amount of the given concrete product for the given stock type.
     * - Touches the stock product.
     *
     * @api
     *
     * @param string $sku
     * @param string $stockType
     * @param int $incrementBy
     *
     * @return void
     */
    public function incrementStockProduct($sku, $stockType, $incrementBy = 1);

    /**
     * Specification:
     * - Checks if the given concrete product for the given stock type has positive amount.
     *
     * @api
     *
     * @param string $sku
     * @param string $stockType
     *
     * @return bool
     */
    public function hasStockProduct($sku, $stockType);

    /**
     * Specification:
     * - Processes all provided stocks of the concrete product transfer
     * - If a stock entry from the collection doesn't exists for the product, then it will be newly created.
     * - If a stock entry from the collection exists for the product, then it will be updated with the provided data.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function persistStockProductCollection(ProductConcreteTransfer $productConcreteTransfer);

    /**
     * Specification:
     * - Expands concrete product transfer (by the ID of the product) with it's stock information from the database.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     *
     * @return \Generated\Shared\Transfer\ProductConcreteTransfer
     */
    public function expandProductConcreteWithStocks(ProductConcreteTransfer $productConcreteTransfer);

    /**
     *
     * Specification:
     *  - Returns all available stock types
     *
     * @api
     *
     * @return array
     */
    public function getAvailableStockTypes();

    /**
     *
     * Specification:
     *  - Returns stock product by givent id product
     *
     * @api
     *
     * @param int $idProductConcrete
     *
     * @return \Generated\Shared\Transfer\StockProductTransfer[]
     */
    public function getStockProductsByIdProduct($idProductConcrete);

    /**
     *
     * Specification:
     *  - Returns stock mapping per store/warehouse pair
     *
     * @api
     *
     * @return array
     */
    public function getWarehouseToStoreMapping();

    /**
     *
     * @api
     *
     * @return array
     */
    public function getStoreToWarehouseMapping();
}
