<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductMeasurementUnit\Persistence;

use Generated\Shared\Transfer\ProductMeasurementBaseUnitTransfer;
use Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer;
use Generated\Shared\Transfer\ProductMeasurementUnitTransfer;
use Generated\Shared\Transfer\SpySalesOrderItemEntityTransfer;
use Orm\Zed\Product\Persistence\Map\SpyProductTableMap;
use Orm\Zed\ProductMeasurementUnit\Persistence\Map\SpyProductMeasurementSalesUnitTableMap;
use Propel\Runtime\Exception\EntityNotFoundException;
use Spryker\Zed\Kernel\Persistence\AbstractRepository;

/**
 * @method \Spryker\Zed\ProductMeasurementUnit\Persistence\ProductMeasurementUnitPersistenceFactory getFactory()
 */
class ProductMeasurementUnitRepository extends AbstractRepository implements ProductMeasurementUnitRepositoryInterface
{
    protected const ERROR_NO_BASE_UNIT_FOR_ID_PRODUCT = 'Product measurement base unit was not found for product ID "%d".';
    protected const ERROR_NO_BASE_UNIT_BY_ID = 'Product measurement base unit was not found by its ID "%d".';
    protected const ERROR_NO_SALES_UNIT_BY_ID = 'Product measurement sales unit was not found by its ID "%d".';

    protected const COL_ID_PRODUCT_MEASUREMENT_UNIT = 'idProductMeasurementUnit';
    protected const COL_CODE = 'code';

    /**
     * @module Store
     *
     * @param int $idProductMeasurementSalesUnit
     *
     * @throws \Propel\Runtime\Exception\EntityNotFoundException
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer
     */
    public function getProductMeasurementSalesUnitTransfer(int $idProductMeasurementSalesUnit): ProductMeasurementSalesUnitTransfer
    {
        $query = $this->getFactory()
            ->createProductMeasurementSalesUnitQuery()
            ->filterByIdProductMeasurementSalesUnit($idProductMeasurementSalesUnit)
            ->joinWithProductMeasurementBaseUnit()
            ->joinWith('ProductMeasurementUnit salesUnitMeasurementUnit')
            ->joinWith('ProductMeasurementBaseUnit.ProductMeasurementUnit baseUnitMeasurementUnit')
            ->leftJoinWithSpyProductMeasurementSalesUnitStore()
            ->leftJoinWith('SpyProductMeasurementSalesUnitStore.SpyStore');

        $productMeasurementSalesUnitEntityCollection = $query->find();
        if (!$productMeasurementSalesUnitEntityCollection) {
            throw new EntityNotFoundException(sprintf(static::ERROR_NO_SALES_UNIT_BY_ID, $idProductMeasurementSalesUnit));
        }

        $productMeasurementSalesUnitEntity = $productMeasurementSalesUnitEntityCollection->getFirst();
        if (!$productMeasurementSalesUnitEntity) {
            throw new EntityNotFoundException(sprintf(static::ERROR_NO_SALES_UNIT_BY_ID, $idProductMeasurementSalesUnit));
        }

        return $this->getFactory()
            ->createProductMeasurementUnitMapper()
            ->mapProductMeasurementSalesUnitTransfer(
                $productMeasurementSalesUnitEntity,
                new ProductMeasurementSalesUnitTransfer()
            );
    }

    /**
     * @module Store
     *
     * @param int $idProduct
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer[]
     */
    public function getProductMeasurementSalesUnitTransfersByIdProduct(int $idProduct): array
    {
        $query = $this->getFactory()
            ->createProductMeasurementSalesUnitQuery()
            ->filterByFkProduct($idProduct)
            ->joinWithProductMeasurementBaseUnit()
            ->joinWith('ProductMeasurementUnit salesUnitMeasurementUnit')
            ->joinWith('ProductMeasurementBaseUnit.ProductMeasurementUnit baseUnitMeasurementUnit')
            ->leftJoinWithSpyProductMeasurementSalesUnitStore()
            ->leftJoinWith('SpyProductMeasurementSalesUnitStore.SpyStore');

        $productMeasurementSalesUnitEntityCollection = $query->find();
        $productMeasurementSalesUnitTransfers = [];
        $mapper = $this->getFactory()->createProductMeasurementUnitMapper();
        foreach ($productMeasurementSalesUnitEntityCollection as $productMeasurementSalesUnitEntity) {
            $productMeasurementSalesUnitTransfers[] = $mapper->mapProductMeasurementSalesUnitTransfer(
                $productMeasurementSalesUnitEntity,
                new ProductMeasurementSalesUnitTransfer()
            );
        }

        return $productMeasurementSalesUnitTransfers;
    }

    /**
     * @uses SpyStoreQuery
     *
     * @param int[] $salesUnitsIds
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer[]
     */
    public function getProductMeasurementSalesUnitTransfersByIds(array $salesUnitsIds): array
    {
        $query = $this->getFactory()
            ->createProductMeasurementSalesUnitQuery()
            ->filterByIdProductMeasurementSalesUnit_In($salesUnitsIds)
            ->joinWithProductMeasurementBaseUnit()
            ->joinWith('ProductMeasurementUnit salesUnitMeasurementUnit')
            ->joinWith('ProductMeasurementBaseUnit.ProductMeasurementUnit baseUnitMeasurementUnit')
            ->leftJoinWithSpyProductMeasurementSalesUnitStore()
            ->leftJoinWith('SpyProductMeasurementSalesUnitStore.SpyStore');

        $productMeasurementSalesUnitEntityCollection = $query->find();
        $productMeasurementSalesUnitTransfers = [];
        $mapper = $this->getFactory()->createProductMeasurementUnitMapper();
        foreach ($productMeasurementSalesUnitEntityCollection as $productMeasurementSalesUnitEntity) {
            $productMeasurementSalesUnitTransfers[] = $mapper->mapProductMeasurementSalesUnitTransfer(
                $productMeasurementSalesUnitEntity,
                new ProductMeasurementSalesUnitTransfer()
            );
        }

        return $productMeasurementSalesUnitTransfers;
    }

    /**
     * @param int $idProductMeasurementBaseUnit
     *
     * @throws \Propel\Runtime\Exception\EntityNotFoundException
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementBaseUnitTransfer
     */
    public function getProductMeasurementBaseUnitTransfer(int $idProductMeasurementBaseUnit): ProductMeasurementBaseUnitTransfer
    {
        $query = $this->getFactory()
            ->createProductMeasurementBaseUnitQuery()
            ->filterByIdProductMeasurementBaseUnit($idProductMeasurementBaseUnit)
            ->joinWithProductMeasurementUnit();

        $productMeasurementBaseUnitEntity = $query->findOne();
        if (!$productMeasurementBaseUnitEntity) {
            throw new EntityNotFoundException(sprintf(static::ERROR_NO_BASE_UNIT_BY_ID, $idProductMeasurementBaseUnit));
        }

        return $this->getFactory()
            ->createProductMeasurementUnitMapper()
            ->mapProductMeasurementBaseUnitTransfer(
                $productMeasurementBaseUnitEntity,
                new ProductMeasurementBaseUnitTransfer()
            );
    }

    /**
     * @param int[] $productMeasurementUnitIds
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementUnitTransfer[]
     */
    public function findProductMeasurementUnitTransfers(array $productMeasurementUnitIds): array
    {
        if (!$productMeasurementUnitIds) {
            return [];
        }

        $query = $this->getFactory()
            ->createProductMeasurementUnitQuery()
            ->filterByIdProductMeasurementUnit_In($productMeasurementUnitIds);

        $productMeasurementUnitEntityCollection = $query->find();

        $productMeasurementUnitTransfers = [];
        $mapper = $this->getFactory()->createProductMeasurementUnitMapper();
        foreach ($productMeasurementUnitEntityCollection as $productMeasurementUnitEntity) {
            $productMeasurementUnitTransfers[] = $mapper->mapProductMeasurementUnitTransfer(
                $productMeasurementUnitEntity,
                new ProductMeasurementUnitTransfer()
            );
        }

        return $productMeasurementUnitTransfers;
    }

    /**
     * @param int $idSalesOrder
     *
     * @return \Generated\Shared\Transfer\SpySalesOrderItemEntityTransfer[]
     */
    public function querySalesOrderItemsByIdSalesOrder($idSalesOrder): array
    {
        $salesOrderItemEntities = $this->getFactory()
            ->getSalesOrderItemQuery()
            ->filterByFkSalesOrder($idSalesOrder)
            ->find();

        $spySalesOrderItemEntityTransfers = [];
        $mapper = $this->getFactory()->createSalesOrderItemMapper();
        foreach ($salesOrderItemEntities as $salesOrderItemEntity) {
            $spySalesOrderItemEntityTransfers[] = $mapper->mapSalesOrderItemTransfer(
                $salesOrderItemEntity,
                new SpySalesOrderItemEntityTransfer()
            );
        }

        return $spySalesOrderItemEntityTransfers;
    }

    /**
     * @return \Generated\Shared\Transfer\ProductMeasurementUnitTransfer[]
     */
    public function findAllProductMeasurementUnitTransfers(): array
    {
        $query = $this->getFactory()->createProductMeasurementUnitQuery();
        $productMeasurementUnitEntityCollection = $query->find();

        $productMeasurementUnitTransfers = [];
        $mapper = $this->getFactory()->createProductMeasurementUnitMapper();
        foreach ($productMeasurementUnitEntityCollection as $productMeasurementUnitEntity) {
            $productMeasurementUnitTransfers[] = $mapper->mapProductMeasurementUnitTransfer(
                $productMeasurementUnitEntity,
                new ProductMeasurementUnitTransfer()
            );
        }

        return $productMeasurementUnitTransfers;
    }

    /**
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer[]
     */
    public function getProductMeasurementSalesUnitTransfers(): array
    {
        $query = $this->getFactory()
            ->createProductMeasurementSalesUnitQuery()
            ->joinWithProductMeasurementBaseUnit()
            ->joinWith('ProductMeasurementUnit salesUnitMeasurementUnit')
            ->joinWith('ProductMeasurementBaseUnit.ProductMeasurementUnit baseUnitMeasurementUnit')
            ->leftJoinWithSpyProductMeasurementSalesUnitStore()
            ->leftJoinWith('SpyProductMeasurementSalesUnitStore.SpyStore');

        $productMeasurementSalesUnitEntityCollection = $query->find();
        $productMeasurementSalesUnitTransfers = [];
        $mapper = $this->getFactory()->createProductMeasurementUnitMapper();
        foreach ($productMeasurementSalesUnitEntityCollection as $productMeasurementSalesUnitEntity) {
            $productMeasurementSalesUnitTransfers[] = $mapper->mapProductMeasurementSalesUnitTransfer(
                $productMeasurementSalesUnitEntity,
                new ProductMeasurementSalesUnitTransfer()
            );
        }

        return $productMeasurementSalesUnitTransfers;
    }

    /**
     * @module Product
     *
     * @param string[] $productConcreteSkus
     * @param int $idStore
     *
     * @return int[]
     */
    public function findIndexedStoreAwareDefaultProductMeasurementSalesUnitIds(array $productConcreteSkus, int $idStore): array
    {
        $productMeasurementSalesUnitQuery = $this->getFactory()
            ->createProductMeasurementSalesUnitQuery();
        $productMeasurementSalesUnitQuery
            ->filterByIsDefault(true)
            ->useProductQuery()
                ->filterBySku_In($productConcreteSkus)
            ->endUse()
            ->useSpyProductMeasurementSalesUnitStoreQuery()
                ->filterByFkStore($idStore)
            ->endUse()
            ->select([SpyProductMeasurementSalesUnitTableMap::COL_ID_PRODUCT_MEASUREMENT_SALES_UNIT, SpyProductTableMap::COL_SKU]);

        return $productMeasurementSalesUnitQuery->find()
            ->toKeyValue(SpyProductTableMap::COL_SKU, SpyProductMeasurementSalesUnitTableMap::COL_ID_PRODUCT_MEASUREMENT_SALES_UNIT);
    }
}
