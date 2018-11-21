<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductMeasurementUnit\Business;

use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\FilterTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\OrderTransfer;
use Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\SpySalesOrderItemEntityTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\ProductMeasurementUnit\Business\ProductMeasurementUnitBusinessFactory getFactory()
 * @method \Spryker\Zed\ProductMeasurementUnit\Persistence\ProductMeasurementUnitRepositoryInterface getRepository()
 * @method \Spryker\Zed\ProductMeasurementUnit\Persistence\ProductMeasurementUnitEntityManagerInterface getEntityManager()
 */
class ProductMeasurementUnitFacade extends AbstractFacade implements ProductMeasurementUnitFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return string
     */
    public function expandItemGroupKeyWithQuantitySalesUnit(ItemTransfer $itemTransfer): string
    {
        return $this->getFactory()
            ->createProductMeasurementSalesUnitItemGroupKeyGenerator()
            ->expandItemGroupKey($itemTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return int
     */
    public function calculateQuantityNormalizedSalesUnitValue(ItemTransfer $itemTransfer): int
    {
        return $this->getFactory()
            ->createProductMeasurementSalesUnitValue()
            ->calculateQuantityNormalizedSalesUnitValue($itemTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProduct
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer[]
     */
    public function getSalesUnitsByIdProduct(int $idProduct): array
    {
        return $this->getFactory()
            ->createProductMeasurementSalesUnitReader()
            ->getProductMeasurementSalesUnitTransfersByIdProduct($idProduct);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idProductMeasurementSalesUnit
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer
     */
    public function getProductMeasurementSalesUnitTransfer(int $idProductMeasurementSalesUnit): ProductMeasurementSalesUnitTransfer
    {
        return $this->getFactory()
            ->createProductMeasurementSalesUnitReader()
            ->getProductMeasurementSalesUnitTransfer($idProductMeasurementSalesUnit);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $salesUnitsIds
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer[]
     */
    public function getSalesUnitsByIds(array $salesUnitsIds): array
    {
        return $this->getFactory()
            ->createProductMeasurementSalesUnitReader()
            ->getProductMeasurementSalesUnitTransfersByIds($salesUnitsIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer[]
     */
    public function getSalesUnits(): array
    {
        return $this->getFactory()
            ->createProductMeasurementSalesUnitReader()
            ->getProductMeasurementSalesUnitTransfers();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $productMeasurementUnitIds
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementUnitTransfer[]
     */
    public function findProductMeasurementUnitTransfers(array $productMeasurementUnitIds): array
    {
        return $this->getRepository()->findProductMeasurementUnitTransfers($productMeasurementUnitIds);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementUnitTransfer[]
     */
    public function findAllProductMeasurementUnitTransfers(): array
    {
        return $this->getRepository()->findAllProductMeasurementUnitTransfers();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function calculateQuantitySalesUnitValueInQuote(QuoteTransfer $quoteTransfer): QuoteTransfer
    {
        return $this->getFactory()
            ->createProductMeasurementSalesUnitValue()
            ->calculateSalesUnitValueInQuote($quoteTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     *
     * @return \Generated\Shared\Transfer\CartChangeTransfer
     */
    public function expandCartChangeWithQuantitySalesUnit(CartChangeTransfer $cartChangeTransfer): CartChangeTransfer
    {
        return $this->getFactory()
            ->createCartChangeExpander()
            ->expandWithQuantitySalesUnit($cartChangeTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return void
     */
    public function installProductMeasurementUnit(): void
    {
        $this->getFactory()
            ->createProductMeasurementUnitInstaller()
            ->install();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    public function expandOrderWithQuantitySalesUnit(OrderTransfer $orderTransfer): OrderTransfer
    {
        return $this->getFactory()
            ->createOrderExpander()
            ->expandOrderWithQuantitySalesUnit($orderTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param \Generated\Shared\Transfer\SpySalesOrderItemEntityTransfer $salesOrderItemEntity
     *
     * @return \Generated\Shared\Transfer\SpySalesOrderItemEntityTransfer
     */
    public function expandSalesOrderItem(
        ItemTransfer $itemTransfer,
        SpySalesOrderItemEntityTransfer $salesOrderItemEntity
    ): SpySalesOrderItemEntityTransfer {
        return $this->getFactory()
            ->createOrderItemExpander()
            ->expandOrderItem($itemTransfer, $salesOrderItemEntity);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer $productMeasurementSalesUnitTransfer
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer
     */
    public function translateProductMeasurementSalesUnit(
        ProductMeasurementSalesUnitTransfer $productMeasurementSalesUnitTransfer
    ): ProductMeasurementSalesUnitTransfer {
        return $this->getFactory()
            ->createProductMeasurementUnitTranslationExpander()
            ->translateProductMeasurementSalesUnit($productMeasurementSalesUnitTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int[] $productMeasurementUnitIds
     * @param \Generated\Shared\Transfer\FilterTransfer $filterTransfer
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementUnitTransfer[]
     */
    public function findProductMeasurementUnitTransfersByIdsFilteredByOffsetAndLimit(array $productMeasurementUnitIds, FilterTransfer $filterTransfer): array
    {
        return $this->getRepository()->findProductMeasurementUnitTransfersByIdsFilteredByOffsetAndLimit($productMeasurementUnitIds, $filterTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\FilterTransfer $filterTransfer
     *
     * @return \Generated\Shared\Transfer\ProductMeasurementSalesUnitTransfer[]
     */
    public function getSalesUnitsByOffsetAndLimit(FilterTransfer $filterTransfer): array
    {
        return $this->getFactory()
            ->createProductMeasurementSalesUnitReader()
            ->getProductMeasurementSalesUnitTransfersByOffsetAndLimit($filterTransfer);
    }
}
