<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Sales\Business\Model\Order;

use Generated\Shared\Transfer\AddressTransfer;
use Generated\Shared\Transfer\CountryTransfer;
use Generated\Shared\Transfer\ExpenseTransfer;
use Generated\Shared\Transfer\ItemStateTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\OrderTransfer;
use Generated\Shared\Transfer\TaxTotalTransfer;
use Generated\Shared\Transfer\TotalsTransfer;
use Orm\Zed\Country\Persistence\SpyCountry;
use Orm\Zed\Sales\Persistence\Map\SpySalesOrderItemTableMap;
use Orm\Zed\Sales\Persistence\SpySalesOrder;
use Orm\Zed\Sales\Persistence\SpySalesOrderItem;
use Propel\Runtime\ActiveQuery\Criteria;
use Spryker\Zed\Sales\Business\Exception\InvalidSalesOrderException;
use Spryker\Zed\Sales\Dependency\Facade\SalesToOmsInterface;
use Spryker\Zed\Sales\Dependency\Service\SalesToUtilProductServiceInterface;
use Spryker\Zed\Sales\Persistence\SalesQueryContainerInterface;

class OrderHydrator implements OrderHydratorInterface
{
    /**
     * @var \Spryker\Zed\Sales\Persistence\SalesQueryContainerInterface
     */
    protected $queryContainer;

    /**
     * @var \Spryker\Zed\Sales\Dependency\Facade\SalesToOmsInterface
     */
    protected $omsFacade;

    /**
     * @var array|\Spryker\Zed\Sales\Dependency\Plugin\HydrateOrderPluginInterface[]
     */
    protected $hydrateOrderPlugins;

    /**
     * @var \Spryker\Zed\Sales\Dependency\Service\SalesToUtilProductServiceInterface
     */
    protected $utilProductService;

    /**
     * @param \Spryker\Zed\Sales\Persistence\SalesQueryContainerInterface $queryContainer
     * @param \Spryker\Zed\Sales\Dependency\Facade\SalesToOmsInterface $omsFacade
     * @param \Spryker\Zed\Sales\Dependency\Service\SalesToUtilProductServiceInterface $utilProductService
     * @param \Spryker\Zed\Sales\Dependency\Plugin\HydrateOrderPluginInterface[] $hydrateOrderPlugins
     */
    public function __construct(
        SalesQueryContainerInterface $queryContainer,
        SalesToOmsInterface $omsFacade,
        SalesToUtilProductServiceInterface $utilProductService,
        array $hydrateOrderPlugins = []
    ) {
        $this->queryContainer = $queryContainer;
        $this->omsFacade = $omsFacade;
        $this->hydrateOrderPlugins = $hydrateOrderPlugins;
        $this->utilProductService = $utilProductService;
    }

    /**
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    public function getCustomerOrder(OrderTransfer $orderTransfer)
    {
        $orderEntity = $this->getOrderEntity($orderTransfer);

        $this->queryContainer->fillOrderItemsWithLatestStates($orderEntity->getItems());

        $orderTransfer = $this->createOrderTransfer($orderEntity);

        return $orderTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @throws \Spryker\Zed\Sales\Business\Exception\InvalidSalesOrderException
     *
     * @return \Orm\Zed\Sales\Persistence\SpySalesOrder
     */
    protected function getOrderEntity(OrderTransfer $orderTransfer)
    {
        $orderTransfer->requireIdSalesOrder()
            ->requireFkCustomer();

        $orderEntity = $this->queryContainer
            ->querySalesOrderDetails($orderTransfer->getIdSalesOrder())
            ->filterByFkCustomer($orderTransfer->getFkCustomer())
            ->findOne();

        if ($orderEntity === null) {
            throw new InvalidSalesOrderException(sprintf(
                'Order could not be found for ID %s and customer reference %s',
                $orderTransfer->getIdSalesOrder(),
                $orderTransfer->getCustomerReference()
            ));
        }

        return $orderEntity;
    }

    /**
     * @param int $idSalesOrder
     *
     * @throws \Spryker\Zed\Sales\Business\Exception\InvalidSalesOrderException
     *
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    public function hydrateOrderTransferFromPersistenceByIdSalesOrder($idSalesOrder)
    {
        $orderEntity = $this->queryContainer
            ->querySalesOrderDetails($idSalesOrder)
            ->findOne();

        if ($orderEntity === null) {
            throw new InvalidSalesOrderException(
                sprintf(
                    'Order could not be found for ID %s',
                    $idSalesOrder
                )
            );
        }

        $criteria = new Criteria();
        $criteria->addDescendingOrderByColumn(SpySalesOrderItemTableMap::COL_ID_SALES_ORDER_ITEM);

        return $this->hydrateOrderTransferFromPersistenceBySalesOrder($orderEntity);
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity
     *
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    public function hydrateOrderTransferFromPersistenceBySalesOrder(SpySalesOrder $orderEntity): OrderTransfer
    {
        $this->queryContainer->fillOrderItemsWithLatestStates($orderEntity->getItems());

        return $this->createOrderTransfer($orderEntity);
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity
     *
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    protected function applyOrderTransferHydrators(SpySalesOrder $orderEntity)
    {
        $orderTransfer = $this->hydrateBaseOrderTransfer($orderEntity);

        $this->hydrateOrderTotals($orderEntity, $orderTransfer);
        $this->hydrateOrderItemsToOrderTransfer($orderEntity, $orderTransfer);
        $this->hydrateBillingAddressToOrderTransfer($orderEntity, $orderTransfer);
        $this->hydrateShippingAddressToOrderTransfer($orderEntity, $orderTransfer);
        $this->hydrateExpensesToOrderTransfer($orderEntity, $orderTransfer);
        $this->hydrateMissingCustomer($orderEntity, $orderTransfer);

        $orderTransfer->setTotalOrderCount(0);
        if ($orderTransfer->getCustomerReference()) {
            $customerReference = $orderTransfer->getCustomerReference();
            $totalCustomerOrderCount = $this->getTotalCustomerOrderCount($customerReference);
            $orderTransfer->setTotalOrderCount($totalCustomerOrderCount);
        }

        $uniqueProductQuantity = $this->queryContainer
            ->queryCountUniqueProductsForOrder($orderEntity->getIdSalesOrder())
            ->count();

        $orderTransfer->setUniqueProductQuantity($uniqueProductQuantity);

        $orderTransfer = $this->executeHydrateOrderPlugins($orderTransfer);

        return $orderTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    protected function executeHydrateOrderPlugins(OrderTransfer $orderTransfer)
    {
        foreach ($this->hydrateOrderPlugins as $hydrateOrderPlugin) {
            $orderTransfer = $hydrateOrderPlugin->hydrate($orderTransfer);
        }

        return $orderTransfer;
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return void
     */
    public function hydrateOrderItemsToOrderTransfer(SpySalesOrder $orderEntity, OrderTransfer $orderTransfer)
    {
        $criteria = new Criteria();
        $criteria->addAscendingOrderByColumn(SpySalesOrderItemTableMap::COL_ID_SALES_ORDER_ITEM);
        foreach ($orderEntity->getItems($criteria) as $orderItemEntity) {
            $itemTransfer = $this->hydrateOrderItemTransfer($orderItemEntity);
            $orderTransfer->addItem($itemTransfer);
        }
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity
     *
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    public function hydrateBaseOrderTransfer(SpySalesOrder $orderEntity)
    {
        $orderTransfer = new OrderTransfer();
        $orderTransfer->fromArray($orderEntity->toArray(), true);
        $orderTransfer->setCustomerReference($orderEntity->getCustomerReference());
        // Deprecated: Using FK to customer is obsolete, but needed to prevent BC break.
        $orderTransfer->setFkCustomer($orderEntity->getFkCustomer());

        return $orderTransfer;
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrderItem $orderItemEntity
     *
     * @return \Generated\Shared\Transfer\ItemTransfer
     */
    public function hydrateOrderItemTransfer(SpySalesOrderItem $orderItemEntity)
    {
        $itemTransfer = new ItemTransfer();
        $itemTransfer->fromArray($orderItemEntity->toArray(), true);
        $itemTransfer->setProcess($orderItemEntity->getProcess()->getName());

        $itemTransfer->setQuantity($orderItemEntity->getQuantity());
        $itemTransfer->setSumGrossPrice($orderItemEntity->getGrossPrice());
        $itemTransfer->setSumNetPrice($orderItemEntity->getNetPrice());
        $itemTransfer->setSumPrice($orderItemEntity->getPrice());
        $itemTransfer->setSumSubtotalAggregation($orderItemEntity->getSubtotalAggregation());
        $itemTransfer->setRefundableAmount($orderItemEntity->getRefundableAmount());
        $itemTransfer->setSumDiscountAmountAggregation($orderItemEntity->getDiscountAmountAggregation());
        $itemTransfer->setSumDiscountAmountFullAggregation($orderItemEntity->getDiscountAmountFullAggregation());
        $itemTransfer->setSumExpensePriceAggregation($orderItemEntity->getExpensePriceAggregation());
        $itemTransfer->setSumTaxAmount($orderItemEntity->getTaxAmount());
        $itemTransfer->setSumTaxAmountFullAggregation($orderItemEntity->getTaxAmountFullAggregation());
        $itemTransfer->setSumPriceToPayAggregation($orderItemEntity->getPriceToPayAggregation());

        $itemTransfer->setIsOrdered(true);

        $this->deriveOrderItemUnitPrices($itemTransfer);

        $this->hydrateStateHistory($orderItemEntity, $itemTransfer);
        $this->hydrateCurrentSalesOrderItemState($orderItemEntity, $itemTransfer);

        return $itemTransfer;
    }

    /**
     * Unit prices are populated for presentation purposes only. For further calculations use sum prices or properly populated unit prices.
     *
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return void
     */
    protected function deriveOrderItemUnitPrices(ItemTransfer $itemTransfer)
    {
        $unitGrossPrice = $this->roundUnitGrossPrice($itemTransfer->getSumGrossPrice() / $itemTransfer->getQuantity());
        $unitNetPrice = $this->roundUnitNetPrice($itemTransfer->getSumNetPrice() / $itemTransfer->getQuantity());
        $unitPrice = $this->roundUnitPrice($itemTransfer->getSumPrice() / $itemTransfer->getQuantity());
        $unitSubtotalAggregation = $this->roundUnitSubtotalAggregation($itemTransfer->getSumSubtotalAggregation() / $itemTransfer->getQuantity());
        $unitDiscountAmountAggregation = $this->roundUnitDiscountAmountAggregation($itemTransfer->getSumDiscountAmountAggregation() / $itemTransfer->getQuantity());
        $unitDiscountAmountFullAggregation = $this->roundUnitDiscountAmountFullAggregation($itemTransfer->getSumDiscountAmountFullAggregation() / $itemTransfer->getQuantity());
        $unitExpensePriceAggregation = $this->roundUnitExpensePriceAggregation($itemTransfer->getSumExpensePriceAggregation() / $itemTransfer->getQuantity());
        $unitTaxAmount = $this->roundUnitTaxAmount($itemTransfer->getSumTaxAmount() / $itemTransfer->getQuantity());
        $unitTaxAmountFullAggregation = $this->roundUnitTaxAmountFullAggregation($itemTransfer->getSumTaxAmountFullAggregation() / $itemTransfer->getQuantity());
        $unitPriceToPayAggregation = $this->roundUnitPriceToPayAggregation($itemTransfer->getSumPriceToPayAggregation() / $itemTransfer->getQuantity());

        $itemTransfer->setUnitGrossPrice($unitGrossPrice);
        $itemTransfer->setUnitNetPrice($unitNetPrice);
        $itemTransfer->setUnitPrice($unitPrice);
        $itemTransfer->setUnitSubtotalAggregation($unitSubtotalAggregation);
        $itemTransfer->setUnitDiscountAmountAggregation($unitDiscountAmountAggregation);
        $itemTransfer->setUnitDiscountAmountFullAggregation($unitDiscountAmountFullAggregation);
        $itemTransfer->setUnitExpensePriceAggregation($unitExpensePriceAggregation);
        $itemTransfer->setUnitTaxAmount($unitTaxAmount);
        $itemTransfer->setUnitTaxAmountFullAggregation($unitTaxAmountFullAggregation);
        $itemTransfer->setUnitPriceToPayAggregation($unitPriceToPayAggregation);
    }

    /**
     * @param float $unitPriceToPayAggregation
     *
     * @return int
     */
    protected function roundUnitPriceToPayAggregation(float $unitPriceToPayAggregation): int
    {
        return $this->utilProductService->roundPrice($unitPriceToPayAggregation);
    }

    /**
     * @param float $unitTaxAmountFullAggregation
     *
     * @return int
     */
    protected function roundUnitTaxAmountFullAggregation(float $unitTaxAmountFullAggregation): int
    {
        return $this->utilProductService->roundPrice($unitTaxAmountFullAggregation);
    }

    /**
     * @param float $unitTaxAmount
     *
     * @return int
     */
    protected function roundUnitTaxAmount(float $unitTaxAmount): int
    {
        return $this->utilProductService->roundPrice($unitTaxAmount);
    }

    /**
     * @param float $unitExpensePriceAggregation
     *
     * @return int
     */
    protected function roundUnitExpensePriceAggregation(float $unitExpensePriceAggregation): int
    {
        return $this->utilProductService->roundPrice($unitExpensePriceAggregation);
    }

    /**
     * @param float $unitDiscountAmountFullAggregation
     *
     * @return int
     */
    protected function roundUnitDiscountAmountFullAggregation(float $unitDiscountAmountFullAggregation): int
    {
        return $this->utilProductService->roundPrice($unitDiscountAmountFullAggregation);
    }

    /**
     * @param float $unitDiscountAmountAggregation
     *
     * @return int
     */
    protected function roundUnitDiscountAmountAggregation(float $unitDiscountAmountAggregation): int
    {
        return $this->utilProductService->roundPrice($unitDiscountAmountAggregation);
    }

    /**
     * @param float $unitSubtotalAggregation
     *
     * @return int
     */
    protected function roundUnitSubtotalAggregation(float $unitSubtotalAggregation): int
    {
        return $this->utilProductService->roundPrice($unitSubtotalAggregation);
    }

    /**
     * @param float $unitPrice
     *
     * @return int
     */
    protected function roundUnitPrice(float $unitPrice): int
    {
        return $this->utilProductService->roundPrice($unitPrice);
    }

    /**
     * @param float $unitNetPrice
     *
     * @return int
     */
    protected function roundUnitNetPrice(float $unitNetPrice): int
    {
        return $this->utilProductService->roundPrice($unitNetPrice);
    }

    /**
     * @param float $unitGrossPrice
     *
     * @return int
     */
    protected function roundUnitGrossPrice(float $unitGrossPrice): int
    {
        return $this->utilProductService->roundPrice($unitGrossPrice);
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return void
     */
    protected function hydrateBillingAddressToOrderTransfer(SpySalesOrder $orderEntity, OrderTransfer $orderTransfer)
    {
        $countryEntity = $orderEntity->getBillingAddress()->getCountry();

        $billingAddressTransfer = new AddressTransfer();
        $billingAddressTransfer->fromArray($orderEntity->getBillingAddress()->toArray(), true);
        $this->hydrateCountryEntityIntoAddressTransfer($billingAddressTransfer, $countryEntity);

        $orderTransfer->setBillingAddress($billingAddressTransfer);
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return void
     */
    protected function hydrateShippingAddressToOrderTransfer(SpySalesOrder $orderEntity, OrderTransfer $orderTransfer)
    {
        $countryEntity = $orderEntity->getShippingAddress()->getCountry();

        $shippingAddressTransfer = new AddressTransfer();
        $shippingAddressTransfer->fromArray($orderEntity->getShippingAddress()->toArray(), true);
        $this->hydrateCountryEntityIntoAddressTransfer($shippingAddressTransfer, $countryEntity);

        $orderTransfer->setShippingAddress($shippingAddressTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\AddressTransfer $addressTransfer
     * @param \Orm\Zed\Country\Persistence\SpyCountry $countryEntity
     *
     * @return void
     */
    protected function hydrateCountryEntityIntoAddressTransfer(
        AddressTransfer $addressTransfer,
        SpyCountry $countryEntity
    ) {
        $addressTransfer->setIso2Code($countryEntity->getIso2Code());
        $countryTransfer = (new CountryTransfer())->fromArray($countryEntity->toArray(), true);
        $addressTransfer->setCountry($countryTransfer);
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return void
     */
    protected function hydrateExpensesToOrderTransfer(SpySalesOrder $orderEntity, OrderTransfer $orderTransfer)
    {
        foreach ($orderEntity->getExpenses() as $expenseEntity) {
            $expenseTransfer = new ExpenseTransfer();
            $expenseTransfer->fromArray($expenseEntity->toArray(), true);

            $expenseTransfer->setQuantity(1);
            $expenseTransfer->setSumGrossPrice($expenseEntity->getGrossPrice());
            $expenseTransfer->setSumNetPrice($expenseEntity->getNetPrice());
            $expenseTransfer->setSumPrice($expenseEntity->getPrice());
            $expenseTransfer->setSumPriceToPayAggregation($expenseEntity->getPriceToPayAggregation());
            $expenseTransfer->setSumTaxAmount($expenseEntity->getTaxAmount());

            $expenseTransfer->setIsOrdered(true);

            $this->deriveExpenseUnitPrices($expenseTransfer);

            $orderTransfer->addExpense($expenseTransfer);
        }
    }

    /**
     * Unit prices are populated for presentation purposes only. For further calculations use sum prices or properly populated unit prices.
     *
     * @param \Generated\Shared\Transfer\ExpenseTransfer $expenseTransfer
     *
     * @return void
     */
    protected function deriveExpenseUnitPrices(ExpenseTransfer $expenseTransfer)
    {
        $unitGrossPrice = $this->roundUnitGrossPrice($expenseTransfer->getSumGrossPrice() / $expenseTransfer->getQuantity());
        $unitNetPrice = $this->roundUnitNetPrice($expenseTransfer->getSumNetPrice() / $expenseTransfer->getQuantity());
        $unitPrice = $this->roundUnitPrice($expenseTransfer->getSumPrice() / $expenseTransfer->getQuantity());
        $unitPriceToPayAggregation = $this->roundUnitPriceToPayAggregation($expenseTransfer->getSumPriceToPayAggregation() / $expenseTransfer->getQuantity());
        $unitTaxAmount = $this->roundUnitTaxAmount($expenseTransfer->getSumTaxAmount() / $expenseTransfer->getQuantity());

        $expenseTransfer->setUnitGrossPrice($unitGrossPrice);
        $expenseTransfer->setUnitNetPrice($unitNetPrice);
        $expenseTransfer->setUnitPrice($unitPrice);
        $expenseTransfer->setUnitPriceToPayAggregation($unitPriceToPayAggregation);
        $expenseTransfer->setUnitTaxAmount($unitTaxAmount);
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrderItem $orderItemEntity
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return void
     */
    protected function hydrateCurrentSalesOrderItemState(SpySalesOrderItem $orderItemEntity, ItemTransfer $itemTransfer)
    {
        $stateTransfer = new ItemStateTransfer();
        $stateTransfer->fromArray($orderItemEntity->getState()->toArray(), true);
        $stateTransfer->setIdSalesOrder($orderItemEntity->getIdSalesOrderItem());

        $lastStateHistory = $this->queryContainer
            ->queryOmsOrderItemStateHistoryByOrderItemIdAndOmsStateIdDesc(
                $orderItemEntity->getIdSalesOrderItem(),
                $orderItemEntity->getFkOmsOrderItemState()
            )->findOne();

        if ($lastStateHistory) {
            $stateTransfer->setCreatedAt($lastStateHistory->getCreatedAt());
        }

        $itemTransfer->setState($stateTransfer);
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrderItem $orderItemEntity
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     *
     * @return void
     */
    protected function hydrateStateHistory(SpySalesOrderItem $orderItemEntity, ItemTransfer $itemTransfer)
    {
        foreach ($orderItemEntity->getStateHistories() as $stateHistoryEntity) {
            $itemStateTransfer = new ItemStateTransfer();
            $itemStateTransfer->fromArray($stateHistoryEntity->toArray(), true);
            $itemStateTransfer->setName($stateHistoryEntity->getState()->getName());
            $itemStateTransfer->setIdSalesOrder($orderItemEntity->getFkSalesOrder());
            $itemTransfer->addStateHistory($itemStateTransfer);
        }
    }

    /**
     * @param string|null $customerReference
     *
     * @return int
     */
    protected function getTotalCustomerOrderCount($customerReference)
    {
        if ($customerReference === null) {
            return 0;
        }

        $totalOrderCount = $this->queryContainer
            ->querySalesOrder()
            ->filterByCustomerReference($customerReference)
            ->count();

        return $totalOrderCount;
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity $orderEntity
     *
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    protected function createOrderTransfer(SpySalesOrder $orderEntity)
    {
        return $this->applyOrderTransferHydrators($orderEntity);
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return void
     */
    protected function hydrateOrderTotals(SpySalesOrder $orderEntity, OrderTransfer $orderTransfer)
    {
        $salesOrderTotalsEntity = $orderEntity->getLastOrderTotals();

        if (!$salesOrderTotalsEntity) {
            return;
        }

        $totalsTransfer = new TotalsTransfer();

        $taxTotalTransfer = new TaxTotalTransfer();
        $taxTotalTransfer->setAmount($salesOrderTotalsEntity->getTaxTotal());
        $totalsTransfer->setTaxTotal($taxTotalTransfer);

        $totalsTransfer->setExpenseTotal($salesOrderTotalsEntity->getOrderExpenseTotal());
        $totalsTransfer->setRefundTotal($salesOrderTotalsEntity->getRefundTotal());
        $totalsTransfer->setGrandTotal($salesOrderTotalsEntity->getGrandTotal());
        $totalsTransfer->setSubtotal($salesOrderTotalsEntity->getSubtotal());
        $totalsTransfer->setDiscountTotal($salesOrderTotalsEntity->getDiscountTotal());
        $totalsTransfer->setCanceledTotal($salesOrderTotalsEntity->getCanceledTotal());

        $orderTransfer->setTotals($totalsTransfer);
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $orderEntity
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return void
     */
    protected function hydrateMissingCustomer(SpySalesOrder $orderEntity, OrderTransfer $orderTransfer)
    {
        if (!$orderEntity->getCustomer()) {
            $orderTransfer->setCustomerReference(null);
            // Deprecated: Using FK to customer is obsolete, but needed to prevent BC break.
            $orderTransfer->setFkCustomer(null);
        }
    }
}
