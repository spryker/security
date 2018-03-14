<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Sales\Business\Model\Customer;

use ArrayObject;
use Generated\Shared\Transfer\OrderListTransfer;
use Orm\Zed\Sales\Persistence\SpySalesOrder;
use Propel\Runtime\Collection\ObjectCollection;
use Spryker\Zed\Sales\Business\Model\Order\OrderHydratorInterface;
use Spryker\Zed\Sales\Dependency\Facade\SalesToOmsInterface;
use Spryker\Zed\Sales\Persistence\SalesQueryContainerInterface;

class CustomerOrderReader implements CustomerOrderReaderInterface
{
    /**
     * @var \Spryker\Zed\Sales\Persistence\SalesQueryContainerInterface
     */
    protected $queryContainer;

    /**
     * @var \Spryker\Zed\Sales\Business\Model\Order\OrderHydratorInterface
     */
    protected $orderHydrator;

    /**
     * @var \Spryker\Zed\Sales\Dependency\Facade\SalesToOmsInterface
     */
    protected $omsFacade;

    /**
     * @var \Spryker\Zed\SalesExtension\Dependency\Plugin\OrderListFilterPluginInterface[]
     */
    protected $orderListFilterPlugins;

    /**
     * @param \Spryker\Zed\Sales\Persistence\SalesQueryContainerInterface $queryContainer
     * @param \Spryker\Zed\Sales\Business\Model\Order\OrderHydratorInterface $orderHydrator
     * @param \Spryker\Zed\Sales\Dependency\Facade\SalesToOmsInterface|null $omsFacade
     * @param \Spryker\Zed\SalesExtension\Dependency\Plugin\OrderListFilterPluginInterface[] $orderListFilterPlugins
     */
    public function __construct(
        SalesQueryContainerInterface $queryContainer,
        OrderHydratorInterface $orderHydrator,
        SalesToOmsInterface $omsFacade,
        array $orderListFilterPlugins
    ) {
        $this->queryContainer = $queryContainer;
        $this->orderHydrator = $orderHydrator;
        $this->omsFacade = $omsFacade;
        $this->orderListFilterPlugins = $orderListFilterPlugins;
    }

    /**
     * @param \Generated\Shared\Transfer\OrderListTransfer $orderListTransfer
     * @param int $idCustomer
     *
     * @return \Generated\Shared\Transfer\OrderListTransfer
     */
    public function getOrders(OrderListTransfer $orderListTransfer, $idCustomer)
    {
        $orderCollection = $this
            ->queryContainer
            ->queryCustomerOrders($idCustomer, $orderListTransfer->getFilter())
            ->find();

        $orders = $this->hydrateOrderListCollectionTransferFromEntityCollection($orderCollection);

        $orderListTransfer->setOrders($orders);

        $orderListTransfer = $this->applyAdditionalFilters($orderListTransfer);

        return $orderListTransfer;
    }

    /**
     * @param \Propel\Runtime\Collection\ObjectCollection $orderCollection
     *
     * @return \ArrayObject|\Generated\Shared\Transfer\OrderTransfer[]
     */
    protected function hydrateOrderListCollectionTransferFromEntityCollection(ObjectCollection $orderCollection)
    {
        $orders = new ArrayObject();
        foreach ($orderCollection as $salesOrderEntity) {
            if (count($salesOrderEntity->getItems()) == 0) {
                continue;
            }

            if ($this->excludeOrder($salesOrderEntity)) {
                continue;
            }

            $orderTransfer = $this->orderHydrator->hydrateOrderTransferFromPersistenceByIdSalesOrder(
                $salesOrderEntity->getIdSalesOrder()
            );
            $orders->append($orderTransfer);
        }

        return $orders;
    }

    /**
     * @param \Orm\Zed\Sales\Persistence\SpySalesOrder $salesOrderEntity
     *
     * @return bool
     */
    protected function excludeOrder(SpySalesOrder $salesOrderEntity)
    {
        if (!$this->hasOmsFacade()) {
            return false;
        }

        $excludeFromCustomer = $this->omsFacade->isOrderFlaggedExcludeFromCustomer(
            $salesOrderEntity->getIdSalesOrder()
        );

        return $excludeFromCustomer;
    }

    /**
     * @deprecated Will be removed in next major. Make OMS facade dependency required.
     *
     * @return bool
     */
    protected function hasOmsFacade()
    {
        return $this->omsFacade !== null;
    }

    /**
     * @param \Generated\Shared\Transfer\OrderListTransfer $orderListTransfer
     *
     * @return \Generated\Shared\Transfer\OrderListTransfer
     */
    protected function applyAdditionalFilters(OrderListTransfer $orderListTransfer)
    {
        foreach ($this->orderListFilterPlugins as $plugin) {
            $orderListTransfer = $plugin->filterOrders($orderListTransfer);
        }

        return $orderListTransfer;
    }
}
