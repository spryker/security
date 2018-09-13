<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Sales\Business\Model\Order;

use Generated\Shared\Transfer\OrderTransfer;
use Spryker\Zed\Sales\Persistence\SalesQueryContainerInterface;
use Spryker\Zed\Sales\Persistence\SalesRepositoryInterface;

class OrderReader implements OrderReaderInterface
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
     * @var \Spryker\Zed\Sales\Persistence\SalesRepositoryInterface
     */
    protected $salesRepository;

    /**
     * @param \Spryker\Zed\Sales\Persistence\SalesQueryContainerInterface $queryContainer
     * @param \Spryker\Zed\Sales\Business\Model\Order\OrderHydratorInterface $orderHydrator
     * @param \Spryker\Zed\Sales\Persistence\SalesRepositoryInterface $salesRepository
     */
    public function __construct(
        SalesQueryContainerInterface $queryContainer,
        OrderHydratorInterface $orderHydrator,
        SalesRepositoryInterface $salesRepository
    ) {
        $this->queryContainer = $queryContainer;
        $this->orderHydrator = $orderHydrator;
        $this->salesRepository = $salesRepository;
    }

    /**
     * @param int $idSalesOrder
     *
     * @return string[]
     */
    public function getDistinctOrderStates($idSalesOrder)
    {
        $orderItems = $this->queryContainer
            ->querySalesOrderItemsByIdSalesOrder($idSalesOrder)
            ->find();

        $states = [];
        foreach ($orderItems as $orderItem) {
            $states[$orderItem->getState()->getName()] = $orderItem->getState()->getName();
        }

        return $states;
    }

    /**
     * @param int $idSalesOrderItem
     *
     * @return \Generated\Shared\Transfer\OrderTransfer|null
     */
    public function findOrderByIdSalesOrderItem($idSalesOrderItem)
    {
        $orderItem = $this->queryContainer
            ->querySalesOrderItem()
            ->filterByIdSalesOrderItem($idSalesOrderItem)
            ->findOne();

        if (!$orderItem) {
            return null;
        }

        return $this->orderHydrator->hydrateBaseOrderTransfer($orderItem->getOrder());
    }

    /**
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return \Generated\Shared\Transfer\OrderTransfer
     */
    public function getCustomerOrderByOrderReference(OrderTransfer $orderTransfer): OrderTransfer
    {
        $idSalesOrder = $this->salesRepository->findCustomerOrderIdByOrderReference(
            $orderTransfer->requireCustomerReference()->getCustomerReference(),
            $orderTransfer->requireOrderReference()->getOrderReference()
        );

        if ($idSalesOrder === null) {
            return new OrderTransfer();
        }

        return $this->orderHydrator->hydrateOrderTransferFromPersistenceByIdSalesOrder($idSalesOrder);
    }
}
