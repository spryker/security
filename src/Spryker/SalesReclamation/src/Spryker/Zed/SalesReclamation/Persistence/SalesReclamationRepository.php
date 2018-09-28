<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesReclamation\Persistence;

use ArrayObject;
use Generated\Shared\Transfer\OrderCollectionTransfer;
use Generated\Shared\Transfer\ReclamationItemTransfer;
use Generated\Shared\Transfer\ReclamationTransfer;
use Spryker\Zed\Kernel\Persistence\AbstractRepository;
use Spryker\Zed\SalesReclamation\Persistence\Propel\Mapper\SalesReclamationMapperInterface;

/**
 * @method \Spryker\Zed\SalesReclamation\Persistence\SalesReclamationPersistenceFactory getFactory()
 */
class SalesReclamationRepository extends AbstractRepository implements SalesReclamationRepositoryInterface
{
    /**
     * @param \Generated\Shared\Transfer\ReclamationTransfer $reclamationTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer|null
     */
    public function findReclamationById(ReclamationTransfer $reclamationTransfer): ?ReclamationTransfer
    {
        $reclamationTransfer->requireIdSalesReclamation();

        $reclamationEntities = $this->getFactory()
            ->createSalesReclamationQuery()
            ->leftJoinWithOrder()
            ->leftJoinWithSpySalesReclamationItem()
                ->useSpySalesReclamationItemQuery()
                ->leftJoinWithOrderItem()
            ->endUse()
            ->filterByIdSalesReclamation($reclamationTransfer->getIdSalesReclamation())
            ->find();

        if (!$reclamationEntities->count()) {
            return null;
        }

        return $this->getMapper()->mapEntityToReclamationTransfer($reclamationEntities[0], new ReclamationTransfer());
    }

    /**
     * @param \Generated\Shared\Transfer\ReclamationItemTransfer $reclamationItemTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationItemTransfer|null
     */
    public function findReclamationItemById(ReclamationItemTransfer $reclamationItemTransfer): ?ReclamationItemTransfer
    {
        $reclamationItemTransfer->requireIdSalesReclamationItem();

        $reclamationItemEntities = $this->getFactory()
            ->createSalesReclamationItemQuery()
            ->leftJoinWithOrderItem()
            ->filterByIdSalesReclamationItem($reclamationItemTransfer->getIdSalesReclamationItem())
            ->find();

        if (!$reclamationItemEntities->count()) {
            return null;
        }

        return $this->getMapper()->mapEntityToReclamationItemTransfer($reclamationItemEntities[0], new ReclamationItemTransfer());
    }

    /**
     * @param \Generated\Shared\Transfer\ReclamationTransfer $reclamationTransfer
     *
     * @return \Generated\Shared\Transfer\OrderCollectionTransfer|null
     */
    public function findCreatedOrdersByReclamationId(ReclamationTransfer $reclamationTransfer): ?OrderCollectionTransfer
    {
        $reclamationTransfer->requireIdSalesReclamation();

        $createdSalesOrderEntities = $this->getFactory()
            ->createSalesOrderQuery()
            ->filterByFkSalesReclamation($reclamationTransfer->getIdSalesReclamation())
            ->find();

        if (!$createdSalesOrderEntities->count()) {
            return null;
        }

        return $this->getMapper()->mapSalesOrdersToOrderCollectionTransfer($createdSalesOrderEntities, new OrderCollectionTransfer());
    }

    /**
     * @return \ArrayObject|null
     */
    public function findReclamations(): ?ArrayObject
    {
        $salesReclamationEntities = $this->getFactory()
            ->createSalesReclamationQuery()
            ->leftJoinWithSpySalesReclamationItem()
                ->useSpySalesReclamationItemQuery()
                ->leftJoinWithOrderItem()
            ->endUse()
            ->leftJoinWithOrder()
            ->find();

        if (!$salesReclamationEntities->count()) {
            return null;
        }

        $reclamationTransfers = new ArrayObject();

        foreach ($salesReclamationEntities as $salesReclamationEntity) {
            $reclamationTransfers->append($this->getMapper()->mapEntityToReclamationTransfer($salesReclamationEntity, new ReclamationTransfer()));
        }

        return $reclamationTransfers;
    }

    /**
     * @return \Spryker\Zed\SalesReclamation\Persistence\Propel\Mapper\SalesReclamationMapperInterface
     */
    protected function getMapper(): SalesReclamationMapperInterface
    {
        return $this->getFactory()->createSalesReclamationMapper();
    }
}
