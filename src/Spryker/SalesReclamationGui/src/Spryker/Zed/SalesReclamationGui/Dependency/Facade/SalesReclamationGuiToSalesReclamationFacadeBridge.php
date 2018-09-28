<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesReclamationGui\Dependency\Facade;

use ArrayObject;
use Generated\Shared\Transfer\OrderTransfer;
use Generated\Shared\Transfer\ReclamationCreateRequestTransfer;
use Generated\Shared\Transfer\ReclamationItemTransfer;
use Generated\Shared\Transfer\ReclamationTransfer;

class SalesReclamationGuiToSalesReclamationFacadeBridge implements SalesReclamationGuiToSalesReclamationFacadeInterface
{
    /**
     * @var \Spryker\Zed\SalesReclamation\Business\SalesReclamationFacadeInterface
     */
    protected $salesReclamationFacade;

    /**
     * @param \Spryker\Zed\SalesReclamation\Business\SalesReclamationFacadeInterface $salesReclamationFacade
     */
    public function __construct($salesReclamationFacade)
    {
        $this->salesReclamationFacade = $salesReclamationFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\ReclamationCreateRequestTransfer $reclamationCreateRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer|null
     */
    public function createReclamation(ReclamationCreateRequestTransfer $reclamationCreateRequestTransfer): ?ReclamationTransfer
    {
        return $this->salesReclamationFacade->createReclamation($reclamationCreateRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ReclamationTransfer $reclamationTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer
     */
    public function updateReclamation(ReclamationTransfer $reclamationTransfer): ReclamationTransfer
    {
        return $this->salesReclamationFacade->updateReclamation($reclamationTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ReclamationItemTransfer $reclamationItemTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationItemTransfer
     */
    public function updateReclamationItem(ReclamationItemTransfer $reclamationItemTransfer): ReclamationItemTransfer
    {
        return $this->salesReclamationFacade->updateReclamationItem($reclamationItemTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer
     */
    public function hydrateReclamationByOrder(OrderTransfer $orderTransfer): ReclamationTransfer
    {
        return $this->salesReclamationFacade->hydrateReclamationByOrder($orderTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ReclamationTransfer $reclamationTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer|null
     */
    public function hydrateReclamationByIdReclamation(ReclamationTransfer $reclamationTransfer): ?ReclamationTransfer
    {
        return $this->salesReclamationFacade->hydrateReclamationByIdReclamation($reclamationTransfer);
    }

    /**
     * @return \ArrayObject
     */
    public function getReclamations(): ArrayObject
    {
        return $this->salesReclamationFacade->getReclamations();
    }

    /**
     * @param \Generated\Shared\Transfer\ReclamationItemTransfer $reclamationItemTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationItemTransfer
     */
    public function getReclamationItemById(ReclamationItemTransfer $reclamationItemTransfer): ReclamationItemTransfer
    {
        return $this->salesReclamationFacade->getReclamationItemById($reclamationItemTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\ReclamationTransfer $reclamationTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer
     */
    public function getReclamationById(ReclamationTransfer $reclamationTransfer): ReclamationTransfer
    {
        return $this->salesReclamationFacade->getReclamationById($reclamationTransfer);
    }
}
