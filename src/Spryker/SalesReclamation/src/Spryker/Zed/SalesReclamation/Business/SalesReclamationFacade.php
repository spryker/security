<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\SalesReclamation\Business;

use Generated\Shared\Transfer\OrderTransfer;
use Generated\Shared\Transfer\ReclamationCreateRequestTransfer;
use Generated\Shared\Transfer\ReclamationTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\SalesReclamation\Business\SalesReclamationBusinessFactory getFactory()
 * @method \Spryker\Zed\SalesReclamation\Persistence\SalesReclamationEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\SalesReclamation\Persistence\SalesReclamationRepositoryInterface getRepository()
 */
class SalesReclamationFacade extends AbstractFacade implements SalesReclamationFacadeInterface
{
    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ReclamationCreateRequestTransfer $reclamationCreateRequestTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer
     */
    public function createReclamation(ReclamationCreateRequestTransfer $reclamationCreateRequestTransfer): ReclamationTransfer
    {
        return $this->getFactory()
            ->createReclamationWriter()
            ->createReclamation($reclamationCreateRequestTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ReclamationTransfer $reclamationTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer
     */
    public function closeReclamation(ReclamationTransfer $reclamationTransfer): ReclamationTransfer
    {
        return $this->getFactory()
            ->createReclamationWriter()
            ->closeReclamation($reclamationTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\OrderTransfer $orderTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer
     */
    public function mapOrderTransferToReclamationTransfer(
        OrderTransfer $orderTransfer,
        ReclamationTransfer $reclamationTransfer
    ): ReclamationTransfer {
        return $this->getFactory()
            ->createReclamationMapper()
            ->mapOrderTransferToReclamationTransfer($orderTransfer, $reclamationTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ReclamationTransfer $reclamationTransfer
     *
     * @return \Generated\Shared\Transfer\ReclamationTransfer
     *
     * @throws \Spryker\Zed\SalesReclamation\Business\Exception\ReclamationNotFoundException
     */
    public function getReclamationById(ReclamationTransfer $reclamationTransfer): ReclamationTransfer
    {
        return $this->getFactory()->createReclamationReader()->getReclamationById($reclamationTransfer);
    }
}
