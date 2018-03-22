<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ShipmentCartConnector\Dependency\Facade;

use Generated\Shared\Transfer\QuoteTransfer;

class ShipmentCartConnectorToShipmentFacadeBridge implements ShipmentCartConnectorToShipmentFacadeInterface
{
    /**
     * @var \Spryker\Zed\Shipment\Business\ShipmentFacadeInterface
     */
    protected $shipmentFacade;

    /**
     * @param \Spryker\Zed\Shipment\Business\ShipmentFacadeInterface $shipmentFacade
     */
    public function __construct($shipmentFacade)
    {
        $this->shipmentFacade = $shipmentFacade;
    }

    /**
     * @param int $idShipmentMethod
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\ShipmentMethodTransfer|null
     */
    public function findAvailableMethodById($idShipmentMethod, QuoteTransfer $quoteTransfer)
    {
        return $this->shipmentFacade->findAvailableMethodById($idShipmentMethod, $quoteTransfer);
    }

    /**
     * @return string
     */
    public function getShipmentExpenseTypeIdentifier()
    {
        return $this->shipmentFacade->getShipmentExpenseTypeIdentifier();
    }
}
