<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ProductAvailabilitiesRestApi\Processor\Mapper;

use Generated\Shared\Transfer\RestConcreteProductAvailabilityAttributesTransfer;
use Generated\Shared\Transfer\SpyAvailabilityEntityTransfer;

interface ConcreteProductAvailabilitiesResourceMapperInterface
{
    /**
     * @param \Generated\Shared\Transfer\SpyAvailabilityEntityTransfer $availabilityEntityTransfer
     *
     * @return \Generated\Shared\Transfer\RestConcreteProductAvailabilityAttributesTransfer
     */
    public function mapAvailabilityTransferToRestConcreteProductAvailabilityAttributesTransfer(SpyAvailabilityEntityTransfer $availabilityEntityTransfer): RestConcreteProductAvailabilityAttributesTransfer;
}
