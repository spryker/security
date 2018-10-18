<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Customer\Dependency\Plugin;

use Generated\Shared\Transfer\CustomerTransfer;

interface CustomerTransferExpanderPluginInterface
{
    /**
     * Specification:
     * - Expands the provided customer transfer object's data and returns the modified object.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Generated\Shared\Transfer\CustomerTransfer
     */
    public function expandTransfer(CustomerTransfer $customerTransfer);
}
