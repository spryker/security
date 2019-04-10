<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\QuoteApprovalExtension\Dependency\Plugin;

use Generated\Shared\Transfer\QuoteTransfer;

interface QuoteApprovalCreatePreCheckPluginInterface
{
    /**
     * Specification:
     * - Returns true if quote applicable for approval - false otherwise.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return bool
     */
    public function check(QuoteTransfer $quoteTransfer): bool;
}
