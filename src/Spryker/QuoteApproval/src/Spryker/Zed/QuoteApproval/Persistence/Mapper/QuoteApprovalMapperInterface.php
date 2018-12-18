<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteApproval\Persistence\Mapper;

use Generated\Shared\Transfer\QuoteApprovalTransfer;
use Orm\Zed\QuoteApproval\Persistence\SpyQuoteApproval;

interface QuoteApprovalMapperInterface
{
    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalTransfer $quoteApprovalTransfer
     * @param \Orm\Zed\QuoteApproval\Persistence\SpyQuoteApproval $spyQuoteApproval
     *
     * @return \Orm\Zed\QuoteApproval\Persistence\SpyQuoteApproval
     */
    public function mapQuoteApprovalTransferToEntity(
        QuoteApprovalTransfer $quoteApprovalTransfer,
        SpyQuoteApproval $spyQuoteApproval
    ): SpyQuoteApproval;

    /**
     * @param \Orm\Zed\QuoteApproval\Persistence\SpyQuoteApproval $spyQuoteApproval
     * @param \Generated\Shared\Transfer\QuoteApprovalTransfer $quoteApprovalTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalTransfer
     */
    public function mapEntityToQuoteApprovalTransfer(
        SpyQuoteApproval $spyQuoteApproval,
        QuoteApprovalTransfer $quoteApprovalTransfer
    ): QuoteApprovalTransfer;
}
