<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Quote\Zed;

use Generated\Shared\Transfer\CustomerTransfer;
use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Client\ZedRequest\ZedRequestClientInterface;

class QuoteStub implements QuoteStubInterface
{
    /**
     * @var \Spryker\Client\ZedRequest\ZedRequestClientInterface
     */
    protected $zedStub;

    /**
     * @param \Spryker\Client\ZedRequest\ZedRequestClientInterface $zedStub
     */
    public function __construct(ZedRequestClientInterface $zedStub)
    {
        $this->zedStub = $zedStub;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Spryker\Shared\Kernel\Transfer\TransferInterface|\Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function persistQuote(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        return $this->zedStub->call('/quote/gateway/persist-quote', $quoteTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Spryker\Shared\Kernel\Transfer\TransferInterface|\Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function getQuoteByCustomer(CustomerTransfer $customerTransfer): QuoteResponseTransfer
    {
        return $this->zedStub->call('/quote/gateway/find-quote-by-customer', $customerTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Spryker\Shared\Kernel\Transfer\TransferInterface|\Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function deleteQuote(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        return $this->zedStub->call('/quote/gateway/delete-quote', $quoteTransfer);
    }
}
