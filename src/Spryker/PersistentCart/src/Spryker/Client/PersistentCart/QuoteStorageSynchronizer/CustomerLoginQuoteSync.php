<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\PersistentCart\QuoteStorageSynchronizer;

use Generated\Shared\Transfer\CustomerTransfer;
use Generated\Shared\Transfer\QuoteSyncRequestTransfer;
use Spryker\Client\PersistentCart\Dependency\Client\PersistentCartToQuoteClientInterface;
use Spryker\Client\PersistentCart\QuoteUpdatePluginExecutor\QuoteUpdatePluginExecutorInterface;
use Spryker\Client\PersistentCart\Zed\PersistentCartStubInterface;
use Spryker\Shared\Quote\QuoteConfig;

class CustomerLoginQuoteSync implements CustomerLoginQuoteSyncInterface
{
    /**
     * @var \Spryker\Client\PersistentCart\Dependency\Client\PersistentCartToQuoteClientInterface
     */
    protected $quoteClient;

    /**
     * @var \Spryker\Client\PersistentCart\Zed\PersistentCartStubInterface
     */
    protected $persistentCartStub;

    /**
     * @var \Spryker\Client\PersistentCart\QuoteUpdatePluginExecutor\QuoteUpdatePluginExecutorInterface
     */
    protected $quoteUpdatePluginExecutor;

    /**
     * @param \Spryker\Client\PersistentCart\Zed\PersistentCartStubInterface $persistentCartStub
     * @param \Spryker\Client\PersistentCart\Dependency\Client\PersistentCartToQuoteClientInterface $quoteClient
     * @param \Spryker\Client\PersistentCart\QuoteUpdatePluginExecutor\QuoteUpdatePluginExecutorInterface $quoteUpdatePluginExecutor
     */
    public function __construct(
        PersistentCartStubInterface $persistentCartStub,
        PersistentCartToQuoteClientInterface $quoteClient,
        QuoteUpdatePluginExecutorInterface $quoteUpdatePluginExecutor
    ) {
        $this->quoteClient = $quoteClient;
        $this->persistentCartStub = $persistentCartStub;
        $this->quoteUpdatePluginExecutor = $quoteUpdatePluginExecutor;
    }

    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return void
     */
    public function syncQuoteForCustomer(CustomerTransfer $customerTransfer)
    {
        if ($this->quoteClient->getStorageStrategy() !== QuoteConfig::STORAGE_STRATEGY_DATABASE) {
            return;
        }

        $quoteTransfer = $this->quoteClient->getQuote();
        if ($quoteTransfer->getCustomer()) {
            return;
        }

        $quoteSyncRequestTransfer = new QuoteSyncRequestTransfer();
        $quoteSyncRequestTransfer->setQuoteTransfer($quoteTransfer);
        $quoteSyncRequestTransfer->setCustomerTransfer($customerTransfer);
        $quoteResponseTransfer = $this->persistentCartStub->syncStorageQuote($quoteSyncRequestTransfer);
        $this->quoteClient->setQuote($quoteResponseTransfer->getQuoteTransfer());
        $this->quoteUpdatePluginExecutor->executePlugins($quoteResponseTransfer);
    }
}
