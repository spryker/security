<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Quote\Business\Model;

use Generated\Shared\Transfer\QuoteErrorTransfer;
use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Zed\Kernel\Persistence\EntityManager\TransactionTrait;
use Spryker\Zed\Quote\Dependency\Facade\QuoteToStoreFacadeInterface;
use Spryker\Zed\Quote\Persistence\QuoteEntityManagerInterface;
use Spryker\Zed\Quote\Persistence\QuoteRepositoryInterface;
use Spryker\Zed\Store\Business\Model\Exception\StoreNotFoundException;

class QuoteWriter implements QuoteWriterInterface
{
    use TransactionTrait;

    /**
     * @var \Spryker\Zed\Quote\Persistence\QuoteEntityManagerInterface
     */
    protected $quoteEntityManager;

    /**
     * @var \Spryker\Zed\Quote\Dependency\Facade\QuoteToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @var \Spryker\Zed\Quote\Persistence\QuoteRepositoryInterface
     */
    protected $quoteRepository;

    /**
     * @var \Spryker\Zed\Quote\Business\Model\QuoteWriterPluginExecutorInterface
     */
    protected $quoteWriterPluginExecutor;

    /**
     * @param \Spryker\Zed\Quote\Persistence\QuoteEntityManagerInterface $quoteEntityManager
     * @param \Spryker\Zed\Quote\Persistence\QuoteRepositoryInterface $quoteRepository
     * @param \Spryker\Zed\Quote\Business\Model\QuoteWriterPluginExecutorInterface $quoteWriterPluginExecutor
     * @param \Spryker\Zed\Quote\Dependency\Facade\QuoteToStoreFacadeInterface $storeFacade
     */
    public function __construct(
        QuoteEntityManagerInterface $quoteEntityManager,
        QuoteRepositoryInterface $quoteRepository,
        QuoteWriterPluginExecutorInterface $quoteWriterPluginExecutor,
        QuoteToStoreFacadeInterface $storeFacade
    ) {
        $this->quoteEntityManager = $quoteEntityManager;
        $this->storeFacade = $storeFacade;
        $this->quoteRepository = $quoteRepository;
        $this->quoteWriterPluginExecutor = $quoteWriterPluginExecutor;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function save(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        if ($quoteTransfer->getIdQuote()) {
            return $this->update($quoteTransfer);
        }

        return $this->create($quoteTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function create(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        if ($quoteTransfer->getIdQuote()) {
            return $this->createQuoteResponseTransfer($quoteTransfer, false);
        }

        try {
            $quoteTransfer = $this->addStoreToQuote($quoteTransfer);
        } catch (StoreNotFoundException $exception) {
            $quoteErrorTransfer = (new QuoteErrorTransfer())->setMessage(
                $exception->getMessage()
            );

            return $this->createQuoteResponseTransfer($quoteTransfer, false)->addError($quoteErrorTransfer);
        }

        return $this->getTransactionHandler()->handleTransaction(function () use ($quoteTransfer) {
            return $this->executeCreateTransaction($quoteTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function update(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        $quoteByIdTransfer = $this->quoteRepository->findQuoteById($quoteTransfer->getIdQuote());
        if (!$quoteByIdTransfer) {
            return $this->createQuoteResponseTransfer($quoteTransfer, false);
        }

        try {
            $quoteTransfer = $this->addStoreToQuote($quoteTransfer);
        } catch (StoreNotFoundException $exception) {
            $quoteErrorTransfer = (new QuoteErrorTransfer())->setMessage(
                $exception->getMessage()
            );

            return $this->createQuoteResponseTransfer($quoteTransfer, false)->addError($quoteErrorTransfer);
        }

        return $this->getTransactionHandler()->handleTransaction(function () use ($quoteTransfer) {
            return $this->executeUpdateTransaction($quoteTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function executeCreateTransaction(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        $quoteTransfer = $this->quoteWriterPluginExecutor->executeCreateBeforePlugins($quoteTransfer);
        $quoteTransfer = $this->quoteEntityManager->saveQuote($quoteTransfer);
        $quoteTransfer = $this->quoteWriterPluginExecutor->executeCreateAfterPlugins($quoteTransfer);

        return $this->createQuoteResponseTransfer($quoteTransfer, true);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function executeUpdateTransaction(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        $quoteTransfer = $this->quoteWriterPluginExecutor->executeUpdateBeforePlugins($quoteTransfer);
        $quoteTransfer = $this->quoteEntityManager->saveQuote($quoteTransfer);
        $quoteTransfer = $this->quoteWriterPluginExecutor->executeUpdateAfterPlugins($quoteTransfer);

        $quoteResponseTransfer = $this->createQuoteResponseTransfer($quoteTransfer, true);

        return $quoteResponseTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function addStoreToQuote(QuoteTransfer $quoteTransfer): QuoteTransfer
    {
        if (!$quoteTransfer->getStore()) {
            $quoteTransfer->setStore($this->storeFacade->getCurrentStore());

            return $quoteTransfer;
        }

        if ($quoteTransfer->getStore()->getIdStore()) {
            return $quoteTransfer;
        }

        $store = $this->storeFacade->getStoreByName($quoteTransfer->getStore()->getName());
        $quoteTransfer->setStore($store);

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param bool $isSuccessfull
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function createQuoteResponseTransfer(QuoteTransfer $quoteTransfer, bool $isSuccessfull): QuoteResponseTransfer
    {
        $quoteResponseTransfer = (new QuoteResponseTransfer())
            ->setCustomer($quoteTransfer->getCustomer())
            ->setIsSuccessful($isSuccessfull);

        if ($isSuccessfull) {
            $quoteResponseTransfer->setQuoteTransfer($quoteTransfer);
        }

        return $quoteResponseTransfer;
    }
}
