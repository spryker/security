<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteRequest\Business\Sender;

use Generated\Shared\Transfer\MessageTransfer;
use Generated\Shared\Transfer\QuoteRequestCriteriaTransfer;
use Generated\Shared\Transfer\QuoteRequestResponseTransfer;
use Generated\Shared\Transfer\QuoteRequestTransfer;
use Spryker\Shared\QuoteRequest\QuoteRequestConfig as SharedQuoteRequestConfig;
use Spryker\Zed\QuoteRequest\Business\Reader\QuoteRequestReaderInterface;
use Spryker\Zed\QuoteRequest\Persistence\QuoteRequestEntityManagerInterface;

class QuoteRequestUserSender implements QuoteRequestUserSenderInterface
{
    protected const GLOSSARY_KEY_QUOTE_REQUEST_WRONG_STATUS = 'quote_request.validation.error.wrong_status';
    protected const GLOSSARY_KEY_QUOTE_REQUEST_EMPTY_QUOTE_ITEMS = 'quote_request.validation.error.empty_quote_items';
    protected const GLOSSARY_KEY_WRONG_QUOTE_REQUEST_VALID_UNTIL = 'quote_request.update.validation.error.wrong_valid_until';

    /**
     * @var \Spryker\Zed\QuoteRequest\Persistence\QuoteRequestEntityManagerInterface
     */
    protected $quoteRequestEntityManager;

    /**
     * @var \Spryker\Zed\QuoteRequest\Business\Reader\QuoteRequestReaderInterface
     */
    protected $quoteRequestReader;

    /**
     * @param \Spryker\Zed\QuoteRequest\Persistence\QuoteRequestEntityManagerInterface $quoteRequestEntityManager
     * @param \Spryker\Zed\QuoteRequest\Business\Reader\QuoteRequestReaderInterface $quoteRequestReader
     */
    public function __construct(
        QuoteRequestEntityManagerInterface $quoteRequestEntityManager,
        QuoteRequestReaderInterface $quoteRequestReader
    ) {
        $this->quoteRequestEntityManager = $quoteRequestEntityManager;
        $this->quoteRequestReader = $quoteRequestReader;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    public function sendQuoteRequestToCustomer(QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer): QuoteRequestResponseTransfer
    {
        $quoteRequestResponseTransfer = $this->quoteRequestReader->findQuoteRequest($quoteRequestCriteriaTransfer);

        if (!$quoteRequestResponseTransfer->getIsSuccessful()) {
            return $quoteRequestResponseTransfer;
        }

        $quoteRequestTransfer = $quoteRequestResponseTransfer->getQuoteRequest();
        $quoteRequestResponseTransfer = $this->validateQuoteRequestBeforeSend($quoteRequestTransfer);

        if (!$quoteRequestResponseTransfer->getIsSuccessful()) {
            return $quoteRequestResponseTransfer;
        }

        $quoteRequestTransfer->setStatus(SharedQuoteRequestConfig::STATUS_READY);
        $quoteRequestTransfer->setIsLatestVersionHidden(false);
        $quoteRequestTransfer = $this->quoteRequestEntityManager->updateQuoteRequest($quoteRequestTransfer);

        return $quoteRequestResponseTransfer->setQuoteRequest($quoteRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    protected function validateQuoteRequestBeforeSend(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestResponseTransfer
    {
        if ($quoteRequestTransfer->getStatus() !== SharedQuoteRequestConfig::STATUS_IN_PROGRESS) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_WRONG_STATUS);
        }

        if (!$quoteRequestTransfer->getLatestVersion()->getQuote()->getItems()->count()) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_EMPTY_QUOTE_ITEMS);
        }

        if ($quoteRequestTransfer->getValidUntil() && strtotime($quoteRequestTransfer->getValidUntil()) < time()) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_WRONG_QUOTE_REQUEST_VALID_UNTIL);
        }

        return (new QuoteRequestResponseTransfer())
            ->setIsSuccessful(true);
    }

    /**
     * @param string $message
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    protected function getErrorResponse(string $message): QuoteRequestResponseTransfer
    {
        $messageTransfer = (new MessageTransfer())
            ->setValue($message);

        return (new QuoteRequestResponseTransfer())
            ->setIsSuccessful(false)
            ->addMessage($messageTransfer);
    }
}
