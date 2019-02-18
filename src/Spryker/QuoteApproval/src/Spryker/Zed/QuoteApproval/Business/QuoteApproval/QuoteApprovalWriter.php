<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteApproval\Business\QuoteApproval;

use ArrayObject;
use Generated\Shared\Transfer\QuoteApprovalRequestTransfer;
use Generated\Shared\Transfer\QuoteApprovalResponseTransfer;
use Generated\Shared\Transfer\QuoteApprovalTransfer;
use Spryker\Shared\QuoteApproval\QuoteApprovalConfig;
use Spryker\Zed\Kernel\Persistence\EntityManager\TransactionTrait;
use Spryker\Zed\QuoteApproval\Business\Quote\QuoteLockerInterface;
use Spryker\Zed\QuoteApproval\Persistence\QuoteApprovalEntityManagerInterface;

class QuoteApprovalWriter implements QuoteApprovalWriterInterface
{
    use TransactionTrait;

    /**
     * @var \Spryker\Zed\QuoteApproval\Business\QuoteApproval\QuoteApprovalRequestValidatorInterface
     */
    protected $quoteApprovalRequestValidator;

    /**
     * @var \Spryker\Zed\QuoteApproval\Business\QuoteApproval\QuoteApprovalMessageBuilderInterface
     */
    protected $quoteApprovalMessageBuilder;

    /**
     * @var \Spryker\Zed\QuoteApproval\Persistence\QuoteApprovalEntityManagerInterface
     */
    protected $quoteApprovalEntityManager;

    /**
     * @var \Spryker\Zed\QuoteApproval\Business\Quote\QuoteLockerInterface
     */
    protected $quoteLocker;

    /**
     * @param \Spryker\Zed\QuoteApproval\Business\QuoteApproval\QuoteApprovalRequestValidatorInterface $quoteApprovalRequestValidator
     * @param \Spryker\Zed\QuoteApproval\Business\QuoteApproval\QuoteApprovalMessageBuilderInterface $quoteApprovalMessageBuilder
     * @param \Spryker\Zed\QuoteApproval\Persistence\QuoteApprovalEntityManagerInterface $quoteApprovalEntityManager
     * @param \Spryker\Zed\QuoteApproval\Business\Quote\QuoteLockerInterface $quoteLocker
     */
    public function __construct(
        QuoteApprovalRequestValidatorInterface $quoteApprovalRequestValidator,
        QuoteApprovalMessageBuilderInterface $quoteApprovalMessageBuilder,
        QuoteApprovalEntityManagerInterface $quoteApprovalEntityManager,
        QuoteLockerInterface $quoteLocker
    ) {
        $this->quoteApprovalRequestValidator = $quoteApprovalRequestValidator;
        $this->quoteApprovalMessageBuilder = $quoteApprovalMessageBuilder;
        $this->quoteApprovalEntityManager = $quoteApprovalEntityManager;
        $this->quoteLocker = $quoteLocker;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalResponseTransfer
     */
    public function approveQuoteApproval(QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer): QuoteApprovalResponseTransfer
    {
        return $this->getTransactionHandler()->handleTransaction(function () use ($quoteApprovalRequestTransfer) {
            return $this->executeApproveQuoteApprovalTransaction($quoteApprovalRequestTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalResponseTransfer
     */
    public function declineQuoteApproval(QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer): QuoteApprovalResponseTransfer
    {
        return $this->getTransactionHandler()->handleTransaction(function () use ($quoteApprovalRequestTransfer) {
            return $this->executeDeclineQuoteApprovalTransaction($quoteApprovalRequestTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalResponseTransfer
     */
    protected function executeDeclineQuoteApprovalTransaction(QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer): QuoteApprovalResponseTransfer
    {
        $quoteApprovalResponseTransfer = $this->quoteApprovalRequestValidator
            ->validateQuoteApprovalRequest($quoteApprovalRequestTransfer);

        if (!$quoteApprovalResponseTransfer->getIsSuccessful()) {
            return $this->createNotSuccessfulQuoteApprovalResponseTransfer(
                $quoteApprovalResponseTransfer->getMessages()
            );
        }

        $this->quoteLocker->unlockQuote($quoteApprovalResponseTransfer->getQuote());

        return $this->updateQuoteApprovalWithStatus(
            $quoteApprovalResponseTransfer->getQuoteApproval(),
            QuoteApprovalConfig::STATUS_DECLINED
        );
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalResponseTransfer
     */
    protected function executeApproveQuoteApprovalTransaction(QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer): QuoteApprovalResponseTransfer
    {
        $quoteApprovalResponseTransfer = $this->quoteApprovalRequestValidator
            ->validateQuoteApprovalRequest($quoteApprovalRequestTransfer);

        if (!$quoteApprovalResponseTransfer->getIsSuccessful()) {
            return $this->createNotSuccessfulQuoteApprovalResponseTransfer(
                $quoteApprovalResponseTransfer->getMessages()
            );
        }

        return $this->updateQuoteApprovalWithStatus(
            $quoteApprovalResponseTransfer->getQuoteApproval(),
            QuoteApprovalConfig::STATUS_APPROVED
        );
    }

    /**
     * @param \Generated\Shared\Transfer\MessageTransfer[]|\ArrayObject $messageTransfers
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalResponseTransfer
     */
    protected function createNotSuccessfulQuoteApprovalResponseTransfer(ArrayObject $messageTransfers): QuoteApprovalResponseTransfer
    {
        return (new QuoteApprovalResponseTransfer())
            ->setMessages($messageTransfers)
            ->setIsSuccessful(false);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalTransfer $quoteApprovalTransfer
     * @param string $status
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalResponseTransfer
     */
    protected function updateQuoteApprovalWithStatus(QuoteApprovalTransfer $quoteApprovalTransfer, string $status): QuoteApprovalResponseTransfer
    {
        $quoteApprovalTransfer->setStatus($status);
        $quoteApprovalTransfer = $this->quoteApprovalEntityManager->saveQuoteApproval($quoteApprovalTransfer);

        return (new QuoteApprovalResponseTransfer())
            ->setQuoteApproval($quoteApprovalTransfer)
            ->setIsSuccessful(true)
            ->addMessage($this->quoteApprovalMessageBuilder->getSuccessMessage($quoteApprovalTransfer, $status));
    }
}
