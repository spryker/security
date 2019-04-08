<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteRequest\Business\UserQuoteRequest;

use Generated\Shared\Transfer\CompanyUserTransfer;
use Generated\Shared\Transfer\MessageTransfer;
use Generated\Shared\Transfer\QuoteRequestCriteriaTransfer;
use Generated\Shared\Transfer\QuoteRequestFilterTransfer;
use Generated\Shared\Transfer\QuoteRequestResponseTransfer;
use Generated\Shared\Transfer\QuoteRequestTransfer;
use Generated\Shared\Transfer\QuoteRequestVersionTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Shared\QuoteRequest\QuoteRequestConfig as SharedQuoteRequestConfig;
use Spryker\Zed\Kernel\Persistence\EntityManager\TransactionTrait;
use Spryker\Zed\QuoteRequest\Business\Reader\QuoteRequestReaderInterface;
use Spryker\Zed\QuoteRequest\Business\ReferenceGenerator\QuoteRequestReferenceGeneratorInterface;
use Spryker\Zed\QuoteRequest\Dependency\Facade\QuoteRequestToCartFacadeInterface;
use Spryker\Zed\QuoteRequest\Dependency\Facade\QuoteRequestToCompanyUserFacadeInterface;
use Spryker\Zed\QuoteRequest\Persistence\QuoteRequestEntityManagerInterface;
use Spryker\Zed\QuoteRequest\QuoteRequestConfig;

class UserQuoteRequestWriter implements UserQuoteRequestWriterInterface
{
    use TransactionTrait;

    protected const GLOSSARY_KEY_QUOTE_REQUEST_COMPANY_USER_NOT_FOUND = 'quote_request.validation.error.company_user_not_found';
    protected const GLOSSARY_KEY_QUOTE_REQUEST_NOT_EXISTS = 'quote_request.validation.error.not_exists';
    protected const GLOSSARY_KEY_QUOTE_REQUEST_WRONG_STATUS = 'quote_request.validation.error.wrong_status';
    protected const GLOSSARY_KEY_QUOTE_REQUEST_EMPTY_QUOTE_ITEMS = 'quote_request.validation.error.empty_quote_items';
    protected const GLOSSARY_KEY_WRONG_QUOTE_REQUEST_VALID_UNTIL = 'quote_request.update.validation.error.wrong_valid_until';

    /**
     * @var \Spryker\Zed\QuoteRequest\QuoteRequestConfig
     */
    protected $quoteRequestConfig;

    /**
     * @var \Spryker\Zed\QuoteRequest\Persistence\QuoteRequestEntityManagerInterface
     */
    protected $quoteRequestEntityManager;

    /**
     * @var \Spryker\Zed\QuoteRequest\Business\Reader\QuoteRequestReaderInterface
     */
    protected $quoteRequestReader;

    /**
     * @var \Spryker\Zed\QuoteRequest\Business\ReferenceGenerator\QuoteRequestReferenceGeneratorInterface
     */
    protected $quoteRequestReferenceGenerator;

    /**
     * @var \Spryker\Zed\QuoteRequest\Dependency\Facade\QuoteRequestToCompanyUserFacadeInterface
     */
    protected $companyUserFacade;

    /**
     * @var \Spryker\Zed\QuoteRequest\Dependency\Facade\QuoteRequestToCartFacadeInterface
     */
    protected $cartFacade;

    /**
     * @param \Spryker\Zed\QuoteRequest\QuoteRequestConfig $quoteRequestConfig
     * @param \Spryker\Zed\QuoteRequest\Persistence\QuoteRequestEntityManagerInterface $quoteRequestEntityManager
     * @param \Spryker\Zed\QuoteRequest\Business\Reader\QuoteRequestReaderInterface $quoteRequestReader
     * @param \Spryker\Zed\QuoteRequest\Business\ReferenceGenerator\QuoteRequestReferenceGeneratorInterface $quoteRequestReferenceGenerator
     * @param \Spryker\Zed\QuoteRequest\Dependency\Facade\QuoteRequestToCompanyUserFacadeInterface $companyUserFacade
     * @param \Spryker\Zed\QuoteRequest\Dependency\Facade\QuoteRequestToCartFacadeInterface $cartFacade
     */
    public function __construct(
        QuoteRequestConfig $quoteRequestConfig,
        QuoteRequestEntityManagerInterface $quoteRequestEntityManager,
        QuoteRequestReaderInterface $quoteRequestReader,
        QuoteRequestReferenceGeneratorInterface $quoteRequestReferenceGenerator,
        QuoteRequestToCompanyUserFacadeInterface $companyUserFacade,
        QuoteRequestToCartFacadeInterface $cartFacade
    ) {
        $this->quoteRequestConfig = $quoteRequestConfig;
        $this->quoteRequestEntityManager = $quoteRequestEntityManager;
        $this->quoteRequestReader = $quoteRequestReader;
        $this->quoteRequestReferenceGenerator = $quoteRequestReferenceGenerator;
        $this->companyUserFacade = $companyUserFacade;
        $this->cartFacade = $cartFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    public function createQuoteRequest(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestResponseTransfer
    {
        return $this->getTransactionHandler()->handleTransaction(function () use ($quoteRequestTransfer) {
            return $this->executeCreateQuoteRequestTransaction($quoteRequestTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    public function updateQuoteRequest(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestResponseTransfer
    {
        return $this->getTransactionHandler()->handleTransaction(function () use ($quoteRequestTransfer) {
            return $this->executeUpdateQuoteRequestTransaction($quoteRequestTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    public function reviseQuoteRequest(QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer): QuoteRequestResponseTransfer
    {
        return $this->getTransactionHandler()->handleTransaction(function () use ($quoteRequestCriteriaTransfer) {
            return $this->executeReviseQuoteRequestTransaction($quoteRequestCriteriaTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    public function cancelQuoteRequest(QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer): QuoteRequestResponseTransfer
    {
        $quoteRequestTransfer = $this->findQuoteRequestTransfer($quoteRequestCriteriaTransfer);

        if (!$quoteRequestTransfer) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_NOT_EXISTS);
        }

        if (!$this->isQuoteRequestCancelable($quoteRequestTransfer)) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_WRONG_STATUS);
        }

        $quoteRequestTransfer->setStatus(SharedQuoteRequestConfig::STATUS_CANCELED);
        $quoteRequestTransfer = $this->quoteRequestEntityManager->updateQuoteRequest($quoteRequestTransfer);

        return (new QuoteRequestResponseTransfer())
            ->setIsSuccessful(true)
            ->setQuoteRequest($quoteRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    public function sendQuoteRequestToCustomer(QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer): QuoteRequestResponseTransfer
    {
        $quoteRequestTransfer = $this->findQuoteRequestTransfer($quoteRequestCriteriaTransfer);

        if (!$quoteRequestTransfer) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_NOT_EXISTS);
        }

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
    protected function executeCreateQuoteRequestTransaction(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestResponseTransfer
    {
        $quoteRequestTransfer->requireCompanyUser()
            ->getCompanyUser()
            ->requireIdCompanyUser();

        $customerReference = $this->findCustomerReference($quoteRequestTransfer->getCompanyUser());

        if (!$customerReference) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_COMPANY_USER_NOT_FOUND);
        }

        $quoteRequestReference = $this->quoteRequestReferenceGenerator->generateQuoteRequestReference($customerReference);

        $quoteRequestTransfer
            ->setQuoteRequestReference($quoteRequestReference)
            ->setStatus(SharedQuoteRequestConfig::STATUS_IN_PROGRESS)
            ->setIsLatestVersionHidden(true);

        $quoteRequestTransfer = $this->quoteRequestEntityManager->createQuoteRequest($quoteRequestTransfer);

        $quoteRequestVersionTransfer = $this->createQuoteRequestVersionTransfer($quoteRequestTransfer);
        $quoteRequestTransfer->setLatestVersion($quoteRequestVersionTransfer);

        return (new QuoteRequestResponseTransfer())
            ->setQuoteRequest($quoteRequestTransfer)
            ->setIsSuccessful(true);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    protected function executeUpdateQuoteRequestTransaction(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestResponseTransfer
    {
        $quoteRequestTransfer->requireQuoteRequestReference()
            ->requireCompanyUser()
            ->getCompanyUser()
            ->requireIdCompanyUser();

        $quoteRequestCriteriaTransfer = (new QuoteRequestCriteriaTransfer())
            ->setQuoteRequestReference($quoteRequestTransfer->getQuoteRequestReference())
            ->setIdCompanyUser($quoteRequestTransfer->getCompanyUser()->getIdCompanyUser());

        $currentQuoteRequestTransfer = $this->findQuoteRequestTransfer($quoteRequestCriteriaTransfer);

        if (!$currentQuoteRequestTransfer) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_NOT_EXISTS);
        }

        if (!$this->isQuoteRequestEditable($currentQuoteRequestTransfer)) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_WRONG_STATUS);
        }

        $latestQuoteRequestVersionTransfer = $this->reloadQuoteRequestVersionItems($quoteRequestTransfer->getLatestVersion());
        $latestQuoteRequestVersionTransfer = $this->quoteRequestEntityManager->updateQuoteRequestVersion(
            $this->cleanUpQuoteRequestVersionQuote($latestQuoteRequestVersionTransfer)
        );

        $quoteRequestTransfer = $this->quoteRequestEntityManager->updateQuoteRequest($quoteRequestTransfer);

        $quoteRequestTransfer->setLatestVersion($latestQuoteRequestVersionTransfer);

        return (new QuoteRequestResponseTransfer())
            ->setQuoteRequest($quoteRequestTransfer)
            ->setIsSuccessful(true);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    protected function executeReviseQuoteRequestTransaction(QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer): QuoteRequestResponseTransfer
    {
        $quoteRequestTransfer = $this->findQuoteRequestTransfer($quoteRequestCriteriaTransfer);

        if (!$quoteRequestTransfer) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_NOT_EXISTS);
        }

        if (!$this->isQuoteRequestRevisable($quoteRequestTransfer)) {
            return $this->getErrorResponse(static::GLOSSARY_KEY_QUOTE_REQUEST_WRONG_STATUS);
        }

        $latestQuoteRequestVersionTransfer = $this->addQuoteRequestVersion($quoteRequestTransfer);

        $quoteRequestTransfer
            ->setStatus(SharedQuoteRequestConfig::STATUS_IN_PROGRESS)
            ->setLatestVersion($latestQuoteRequestVersionTransfer)
            ->setLatestVisibleVersion($latestQuoteRequestVersionTransfer);

        $quoteRequestTransfer = $this->quoteRequestEntityManager->updateQuoteRequest($quoteRequestTransfer);

        return (new QuoteRequestResponseTransfer())
            ->setQuoteRequest($quoteRequestTransfer)
            ->setIsSuccessful(true);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestVersionTransfer
     */
    protected function addQuoteRequestVersion(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestVersionTransfer
    {
        $quoteRequestTransfer->requireIdQuoteRequest()
            ->requireLatestVersion();

        $latestQuoteRequestVersionTransfer = $quoteRequestTransfer->getLatestVersion();

        $quoteRequestVersionTransfer = (new QuoteRequestVersionTransfer())
            ->setVersion($quoteRequestTransfer->getLatestVersion()->getVersion() + 1)
            ->setFkQuoteRequest($quoteRequestTransfer->getIdQuoteRequest())
            ->setQuote($latestQuoteRequestVersionTransfer->getQuote())
            ->setMetadata($latestQuoteRequestVersionTransfer->getMetadata());

        $quoteRequestVersionTransfer->setVersionReference(
            $this->quoteRequestReferenceGenerator->generateQuoteRequestVersionReference($quoteRequestTransfer, $quoteRequestVersionTransfer)
        );

        return $this->quoteRequestEntityManager->createQuoteRequestVersion($quoteRequestVersionTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestVersionTransfer
     */
    protected function createQuoteRequestVersionTransfer(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestVersionTransfer
    {
        $quoteRequestTransfer->requireIdQuoteRequest()
            ->requireQuoteRequestReference();

        $quoteRequestVersionTransfer = (new QuoteRequestVersionTransfer())
            ->setQuote(new QuoteTransfer())
            ->setVersion($this->quoteRequestConfig->getInitialVersion())
            ->setFkQuoteRequest($quoteRequestTransfer->getIdQuoteRequest());

        $quoteRequestVersionTransfer->setVersionReference(
            $this->quoteRequestReferenceGenerator->generateQuoteRequestVersionReference($quoteRequestTransfer, $quoteRequestVersionTransfer)
        );

        return $this->quoteRequestEntityManager->createQuoteRequestVersion($quoteRequestVersionTransfer);
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
     * @param \Generated\Shared\Transfer\CompanyUserTransfer $companyUserTransfer
     *
     * @return string|null
     */
    protected function findCustomerReference(CompanyUserTransfer $companyUserTransfer): ?string
    {
        $customerReferences = $this->companyUserFacade
            ->getCustomerReferencesByCompanyUserIds([$companyUserTransfer->getIdCompanyUser()]);

        return array_shift($customerReferences);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestTransfer|null
     */
    protected function findQuoteRequestTransfer(QuoteRequestCriteriaTransfer $quoteRequestCriteriaTransfer): ?QuoteRequestTransfer
    {
        $quoteRequestCriteriaTransfer->requireQuoteRequestReference();

        $quoteRequestFilterTransfer = (new QuoteRequestFilterTransfer())
            ->setWithHidden(true)
            ->setQuoteRequestReference($quoteRequestCriteriaTransfer->getQuoteRequestReference());

        $quoteRequestTransfers = $this->quoteRequestReader
            ->getQuoteRequestCollectionByFilter($quoteRequestFilterTransfer)
            ->getQuoteRequests()
            ->getArrayCopy();

        return array_shift($quoteRequestTransfers);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestVersionTransfer $quoteRequestVersionTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestVersionTransfer
     */
    protected function reloadQuoteRequestVersionItems(QuoteRequestVersionTransfer $quoteRequestVersionTransfer): QuoteRequestVersionTransfer
    {
        if ($quoteRequestVersionTransfer->getQuote()->getItems()->count()) {
            $quoteRequestVersionTransfer->setQuote($this->cartFacade->reloadItems($quoteRequestVersionTransfer->getQuote()));
        }

        return $quoteRequestVersionTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestVersionTransfer $quoteRequestVersionTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestVersionTransfer
     */
    protected function cleanUpQuoteRequestVersionQuote(QuoteRequestVersionTransfer $quoteRequestVersionTransfer): QuoteRequestVersionTransfer
    {
        $quoteTransfer = $quoteRequestVersionTransfer->getQuote()
            ->setQuoteRequestVersionReference(null)
            ->setQuoteRequestReference(null);

        $quoteRequestVersionTransfer->setQuote($quoteTransfer);

        return $quoteRequestVersionTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return bool
     */
    protected function isQuoteRequestCancelable(QuoteRequestTransfer $quoteRequestTransfer): bool
    {
        return in_array($quoteRequestTransfer->getStatus(), $this->quoteRequestConfig->getUserCancelableStatuses());
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return bool
     */
    protected function isQuoteRequestEditable(QuoteRequestTransfer $quoteRequestTransfer): bool
    {
        return $quoteRequestTransfer->getStatus() === SharedQuoteRequestConfig::STATUS_IN_PROGRESS;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return bool
     */
    protected function isQuoteRequestRevisable(QuoteRequestTransfer $quoteRequestTransfer): bool
    {
        return in_array($quoteRequestTransfer->getStatus(), $this->quoteRequestConfig->getUserRevisableStatuses());
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
