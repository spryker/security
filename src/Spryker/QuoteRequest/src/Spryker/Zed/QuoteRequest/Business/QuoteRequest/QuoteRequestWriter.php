<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteRequest\Business\QuoteRequest;

use Generated\Shared\Transfer\CompanyUserTransfer;
use Generated\Shared\Transfer\QuoteRequestFilterTransfer;
use Generated\Shared\Transfer\QuoteRequestResponseTransfer;
use Generated\Shared\Transfer\QuoteRequestTransfer;
use Generated\Shared\Transfer\QuoteRequestVersionTransfer;
use Spryker\Shared\QuoteRequest\QuoteRequestConfig as SharedQuoteRequestConfig;
use Spryker\Zed\Kernel\Persistence\EntityManager\TransactionTrait;
use Spryker\Zed\QuoteRequest\Dependency\Facade\QuoteRequestToCompanyUserInterface;
use Spryker\Zed\QuoteRequest\Persistence\QuoteRequestEntityManagerInterface;
use Spryker\Zed\QuoteRequest\Persistence\QuoteRequestRepositoryInterface;
use Spryker\Zed\QuoteRequest\QuoteRequestConfig;

class QuoteRequestWriter implements QuoteRequestWriterInterface
{
    use TransactionTrait;

    protected const ERROR_MESSAGE_QUOTE_REQUEST_NOT_EXISTS = 'quote_request.validation.error.not_exists';
    protected const ERROR_MESSAGE_QUOTE_REQUEST_WRONG_STATUS = 'quote_request.validation.error.wrong_status';

    /**
     * @var \Spryker\Zed\QuoteRequest\QuoteRequestConfig
     */
    protected $quoteRequestConfig;

    /**
     * @var \Spryker\Zed\QuoteRequest\Persistence\QuoteRequestEntityManagerInterface
     */
    protected $quoteRequestEntityManager;

    /**
     * @var \Spryker\Zed\QuoteRequest\Persistence\QuoteRequestRepositoryInterface
     */
    protected $quoteRequestRepository;

    /**
     * @var \Spryker\Zed\QuoteRequest\Business\QuoteRequest\QuoteRequestReferenceGeneratorInterface
     */
    protected $referenceGenerator;

    /**
     * @var \Spryker\Zed\QuoteRequest\Dependency\Facade\QuoteRequestToCompanyUserInterface
     */
    protected $companyUserFacade;

    /**
     * @param \Spryker\Zed\QuoteRequest\QuoteRequestConfig $quoteRequestConfig
     * @param \Spryker\Zed\QuoteRequest\Persistence\QuoteRequestEntityManagerInterface $quoteRequestEntityManager
     * @param \Spryker\Zed\QuoteRequest\Persistence\QuoteRequestRepositoryInterface $quoteRequestRepository
     * @param \Spryker\Zed\QuoteRequest\Business\QuoteRequest\QuoteRequestReferenceGeneratorInterface $referenceGenerator
     * @param \Spryker\Zed\QuoteRequest\Dependency\Facade\QuoteRequestToCompanyUserInterface $companyUserFacade
     */
    public function __construct(
        QuoteRequestConfig $quoteRequestConfig,
        QuoteRequestEntityManagerInterface $quoteRequestEntityManager,
        QuoteRequestRepositoryInterface $quoteRequestRepository,
        QuoteRequestReferenceGeneratorInterface $referenceGenerator,
        QuoteRequestToCompanyUserInterface $companyUserFacade
    ) {
        $this->quoteRequestConfig = $quoteRequestConfig;
        $this->quoteRequestEntityManager = $quoteRequestEntityManager;
        $this->quoteRequestRepository = $quoteRequestRepository;
        $this->referenceGenerator = $referenceGenerator;
        $this->companyUserFacade = $companyUserFacade;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    public function create(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestResponseTransfer
    {
        return $this->getTransactionHandler()->handleTransaction(function () use ($quoteRequestTransfer) {
            return $this->executeCreateTransaction($quoteRequestTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestFilterTransfer $quoteRequestFilterTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    public function cancelByReference(QuoteRequestFilterTransfer $quoteRequestFilterTransfer): QuoteRequestResponseTransfer
    {
        $quoteRequestFilterTransfer->requireQuoteRequestReference()
            ->requireCompanyUser()
            ->getCompanyUser()
            ->requireIdCompanyUser();

        $quoteRequests = $this->quoteRequestRepository
            ->getQuoteRequestCollectionByFilter($quoteRequestFilterTransfer)
            ->getQuoteRequests()
            ->getArrayCopy();

        $quoteRequestTransfer = array_shift($quoteRequests);
        $quoteRequestResponseTransfer = new QuoteRequestResponseTransfer();

        if (!$quoteRequestTransfer) {
            return $quoteRequestResponseTransfer
                ->setIsSuccess(false)
                ->addError(static::ERROR_MESSAGE_QUOTE_REQUEST_NOT_EXISTS);
        }

        if ($quoteRequestTransfer->getStatus() !== SharedQuoteRequestConfig::STATUS_WAITING) {
            return $quoteRequestResponseTransfer
                ->setIsSuccess(false)
                ->addError(static::ERROR_MESSAGE_QUOTE_REQUEST_WRONG_STATUS);
        }

        $quoteRequestTransfer->setStatus(SharedQuoteRequestConfig::STATUS_CANCELED);
        $quoteRequestTransfer = $this->quoteRequestEntityManager->updateQuoteRequest($quoteRequestTransfer);

        return $quoteRequestResponseTransfer
            ->setQuoteRequest($quoteRequestTransfer)
            ->setIsSuccess(true);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestResponseTransfer
     */
    protected function executeCreateTransaction(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestResponseTransfer
    {
        $quoteRequestTransfer = $this->createQuoteRequest($quoteRequestTransfer);
        $quoteRequestVersionTransfer = $this->createQuoteRequestVersion($quoteRequestTransfer);

        $quoteRequestTransfer->setLatestVersion($quoteRequestVersionTransfer);

        return (new QuoteRequestResponseTransfer())
            ->setQuoteRequest($quoteRequestTransfer)
            ->setIsSuccess(true);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestTransfer
     */
    protected function createQuoteRequest(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestTransfer
    {
        $quoteRequestTransfer->requireCompanyUser()
            ->getCompanyUser()
            ->requireIdCompanyUser();

        $customerReference = $this->getCustomerReference($quoteRequestTransfer->getCompanyUser());

        $quoteRequestTransfer->setStatus($this->quoteRequestConfig->getInitialStatus());
        $quoteRequestTransfer->setQuoteRequestReference(
            $this->referenceGenerator->generateQuoteRequestReference($quoteRequestTransfer, $customerReference)
        );

        return $this->quoteRequestEntityManager->createQuoteRequest($quoteRequestTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteRequestTransfer $quoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteRequestVersionTransfer
     */
    protected function createQuoteRequestVersion(QuoteRequestTransfer $quoteRequestTransfer): QuoteRequestVersionTransfer
    {
        $quoteRequestTransfer->requireLatestVersion()
            ->getLatestVersion()
            ->requireQuote();

        $quoteRequestVersionTransfer = $quoteRequestTransfer->getLatestVersion()
            ->setVersion($this->quoteRequestConfig->getInitialVersion())
            ->setFkQuoteRequest($quoteRequestTransfer->getIdQuoteRequest());

        $quoteRequestVersionTransfer->setVersionReference(
            $this->referenceGenerator->generateQuoteRequestVersionReference($quoteRequestTransfer, $quoteRequestVersionTransfer)
        );

        return $this->quoteRequestEntityManager->createQuoteRequestVersion($quoteRequestVersionTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyUserTransfer $companyUserTransfer
     *
     * @return string
     */
    protected function getCustomerReference(CompanyUserTransfer $companyUserTransfer): string
    {
        $customerReferences = $this->companyUserFacade
            ->getCustomerReferencesByCompanyUserIds([$companyUserTransfer->getIdCompanyUser()]);

        return array_shift($customerReferences);
    }
}
