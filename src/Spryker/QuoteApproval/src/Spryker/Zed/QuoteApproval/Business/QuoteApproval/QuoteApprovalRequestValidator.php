<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\QuoteApproval\Business\QuoteApproval;

use Generated\Shared\Transfer\CustomerTransfer;
use Generated\Shared\Transfer\MessageTransfer;
use Generated\Shared\Transfer\QuoteApprovalCreateRequestTransfer;
use Generated\Shared\Transfer\QuoteApprovalRemoveRequestTransfer;
use Generated\Shared\Transfer\QuoteApprovalRequestTransfer;
use Generated\Shared\Transfer\QuoteApprovalRequestValidationResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Shared\QuoteApproval\QuoteApprovalConfig;
use Spryker\Zed\Kernel\PermissionAwareTrait;
use Spryker\Zed\QuoteApproval\Business\Permission\ContextProvider\PermissionContextProviderInterface;
use Spryker\Zed\QuoteApproval\Business\Quote\QuoteStatusCalculatorInterface;
use Spryker\Zed\QuoteApproval\Communication\Plugin\Permission\ApproveQuotePermissionPlugin;
use Spryker\Zed\QuoteApproval\Dependency\Facade\QuoteApprovalToCompanyUserFacadeInterface;
use Spryker\Zed\QuoteApproval\Dependency\Facade\QuoteApprovalToQuoteFacadeInterface;
use Spryker\Zed\QuoteApproval\Persistence\QuoteApprovalRepositoryInterface;

class QuoteApprovalRequestValidator implements QuoteApprovalRequestValidatorInterface
{
    use PermissionAwareTrait;

    protected const GLOSSARY_KEY_PERMISSION_FAILED = 'global.permission.failed';
    protected const GLOSSARY_KEY_APPROVER_CANT_APPROVE_QUOTE = 'quote_approval.create.approver_cant_approve_quote';
    protected const GLOSSARY_KEY_YOU_CANT_APPROVE_QUOTE = 'quote_approval.create.you_cant_approve_quote';
    protected const GLOSSARY_KEY_QUOTE_ALREADY_APPROVED = 'quote_approval.create.quote_already_approved';
    protected const GLOSSARY_KEY_QUOTE_ALREADY_DECLINED = 'quote_approval.create.quote_already_declined';
    protected const GLOSSARY_KEY_QUOTE_ALREADY_CANCELLED = 'quote_approval.create.quote_already_cancelled';
    protected const GLOSSARY_KEY_QUOTE_ALREADY_WAITING_FOR_APPROVAL = 'quote_approval.create.quote_already_waiting_for_approval';
    protected const GLOSSARY_KEY_ONLY_QUOTE_OWNER_CAN_SEND_APPROVAL_REQUEST = 'quote_approval.create.only_quote_owner_can_send_request';
    protected const GLOSSARY_KEY_DO_NOT_HAVE_PERMISSION_TO_CANCEL_APPROVAL_REQUEST = 'quote_approval.cancel.do_not_have_permission';
    /**
     * @var \Spryker\Zed\QuoteApproval\Business\Quote\QuoteStatusCalculatorInterface
     */
    protected $quoteStatusCalculator;

    /**
     * @var \Spryker\Zed\QuoteApproval\Dependency\Facade\QuoteApprovalToQuoteFacadeInterface
     */
    protected $quoteFacade;

    /**
     * @var \Spryker\Zed\QuoteApproval\Persistence\QuoteApprovalRepositoryInterface
     */
    protected $quoteApprovalRepository;

    /**
     * @var \Spryker\Zed\QuoteApproval\Dependency\Facade\QuoteApprovalToCompanyUserFacadeInterface
     */
    protected $companyUserFacade;

    /**
     * @var \Spryker\Zed\QuoteApproval\Business\Permission\ContextProvider\PermissionContextProviderInterface
     */
    protected $permissionContextProvider;

    /**
     * @param \Spryker\Zed\QuoteApproval\Dependency\Facade\QuoteApprovalToQuoteFacadeInterface $quoteFacade
     * @param \Spryker\Zed\QuoteApproval\Business\Quote\QuoteStatusCalculatorInterface $quoteStatusCalculator
     * @param \Spryker\Zed\QuoteApproval\Persistence\QuoteApprovalRepositoryInterface $quoteApprovalRepository
     * @param \Spryker\Zed\QuoteApproval\Dependency\Facade\QuoteApprovalToCompanyUserFacadeInterface $companyUserFacade
     * @param \Spryker\Zed\QuoteApproval\Business\Permission\ContextProvider\PermissionContextProviderInterface $permissionContextProvider
     */
    public function __construct(
        QuoteApprovalToQuoteFacadeInterface $quoteFacade,
        QuoteStatusCalculatorInterface $quoteStatusCalculator,
        QuoteApprovalRepositoryInterface $quoteApprovalRepository,
        QuoteApprovalToCompanyUserFacadeInterface $companyUserFacade,
        PermissionContextProviderInterface $permissionContextProvider
    ) {
        $this->quoteFacade = $quoteFacade;
        $this->quoteStatusCalculator = $quoteStatusCalculator;
        $this->quoteApprovalRepository = $quoteApprovalRepository;
        $this->companyUserFacade = $companyUserFacade;
        $this->permissionContextProvider = $permissionContextProvider;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalCreateRequestTransfer $quoteApprovalCreateRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalRequestValidationResponseTransfer
     */
    public function validateQuoteApprovalCreateRequest(QuoteApprovalCreateRequestTransfer $quoteApprovalCreateRequestTransfer): QuoteApprovalRequestValidationResponseTransfer
    {
        $this->assertQuoteApprovalCreateRequestValid($quoteApprovalCreateRequestTransfer);
        $quoteTransfer = $this->getQuoteById($quoteApprovalCreateRequestTransfer->getIdQuote());

        if (!$this->isQuoteOwner($quoteTransfer, $quoteApprovalCreateRequestTransfer->getRequesterCompanyUserId())) {
            return $this->createUnsuccessfulValidationResponseTransfer(static::GLOSSARY_KEY_ONLY_QUOTE_OWNER_CAN_SEND_APPROVAL_REQUEST);
        }

        if (!$this->isApproverCanApproveQuote($quoteTransfer, $quoteApprovalCreateRequestTransfer->getApproverCompanyUserId())) {
            return $this->createUnsuccessfulValidationResponseTransfer(static::GLOSSARY_KEY_APPROVER_CANT_APPROVE_QUOTE);
        }

        if ($this->isQuoteWaitingForApproval($quoteTransfer)) {
            return $this->createUnsuccessfulValidationResponseTransfer(static::GLOSSARY_KEY_QUOTE_ALREADY_WAITING_FOR_APPROVAL);
        }

        if ($this->isQuoteApproved($quoteTransfer)) {
            return $this->createUnsuccessfulValidationResponseTransfer(static::GLOSSARY_KEY_QUOTE_ALREADY_APPROVED);
        }

        return $this->createSuccessfullValidationResponseTransfer()
            ->setQuote($quoteTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalRemoveRequestTransfer $quoteApprovalRemoveRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalRequestValidationResponseTransfer
     */
    public function validateQuoteApprovalRemoveRequest(QuoteApprovalRemoveRequestTransfer $quoteApprovalRemoveRequestTransfer): QuoteApprovalRequestValidationResponseTransfer
    {
        $quoteTransfer = $this->findQuoteByIdQuoteApproval($quoteApprovalRemoveRequestTransfer->getIdQuoteApproval());

        if (!$this->isQuoteOwner($quoteTransfer, $quoteApprovalRemoveRequestTransfer->getIdCompanyUser())
            && !$this->isRemoveRequestSentByApprover($quoteApprovalRemoveRequestTransfer)
        ) {
            return $this->createUnsuccessfulValidationResponseTransfer(static::GLOSSARY_KEY_DO_NOT_HAVE_PERMISSION_TO_CANCEL_APPROVAL_REQUEST);
        }

        return $this->createSuccessfullValidationResponseTransfer()
            ->setQuote($quoteTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalRequestValidationResponseTransfer
     */
    public function validateQuoteApprovalRequest(QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer): QuoteApprovalRequestValidationResponseTransfer
    {
        $this->assertQuoteApprovalRequestValid($quoteApprovalRequestTransfer);
        $quoteApprovalTransfer = $this->quoteApprovalRepository
            ->findQuoteApprovalById($quoteApprovalRequestTransfer->getIdQuoteApproval());
        $quoteTransfer = $this->findQuoteByIdQuoteApproval($quoteApprovalTransfer->getIdQuoteApproval());

        if ($this->isQuoteApprovalRequestCanceled($quoteTransfer)) {
            return $this->createUnsuccessfulValidationResponseTransfer(static::GLOSSARY_KEY_QUOTE_ALREADY_CANCELLED);
        }

        if ($this->isQuoteApproved($quoteTransfer)) {
            return $this->createUnsuccessfulValidationResponseTransfer(static::GLOSSARY_KEY_QUOTE_ALREADY_APPROVED);
        }

        if ($this->isQuoteDeclined($quoteTransfer)) {
            return $this->createUnsuccessfulValidationResponseTransfer(static::GLOSSARY_KEY_QUOTE_ALREADY_DECLINED);
        }

        if (!$this->isApproverCanApproveQuote($quoteTransfer, $quoteApprovalRequestTransfer->getFkCompanyUser())) {
            return $this->createUnsuccessfulValidationResponseTransfer(static::GLOSSARY_KEY_YOU_CANT_APPROVE_QUOTE);
        }

        return $this->createSuccessfullValidationResponseTransfer()
            ->setQuote($quoteTransfer)
            ->setQuoteApproval($quoteApprovalTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer
     *
     * @return void
     */
    protected function assertQuoteApprovalRequestValid(QuoteApprovalRequestTransfer $quoteApprovalRequestTransfer): void
    {
        $quoteApprovalRequestTransfer->requireFkCompanyUser()
            ->requireIdQuoteApproval();
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalCreateRequestTransfer $quoteApprovalCreateRequestTransfer
     *
     * @return void
     */
    protected function assertQuoteApprovalCreateRequestValid(QuoteApprovalCreateRequestTransfer $quoteApprovalCreateRequestTransfer): void
    {
        $quoteApprovalCreateRequestTransfer->requireApproverCompanyUserId()
            ->requireRequesterCompanyUserId()
            ->requireIdQuote();
    }

    /**
     * @param string $message
     *
     * @return \Generated\Shared\Transfer\QuoteApprovalRequestValidationResponseTransfer
     */
    protected function createUnsuccessfulValidationResponseTransfer(string $message): QuoteApprovalRequestValidationResponseTransfer
    {
        $quoteApprovalRequestValidationResponseTransfer = new QuoteApprovalRequestValidationResponseTransfer();
        $quoteApprovalRequestValidationResponseTransfer->setIsSuccessful(false);
        $quoteApprovalRequestValidationResponseTransfer->addMessage(
            (new MessageTransfer())->setValue($message)
        );

        return $quoteApprovalRequestValidationResponseTransfer;
    }

    /**
     * @return \Generated\Shared\Transfer\QuoteApprovalRequestValidationResponseTransfer
     */
    protected function createSuccessfullValidationResponseTransfer(): QuoteApprovalRequestValidationResponseTransfer
    {
        $quoteApprovalRequestValidationResponseTransfer = new QuoteApprovalRequestValidationResponseTransfer();
        $quoteApprovalRequestValidationResponseTransfer->setIsSuccessful(true);

        return $quoteApprovalRequestValidationResponseTransfer;
    }

    /**
     * @param int $idQuote
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function getQuoteById(int $idQuote): QuoteTransfer
    {
        $quoteResponseTransfer = $this->quoteFacade->findQuoteById($idQuote);
        $quoteResponseTransfer->requireQuoteTransfer();
        $quoteTransfer = $quoteResponseTransfer->getQuoteTransfer();
        $quoteTransfer->setCustomer(
            (new CustomerTransfer())->setCustomerReference($quoteTransfer->getCustomerReference())
        );

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteApprovalRemoveRequestTransfer $quoteApprovalRemoveRequestTransfer
     *
     * @return bool
     */
    protected function isRemoveRequestSentByApprover(QuoteApprovalRemoveRequestTransfer $quoteApprovalRemoveRequestTransfer): bool
    {
        $quoteApprovalTransfer = $this->quoteApprovalRepository->findQuoteApprovalById(
            $quoteApprovalRemoveRequestTransfer->getIdQuoteApproval()
        );

        return $quoteApprovalTransfer->getApproverCompanyUserId() === $quoteApprovalRemoveRequestTransfer->getIdCompanyUser();
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param int $idCompanyUser
     *
     * @return bool
     */
    protected function isQuoteOwner(QuoteTransfer $quoteTransfer, int $idCompanyUser): bool
    {
        $companyUserTransfer = $this->companyUserFacade->getCompanyUserById($idCompanyUser);

        return $quoteTransfer->getCustomerReference() === $companyUserTransfer->getCustomer()->getCustomerReference();
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param int $idCompanyUser
     *
     * @return bool
     */
    protected function isApproverCanApproveQuote(QuoteTransfer $quoteTransfer, int $idCompanyUser): bool
    {
        return $this->can(
            ApproveQuotePermissionPlugin::KEY,
            $idCompanyUser,
            $this->permissionContextProvider->provideContext($quoteTransfer)
        );
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return bool
     */
    protected function isQuoteApproved(QuoteTransfer $quoteTransfer): bool
    {
        return $this->quoteStatusCalculator->calculateQuoteStatus($quoteTransfer) === QuoteApprovalConfig::STATUS_APPROVED;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return bool
     */
    protected function isQuoteWaitingForApproval(QuoteTransfer $quoteTransfer): bool
    {
        return $this->quoteStatusCalculator->calculateQuoteStatus($quoteTransfer) === QuoteApprovalConfig::STATUS_WAITING;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return bool
     */
    protected function isQuoteApprovalRequestCanceled(QuoteTransfer $quoteTransfer): bool
    {
        return $this->quoteStatusCalculator->calculateQuoteStatus($quoteTransfer) === null;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return bool
     */
    protected function isQuoteDeclined(QuoteTransfer $quoteTransfer): bool
    {
        return $this->quoteStatusCalculator->calculateQuoteStatus($quoteTransfer) === QuoteApprovalConfig::STATUS_DECLINED;
    }

    /**
     * @param int $idQuoteApproval
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer|null
     */
    protected function findQuoteByIdQuoteApproval(int $idQuoteApproval): ?QuoteTransfer
    {
        $idQuote = $this->quoteApprovalRepository->findIdQuoteByIdQuoteApproval($idQuoteApproval);

        if ($idQuote === null) {
            return null;
        }

        return $this->getQuoteById($idQuote);
    }
}
