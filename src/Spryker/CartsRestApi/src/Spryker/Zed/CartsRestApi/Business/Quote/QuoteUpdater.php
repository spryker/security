<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CartsRestApi\Business\Quote;

use Generated\Shared\Transfer\AssignGuestQuoteRequestTransfer;
use Generated\Shared\Transfer\CustomerTransfer;
use Generated\Shared\Transfer\QuoteCollectionTransfer;
use Generated\Shared\Transfer\QuoteCriteriaFilterTransfer;
use Generated\Shared\Transfer\QuoteErrorTransfer;
use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\QuoteUpdateRequestTransfer;
use Spryker\Shared\CartsRestApi\CartsRestApiConfig as CartsRestApiSharedConfig;
use Spryker\Zed\CartsRestApi\Business\ErrorIdentifierAdderTrait;
use Spryker\Zed\CartsRestApi\Business\PermissionChecker\QuotePermissionCheckerInterface;
use Spryker\Zed\CartsRestApi\Business\Quote\Mapper\QuoteMapperInterface;
use Spryker\Zed\CartsRestApi\Dependency\Facade\CartsRestApiToCartFacadeInterface;
use Spryker\Zed\CartsRestApi\Dependency\Facade\CartsRestApiToPersistentCartFacadeInterface;

class QuoteUpdater implements QuoteUpdaterInterface
{
    use ErrorIdentifierAdderTrait;

    /**
     * @var \Spryker\Zed\CartsRestApi\Dependency\Facade\CartsRestApiToPersistentCartFacadeInterface
     */
    protected $persistentCartFacade;

    /**
     * @var \Spryker\Zed\CartsRestApi\Dependency\Facade\CartsRestApiToCartFacadeInterface
     */
    protected $cartFacade;

    /**
     * @var \Spryker\Zed\CartsRestApi\Business\Quote\QuoteReaderInterface
     */
    protected $quoteReader;

    /**
     * @var \Spryker\Zed\CartsRestApi\Business\Quote\Mapper\QuoteMapperInterface
     */
    protected $quoteMapper;

    /**
     * @var \Spryker\Zed\CartsRestApi\Business\PermissionChecker\QuotePermissionCheckerInterface
     */
    protected $quotePermissionChecker;

    /**
     * @param \Spryker\Zed\CartsRestApi\Dependency\Facade\CartsRestApiToPersistentCartFacadeInterface $persistentCartFacade
     * @param \Spryker\Zed\CartsRestApi\Dependency\Facade\CartsRestApiToCartFacadeInterface $cartFacade
     * @param \Spryker\Zed\CartsRestApi\Business\Quote\QuoteReaderInterface $quoteReader
     * @param \Spryker\Zed\CartsRestApi\Business\Quote\Mapper\QuoteMapperInterface $quoteMapper
     * @param \Spryker\Zed\CartsRestApi\Business\PermissionChecker\QuotePermissionCheckerInterface $quotePermissionChecker
     */
    public function __construct(
        CartsRestApiToPersistentCartFacadeInterface $persistentCartFacade,
        CartsRestApiToCartFacadeInterface $cartFacade,
        QuoteReaderInterface $quoteReader,
        QuoteMapperInterface $quoteMapper,
        QuotePermissionCheckerInterface $quotePermissionChecker
    ) {
        $this->persistentCartFacade = $persistentCartFacade;
        $this->cartFacade = $cartFacade;
        $this->quoteReader = $quoteReader;
        $this->quoteMapper = $quoteMapper;
        $this->quotePermissionChecker = $quotePermissionChecker;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function updateQuote(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        $quoteTransfer->requireCustomer();
        $quoteTransfer->requireUuid();

        $quoteResponseTransfer = $this->quoteReader->findQuoteByUuid($quoteTransfer);
        if (!$quoteResponseTransfer->getIsSuccessful()) {
            return $quoteResponseTransfer;
        }

        $quoteTransfer->setIdQuote($quoteResponseTransfer->getQuoteTransfer()->getIdQuote());

        if (!$this->quotePermissionChecker->checkQuoteWritePermission($quoteTransfer)) {
            return $quoteResponseTransfer
                ->setIsSuccessful(false)
                ->addError((new QuoteErrorTransfer())
                    ->setErrorIdentifier(CartsRestApiSharedConfig::ERROR_IDENTIFIER_UNAUTHORIZED_CART_ACTION));
        }

        $originalQuoteTransfer = $quoteResponseTransfer->getQuoteTransfer();
        $quoteResponseTransfer = $this->validateQuoteResponse($originalQuoteTransfer, $quoteTransfer, $quoteResponseTransfer);

        if (!$quoteResponseTransfer->getIsSuccessful()) {
            return $quoteResponseTransfer;
        }

        $quoteTransfer = $this->cartFacade->reloadItems(
            $this->quoteMapper->mapQuoteTransferToOriginalQuoteTransfer($quoteTransfer, $originalQuoteTransfer)
        );

        return $this->performUpdatingQuote($quoteTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\AssignGuestQuoteRequestTransfer $assignGuestQuoteRequestTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function assignGuestCartToRegisteredCustomer(AssignGuestQuoteRequestTransfer $assignGuestQuoteRequestTransfer): QuoteResponseTransfer
    {
        $assignGuestQuoteRequestTransfer
            ->requireCustomerReference()
            ->requireAnonymousCustomerReference();

        $quoteCollectionTransfer = $this->quoteReader->getQuoteCollection(
            (new QuoteCriteriaFilterTransfer())
                ->setCustomerReference($assignGuestQuoteRequestTransfer->getAnonymousCustomerReference())
        );

        if (!$quoteCollectionTransfer->getQuotes()->count()) {
            return (new QuoteResponseTransfer())
                ->setIsSuccessful(false);
        }

        $registeredCustomerReference = $assignGuestQuoteRequestTransfer->getCustomerReference();
        $quoteTransfer = $this->createQuoteTransfer($registeredCustomerReference, $quoteCollectionTransfer);

        return $this->performUpdatingQuote($quoteTransfer);
    }

    /**
     * @param string $registeredCustomerReference
     * @param \Generated\Shared\Transfer\QuoteCollectionTransfer $quoteCollectionTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function createQuoteTransfer(
        string $registeredCustomerReference,
        QuoteCollectionTransfer $quoteCollectionTransfer
    ): QuoteTransfer {
        $registeredCustomer = (new CustomerTransfer())->setCustomerReference($registeredCustomerReference);
        $quoteTransfer = $quoteCollectionTransfer->getQuotes()[0];
        $quoteTransfer->setCustomerReference($registeredCustomerReference);

        return $quoteTransfer->setCustomer($registeredCustomer);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $originalQuoteTransfer
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param \Generated\Shared\Transfer\QuoteResponseTransfer $quoteResponseTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function validateQuoteResponse(
        QuoteTransfer $originalQuoteTransfer,
        QuoteTransfer $quoteTransfer,
        QuoteResponseTransfer $quoteResponseTransfer
    ): QuoteResponseTransfer {
        if ($originalQuoteTransfer->getItems()->count() > 0
            && ($quoteTransfer->getPriceMode() && $quoteTransfer->getPriceMode() !== $originalQuoteTransfer->getPriceMode())
        ) {
            return $quoteResponseTransfer
                ->setIsSuccessful(false)
                ->addError((new QuoteErrorTransfer())
                    ->setErrorIdentifier(CartsRestApiSharedConfig::ERROR_IDENTIFIER_CART_CANT_BE_UPDATED));
        }

        return $quoteResponseTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function performUpdatingQuote(QuoteTransfer $quoteTransfer): QuoteResponseTransfer
    {
        $quoteResponseTransfer = $this->persistentCartFacade
            ->updateQuote($this->quoteMapper->mapQuoteTransferToQuoteUpdateRequestTransfer($quoteTransfer, new QuoteUpdateRequestTransfer()));

        if (!$quoteResponseTransfer->getIsSuccessful()) {
            return $this->addErrorIdentifiersToQuoteResponseErrors($quoteResponseTransfer);
        }

        return $quoteResponseTransfer;
    }
}
