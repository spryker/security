<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PersistentCart\Business\Model;

use Generated\Shared\Transfer\CustomerTransfer;
use Generated\Shared\Transfer\MessageTransfer;
use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\QuoteUpdateRequestAttributesTransfer;
use Spryker\Zed\Kernel\PermissionAwareTrait;
use Spryker\Zed\PersistentCart\Dependency\Facade\PersistentCartToMessengerFacadeInterface;
use Spryker\Zed\PersistentCart\Dependency\Facade\PersistentCartToQuoteFacadeInterface;
use Spryker\Zed\PersistentCart\Dependency\Facade\PersistentCartToStoreFacadeInterface;
use Spryker\Zed\PersistentCart\PersistentCartConfig;

class QuoteResolver implements QuoteResolverInterface
{
    use PermissionAwareTrait;
    public const GLOSSARY_KEY_QUOTE_NOT_AVAILABLE = 'persistent_cart.error.quote.not_available';
    public const GLOSSARY_KEY_PERMISSION_FAILED = 'global.permission.failed';

    protected const WRITE_SHARED_CART_PERMISSION_PLUGIN = 'WriteSharedCartPermissionPlugin';
    protected const READ_SHARED_CART_PERMISSION_PLUGIN = 'ReadSharedCartPermissionPlugin';

    /**
     * @var \Spryker\Zed\PersistentCart\Dependency\Facade\PersistentCartToQuoteFacadeInterface
     */
    protected $quoteFacade;

    /**
     * @var \Spryker\Zed\PersistentCart\Business\Model\QuoteResponseExpanderInterface
     */
    protected $quoteResponseExpander;

    /**
     * @var \Spryker\Zed\PersistentCart\Dependency\Facade\PersistentCartToMessengerFacadeInterface
     */
    protected $messengerFacade;

    /**
     * @var \Spryker\Zed\PersistentCart\Dependency\Facade\PersistentCartToStoreFacadeInterface
     */
    protected $storeFacade;

    /**
     * @var \Spryker\Zed\PersistentCart\PersistentCartConfig
     */
    protected $persistentCartConfig;

    /**
     * @param \Spryker\Zed\PersistentCart\Dependency\Facade\PersistentCartToQuoteFacadeInterface $quoteFacade
     * @param \Spryker\Zed\PersistentCart\Business\Model\QuoteResponseExpanderInterface $quoteResponseExpander
     * @param \Spryker\Zed\PersistentCart\Dependency\Facade\PersistentCartToMessengerFacadeInterface $messengerFacade
     * @param \Spryker\Zed\PersistentCart\Dependency\Facade\PersistentCartToStoreFacadeInterface $storeFacade
     * @param \Spryker\Zed\PersistentCart\PersistentCartConfig $persistentCartConfig
     */
    public function __construct(
        PersistentCartToQuoteFacadeInterface $quoteFacade,
        QuoteResponseExpanderInterface $quoteResponseExpander,
        PersistentCartToMessengerFacadeInterface $messengerFacade,
        PersistentCartToStoreFacadeInterface $storeFacade,
        PersistentCartConfig $persistentCartConfig
    ) {
        $this->quoteFacade = $quoteFacade;
        $this->quoteResponseExpander = $quoteResponseExpander;
        $this->messengerFacade = $messengerFacade;
        $this->storeFacade = $storeFacade;
        $this->persistentCartConfig = $persistentCartConfig;
    }

    /**
     * @param int|null $idQuote
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     * @param \Generated\Shared\Transfer\QuoteUpdateRequestAttributesTransfer|null $quoteUpdateRequestAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function resolveCustomerQuote(
        ?int $idQuote,
        CustomerTransfer $customerTransfer,
        ?QuoteUpdateRequestAttributesTransfer $quoteUpdateRequestAttributesTransfer = null
    ): QuoteResponseTransfer {
        if (!$idQuote) {
            return $this->createNewQuote($customerTransfer, $quoteUpdateRequestAttributesTransfer);
        }
        $customerQuoteTransfer = $this->findCustomerQuoteById(
            $idQuote,
            $customerTransfer
        );

        if (!$customerQuoteTransfer) {
            return $this->createQuoteNotFoundResult($customerTransfer);
        }

        return $this->updateQuote($customerTransfer, $customerQuoteTransfer, $quoteUpdateRequestAttributesTransfer);
    }

    /**
     * @param int $idQuote
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer|null
     */
    protected function findCustomerQuoteById(int $idQuote, CustomerTransfer $customerTransfer): ?QuoteTransfer
    {
        $quoteResponseTransfer = $this->quoteFacade->findQuoteById($idQuote);
        $isReadSharedCartAllowed = $this->isQuoteOperationAllowed(
            $quoteResponseTransfer->getQuoteTransfer(),
            $customerTransfer,
            static::READ_SHARED_CART_PERMISSION_PLUGIN
        );

        if (!$quoteResponseTransfer->getIsSuccessful() || !$isReadSharedCartAllowed) {
            $messageTransfer = new MessageTransfer();
            $messageTransfer->setValue(static::GLOSSARY_KEY_QUOTE_NOT_AVAILABLE);
            $this->messengerFacade->addErrorMessage($messageTransfer);

            return null;
        }
        $quoteTransfer = $quoteResponseTransfer->getQuoteTransfer();
        $quoteTransfer->setCustomer($customerTransfer);

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function createQuoteNotFoundResult(CustomerTransfer $customerTransfer): QuoteResponseTransfer
    {
        $quoteResponseTransfer = new QuoteResponseTransfer();
        $quoteResponseTransfer->setCustomer($customerTransfer);
        $quoteResponseTransfer->setQuoteTransfer($this->resolveDefaultCustomerQuote($customerTransfer));
        $quoteResponseTransfer->setIsSuccessful(false);

        return $this->quoteResponseExpander->expand($quoteResponseTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function createQuoteNotWritableResult(CustomerTransfer $customerTransfer): QuoteResponseTransfer
    {
        $quoteResponseTransfer = new QuoteResponseTransfer();
        $quoteResponseTransfer->setCustomer($customerTransfer);
        $quoteResponseTransfer->setIsSuccessful(false);

        return $this->quoteResponseExpander->expand($quoteResponseTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    protected function resolveDefaultCustomerQuote(CustomerTransfer $customerTransfer): QuoteTransfer
    {
        $quoteTransfer = new QuoteTransfer();
        $storeTransfer = $this->storeFacade->getCurrentStore();
        $customerQuoteTransfer = $this->quoteFacade->findQuoteByCustomerAndStore($customerTransfer, $storeTransfer);
        if ($customerQuoteTransfer->getIsSuccessful()) {
            $quoteTransfer = $customerQuoteTransfer->getQuoteTransfer();
        }
        $quoteTransfer->setCustomer($customerTransfer);
        if (!$quoteTransfer->getIdQuote()) {
            $this->quoteFacade->createQuote($quoteTransfer);
        }

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     * @param \Generated\Shared\Transfer\QuoteUpdateRequestAttributesTransfer|null $quoteUpdateRequestAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function createNewQuote(CustomerTransfer $customerTransfer, ?QuoteUpdateRequestAttributesTransfer $quoteUpdateRequestAttributesTransfer = null): QuoteResponseTransfer
    {
        $quoteTransfer = new QuoteTransfer();
        $quoteTransfer->setCustomer($customerTransfer);
        $quoteTransfer->setCustomerReference($customerTransfer->getCustomerReference());
        if ($quoteUpdateRequestAttributesTransfer) {
            $quoteTransfer->fromArray($quoteUpdateRequestAttributesTransfer->modifiedToArray(), true);
        }

        return $this->quoteFacade->createQuote($quoteTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param \Generated\Shared\Transfer\QuoteUpdateRequestAttributesTransfer|null $quoteUpdateRequestAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    protected function updateQuote(
        CustomerTransfer $customerTransfer,
        QuoteTransfer $quoteTransfer,
        ?QuoteUpdateRequestAttributesTransfer $quoteUpdateRequestAttributesTransfer = null
    ): QuoteResponseTransfer {
        if (!$this->isQuoteOperationAllowed($quoteTransfer, $customerTransfer, static::WRITE_SHARED_CART_PERMISSION_PLUGIN)) {
            $messageTransfer = new MessageTransfer();
            $messageTransfer->setValue(static::GLOSSARY_KEY_PERMISSION_FAILED);
            $this->messengerFacade->addErrorMessage($messageTransfer);

            return $this->createQuoteNotWritableResult($customerTransfer);
        }

        if ($quoteUpdateRequestAttributesTransfer) {
            $quoteTransfer->fromArray($quoteUpdateRequestAttributesTransfer->modifiedToArray(), true);
        }

        $quoteTransfer->setCustomer($customerTransfer);
        $quoteResponseTransfer = new QuoteResponseTransfer();
        $quoteResponseTransfer->setIsSuccessful(true);
        $quoteResponseTransfer->setCustomer($customerTransfer);
        $quoteResponseTransfer->setQuoteTransfer($quoteTransfer);

        return $quoteResponseTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param \Generated\Shared\Transfer\CustomerTransfer $customerTransfer
     * @param string $operation
     *
     * @return bool
     */
    protected function isQuoteOperationAllowed(
        QuoteTransfer $quoteTransfer,
        CustomerTransfer $customerTransfer,
        $operation
    ): bool {
        return strcmp($customerTransfer->getCustomerReference(), $quoteTransfer->getCustomerReference()) === 0
            || $this->isAnonymousCustomerQuote($quoteTransfer->getCustomerReference())
            || ($customerTransfer->getCompanyUserTransfer()
                && $this->can($operation, $customerTransfer->getCompanyUserTransfer()->getIdCompanyUser(), $quoteTransfer->getIdQuote())
            );
    }

    /**
     * @param string $customerReference
     *
     * @return bool
     */
    protected function isAnonymousCustomerQuote(string $customerReference): bool
    {
        $anonymousPrefix = $this->persistentCartConfig->getPersistentCartAnonymousPrefix();

        return strncasecmp($anonymousPrefix, $customerReference, strlen($anonymousPrefix)) === 0;
    }
}
