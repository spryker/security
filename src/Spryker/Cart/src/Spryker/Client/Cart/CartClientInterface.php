<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Cart;

use ArrayObject;
use Generated\Shared\Transfer\CartChangeTransfer;
use Generated\Shared\Transfer\CurrencyTransfer;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\QuoteResponseTransfer;
use Generated\Shared\Transfer\QuoteTransfer;

interface CartClientInterface
{
    /**
     * Specification:
     *  - Gets current quote from session
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function getQuote();

    /**
     * Specification:
     * - Empty existing quote and store to session.
     * - In case of persistent strategy the quote is also deleted from database.
     *
     * @api
     *
     * @return void
     */
    public function clearQuote();

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Adds items to cart using quote storage strategy.
     *  - Invalid items will be skipped.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CartChangeTransfer $cartChangeTransfer
     * @param array $params
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function addValidItems(CartChangeTransfer $cartChangeTransfer, array $params = []): QuoteTransfer;

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Adds item to cart using quote storage strategy.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ItemTransfer $itemTransfer
     * @param array $params
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function addItem(ItemTransfer $itemTransfer, array $params = []);

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Adds items to cart using quote storage strategy.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\ItemTransfer[] $itemTransfers
     * @param array $params
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function addItems(array $itemTransfers, array $params = []);

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Remove item from cart using quote storage strategy.
     *
     * @api
     *
     * @param string $sku
     * @param string|null $groupKey
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function removeItem($sku, $groupKey = null);

    /**
     * Specification:
     *  - Returns the calculated number of items in cart
     *
     * @api
     *
     * @return int
     */
    public function getItemCount();

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Remove items from cart using quote storage strategy.
     *
     * @api
     *
     * @param \ArrayObject|\Generated\Shared\Transfer\ItemTransfer[] $items
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function removeItems(ArrayObject $items);

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Change item quantity using quote storage strategy.
     *
     * @api
     *
     * @param string $sku
     * @param string|null $groupKey
     * @param int $quantity
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function changeItemQuantity($sku, $groupKey = null, $quantity = 1);

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Decrease item quantity using quote storage strategy.
     *
     * @api
     *
     * @param string $sku
     * @param string|null $groupKey
     * @param int $quantity
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function decreaseItemQuantity($sku, $groupKey = null, $quantity = 1);

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Increase item quantity using quote storage strategy.
     *
     * @api
     *
     * @param string $sku
     * @param string|null $groupKey
     * @param int $quantity
     *
     * @return \Generated\Shared\Transfer\QuoteTransfer
     */
    public function increaseItemQuantity($sku, $groupKey = null, $quantity = 1);

    /**
     * Specification:
     *  - Store current quote into session
     *
     * @api
     *
     * @deprecated Use QuoteClient::setQuote() instead.
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return void
     */
    public function storeQuote(QuoteTransfer $quoteTransfer);

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Reloads all items in cart as new, it recreates all items transfer, reads new prices, options, bundles using quote storage strategy.
     *
     * @api
     *
     * @return void
     */
    public function reloadItems();

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Reloads all items in cart as new, it recreates all items transfer, reads new prices, options, bundles using quote storage strategy.
     *  - Observe quote changes after reloading.
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function validateQuote();

    /**
     * Specification:
     *  - Resolve quote storage strategy which implements \Spryker\Client\CartExtension\Dependency\Plugin\QuoteStorageStrategyPluginInterface.
     *  - Default quote storage strategy \Spryker\Client\Cart\Plugin\SessionQuoteStorageStrategyPlugin.
     *  - Update quote currency using quote storage strategy.
     *  - Reloads all items in cart as new, it recreates all items transfer, reads new prices, options, bundles.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CurrencyTransfer $currencyTransfer
     *
     * @return \Generated\Shared\Transfer\QuoteResponseTransfer
     */
    public function setQuoteCurrency(CurrencyTransfer $currencyTransfer): QuoteResponseTransfer;

    /**
     * Specification:
     * - Takes array of MessageTransfers for the last response and push them to flash messages.
     *
     * @api
     *
     * @return void
     */
    public function addFlashMessagesFromLastZedRequest();

    /**
     * Specification:
     * - Finds item in quote.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string $sku
     * @param string|null $groupKey
     *
     * @return \Generated\Shared\Transfer\ItemTransfer|null
     */
    public function findQuoteItem(QuoteTransfer $quoteTransfer, string $sku, ?string $groupKey = null): ?ItemTransfer;
}
