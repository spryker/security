<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Currency\Business;

use Generated\Shared\Transfer\CurrencyTransfer;
use Generated\Shared\Transfer\MessageTransfer;

/**
 * @method \Spryker\Zed\Currency\Business\CurrencyBusinessFactory getFactory()
 */
interface CurrencyFacadeInterface
{
    /**
     * Specification:
     * - Returns CurrencyTransfer object for given ISO code
     *
     * @api
     *
     * @param string $isoCode
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function fromIsoCode($isoCode);

    /**
     * Specification:
     * - Returns CurrencyTransfer object for current ISO code
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function getCurrent();

    /**
     * Specification:
     *  - Reads currency from spy_currency database table.
     *
     * @api
     *
     * @param int $idCurrency
     *
     * @throws \Spryker\Zed\Currency\Business\Model\Exception\CurrencyNotFoundException
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function getByIdCurrency($idCurrency);

    /**
     * Specification:
     *  - Persist currency to database.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CurrencyTransfer $currencyTransfer
     *
     * @return int
     */
    public function createCurrency(CurrencyTransfer $currencyTransfer);

    /**
     * Specification:
     *  - Reads all active currencies for current store
     *
     * @api
     *
     * @throws \Spryker\Zed\Currency\Business\Model\Exception\CurrencyNotFoundException
     *
     * @return \Generated\Shared\Transfer\StoreWithCurrencyTransfer
     */
    public function getCurrentStoreWithCurrencies();

    /**
     * Specification:
     *  - Reads all active store currencies
     *
     * @api
     *
     * @throws \Spryker\Zed\Currency\Business\Model\Exception\CurrencyNotFoundException
     *
     * @return \Generated\Shared\Transfer\StoreWithCurrencyTransfer[]
     */
    public function getAllStoresWithCurrencies();

    /**
     * Specification:
     *  - Returns default currency for current store
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function getDefaultCurrencyForCurrentStore();

    /**
     * Specification:
     *  - Verifies if provided currency in quote is available.
     *  - Returns error message if price mode not valid.
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\MessageTransfer
     */
    public function validateCurrencyInQuote($quoteTransfer): MessageTransfer;
}
