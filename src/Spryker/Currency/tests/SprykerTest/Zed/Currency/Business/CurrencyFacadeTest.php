<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Currency\Business;

use Codeception\Test\Unit;
use Generated\Shared\DataBuilder\CurrencyBuilder;
use Generated\Shared\Transfer\CurrencyTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\StoreTransfer;
use Spryker\Zed\Currency\Business\CurrencyFacade;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Currency
 * @group Business
 * @group Facade
 * @group CurrencyFacadeTest
 * Add your own group annotations below this line
 */
class CurrencyFacadeTest extends Unit
{
    protected const MESSAGE_CURRENCY_DATA_IS_MISSING = 'quote.validation.error.currency_mode_is_missing';
    protected const MESSAGE_CURRENCY_DATA_IS_INCORRECT = 'quote.validation.error.currency_mode_is_incorrect';
    protected const WRONG_ISO_CODE = 'WRONGCODE';
    protected const STORE_NAME = 'DE';

    /**
     * @var \SprykerTest\Zed\Currency\CurrencyBusinessTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function testGetByIdCurrencyShouldReturnCurrencyTransfer()
    {
        $idCurrency = $this->tester->haveCurrency();
        $currencyTransfer = $this->createCurrencyFacade()->getByIdCurrency($idCurrency);

        $this->assertNotNull($currencyTransfer);
    }

    /**
     * @return void
     */
    public function testCreateCurrencyShouldPersistGivenData()
    {
        $currencyTransfer = (new CurrencyBuilder())->build();

        $idCurrency = $this->createCurrencyFacade()->createCurrency($currencyTransfer);

        $this->assertNotNull($idCurrency);
    }

    /**
     * @return void
     */
    public function testGetByIdCurrencyShouldReturnCurrencyFromPersistence()
    {
        $currencyTransfer = $this->createCurrencyFacade()->getByIdCurrency(1);

        $this->assertInstanceOf(CurrencyTransfer::class, $currencyTransfer);
    }

    /**
     * @return void
     */
    public function testValidateCurrencyInQuoteWithEmptyCurrency()
    {
        $quoteTransfer = new QuoteTransfer();

        //Act
        $this->validateCurrencyInQuote($quoteTransfer, static::MESSAGE_CURRENCY_DATA_IS_MISSING);
    }

    /**
     * @return void
     */
    public function testValidateCurrencyInQuoteWithEmptyCurrencyIsoCode()
    {
        $currencyTransfer = new CurrencyTransfer();
        $quoteTransfer = (new QuoteTransfer())
            ->setCurrency($currencyTransfer);

        //Act
        $this->validateCurrencyInQuote($quoteTransfer, static::MESSAGE_CURRENCY_DATA_IS_MISSING);
    }

    /**
     * @return void
     */
    public function testValidateCurrencyInQuoteWithWrongCurrencyIsoCode()
    {
        $currencyTransfer = (new CurrencyTransfer())
            ->setCode(static::WRONG_ISO_CODE);
        $storeTransfer = (new StoreTransfer())
            ->setName(static::STORE_NAME);
        $quoteTransfer = (new QuoteTransfer())
            ->setCurrency($currencyTransfer)
            ->setStore($storeTransfer);

        //Act
        $this->validateCurrencyInQuote($quoteTransfer, static::MESSAGE_CURRENCY_DATA_IS_INCORRECT);
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     * @param string $errorMessage
     *
     * @return void
     */
    protected function validateCurrencyInQuote(QuoteTransfer $quoteTransfer, string $errorMessage): void
    {
        /** @var \Spryker\Zed\Currency\Business\CurrencyFacade $currencyFacade */
        $currencyFacade = $this->tester->getFacade();
        $quoteValidationResponseTransfer = $currencyFacade->validateCurrencyInQuote($quoteTransfer);

        $errors = array_map(function ($messageTransfer) {
            return $messageTransfer->getValue();
        }, (array)$quoteValidationResponseTransfer->getErrors());

        $this->assertFalse($quoteValidationResponseTransfer->getIsSuccess());
        $this->assertContains($errorMessage, $errors);
    }

    /**
     * @return \Spryker\Zed\Currency\Business\CurrencyFacadeInterface
     */
    protected function createCurrencyFacade()
    {
        return new CurrencyFacade();
    }
}
