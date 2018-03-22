<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Money\Business;

use Generated\Shared\Transfer\CurrencyTransfer;
use Generated\Shared\Transfer\MoneyTransfer;
use Spryker\Shared\Money\Formatter\MoneyFormatterCollection;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\Money\Business\MoneyBusinessFactory getFactory()
 */
class MoneyFacade extends AbstractFacade implements MoneyFacadeInterface
{
    /**
     * Specification:
     * - Converts int amount and isoCode to MoneyTransfer Object
     * - If isoCode is not provided it will use from Store configured one
     *
     * @api
     *
     * @param int $amount
     * @param string|null $isoCode
     *
     * @return \Generated\Shared\Transfer\MoneyTransfer
     */
    public function fromInteger($amount, $isoCode = null)
    {
        return $this->getFactory()->createMoneyBuilder()->fromInteger($amount, $isoCode);
    }

    /**
     * Specification:
     * - Converts float amount and isoCode to MoneyTransfer Object
     * - If isoCode is not provided it will use from Store configured one
     *
     * @api
     *
     * @param float $amount
     * @param string|null $isoCode
     *
     * @return \Generated\Shared\Transfer\MoneyTransfer
     */
    public function fromFloat($amount, $isoCode = null)
    {
        return $this->getFactory()->createMoneyBuilder()->fromFloat($amount, $isoCode);
    }

    /**
     * Specification:
     * - Converts string amount and isoCode to MoneyTransfer Object
     * - If isoCode is not provided it will use from Store configured one
     *
     * @api
     *
     * @param string $amount
     * @param string|null $isoCode
     *
     * @return \Generated\Shared\Transfer\MoneyTransfer
     */
    public function fromString($amount, $isoCode = null)
    {
        return $this->getFactory()->createMoneyBuilder()->fromString($amount, $isoCode);
    }

    /**
     * Specification:
     * - Converts MoneyTransfer Object into string representation with currency symbol
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\MoneyTransfer $moneyTransfer
     *
     * @return string
     */
    public function formatWithSymbol(MoneyTransfer $moneyTransfer)
    {
        return $this->getFactory()->createMoneyFormatter()->format(
            $moneyTransfer,
            MoneyFormatterCollection::FORMATTER_WITH_SYMBOL
        );
    }

    /**
     * Specification:
     * - Converts MoneyTransfer Object into string representation without currency symbol
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\MoneyTransfer $moneyTransfer
     *
     * @return string
     */
    public function formatWithoutSymbol(MoneyTransfer $moneyTransfer)
    {
        return $this->getFactory()->createMoneyFormatter()->format(
            $moneyTransfer,
            MoneyFormatterCollection::FORMATTER_WITHOUT_SYMBOL
        );
    }

    /**
     * Specification:
     * - Parses a formatted string representation to MoneyTransfer
     *
     * @api
     *
     * @param string $value
     * @param \Generated\Shared\Transfer\CurrencyTransfer $currencyTransfer
     *
     * @return \Generated\Shared\Transfer\MoneyTransfer
     */
    public function parse($value, CurrencyTransfer $currencyTransfer)
    {
        return $this->getFactory()->createMoneyParser()->parse($value, $currencyTransfer);
    }

    /**
     * Specification
     * - Converts an integer value into decimal value
     *
     * @api
     *
     * @param int $value
     *
     * @return float
     */
    public function convertIntegerToDecimal($value)
    {
        return $this->getFactory()->createIntegerToDecimalConverter()->convert($value);
    }

    /**
     * Specification
     * - Converts a decimal value into integer value
     *
     * @api
     *
     * @param float $value
     *
     * @return int
     */
    public function convertDecimalToInteger($value)
    {
        return $this->getFactory()->createDecimalToIntegerConverter()->convert($value);
    }
}
