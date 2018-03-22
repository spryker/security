<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\Money\Formatter\IntlMoneyFormatter;

use Generated\Shared\Transfer\MoneyTransfer;
use Money\Currencies\ISOCurrencies;
use Money\Formatter\IntlMoneyFormatter as InnerFormatter;
use Spryker\Shared\Kernel\Store;
use Spryker\Shared\Money\Formatter\MoneyFormatterInterface;
use Spryker\Shared\Money\Mapper\TransferToMoneyMapperInterface;

abstract class AbstractIntlMoneyFormatter implements MoneyFormatterInterface
{
    /**
     * @var \Spryker\Shared\Money\Mapper\TransferToMoneyMapperInterface
     */
    protected $converter;

    /**
     * @param \Spryker\Shared\Money\Mapper\TransferToMoneyMapperInterface $transferToMoneyConverter
     */
    public function __construct(TransferToMoneyMapperInterface $transferToMoneyConverter)
    {
        $this->converter = $transferToMoneyConverter;
    }

    /**
     * @param \Generated\Shared\Transfer\MoneyTransfer $moneyTransfer
     *
     * @return string
     */
    public function format(MoneyTransfer $moneyTransfer)
    {
        $locale = $this->getLocale($moneyTransfer);
        $formatter = $this->getInnerFormatter($locale);

        $money = $this->converter->convert($moneyTransfer);
        $formatted = $formatter->format($money);

        return $formatted;
    }

    /**
     * @param \Generated\Shared\Transfer\MoneyTransfer $moneyTransfer
     *
     * @return string
     */
    protected function getLocale(MoneyTransfer $moneyTransfer)
    {
        if ($moneyTransfer->getLocale()) {
            return $moneyTransfer->getLocale()->getLocaleName();
        }

        return Store::getInstance()->getCurrentLocale();
    }

    /**
     * @param string $localeName
     *
     * @return \Money\Formatter\IntlMoneyFormatter
     */
    protected function getInnerFormatter($localeName)
    {
        return new InnerFormatter(
            $this->getNumberFormatter($localeName),
            $this->getIsoCurrencies()
        );
    }

    /**
     * @param string $localeName
     *
     * @return \NumberFormatter
     */
    abstract protected function getNumberFormatter($localeName);

    /**
     * @return \Money\Currencies\ISOCurrencies
     */
    protected function getIsoCurrencies()
    {
        return new ISOCurrencies();
    }
}
