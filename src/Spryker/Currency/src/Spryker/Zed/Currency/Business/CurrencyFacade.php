<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Currency\Business;

use Generated\Shared\Transfer\CurrencyTransfer;
use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\Currency\Business\CurrencyBusinessFactory getFactory()
 */
class CurrencyFacade extends AbstractFacade implements CurrencyFacadeInterface
{

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $isoCode
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function fromIsoCode($isoCode)
    {
        return $this->getFactory()->createCurrencyBuilder()->fromIsoCode($isoCode);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function getCurrent()
    {
        return $this->getFactory()->createCurrencyBuilder()->getCurrent();
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param \Generated\Shared\Transfer\CurrencyTransfer $currencyTransfer
     *
     * @return int
     */
    public function createCurrency(CurrencyTransfer $currencyTransfer)
    {
        return $this->getFactory()
            ->createCurrencyWriter()
            ->create($currencyTransfer);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param int $idCurrency
     *
     * @throws \Spryker\Zed\Currency\Business\Model\Exception\CurrencyNotFoundException
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    public function getByIdCurrency($idCurrency)
    {
        return $this->getFactory()->createCurrencyReader()->getByIdCurrency($idCurrency);
    }

}
