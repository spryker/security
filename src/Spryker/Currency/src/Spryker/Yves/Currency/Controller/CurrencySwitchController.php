<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Yves\Currency\Controller;

use Spryker\Yves\Kernel\Controller\AbstractController;

use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Yves\Currency\CurrencyFactory getFactory()
 */
class CurrencySwitchController extends AbstractController
{

    const URL_PARAM_CURRENCY_ISO_CODE = 'currency-iso-code';
    const URL_PARAM_REFERRER_URL = 'referrer-url';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return \Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $currencyIsoCode = $request->get(static::URL_PARAM_CURRENCY_ISO_CODE);

        $this->getFactory()
            ->createCurrencyPersistence()
            ->setCurrentCurrencyIsoCode($currencyIsoCode);

        $this->getFactory()
            ->createCurrencyPostChangePluginExecutor()
            ->execute($currencyIsoCode);

        return $this->redirectResponseExternal(
            urldecode($request->get(static::URL_PARAM_REFERRER_URL))
        );
    }

}
