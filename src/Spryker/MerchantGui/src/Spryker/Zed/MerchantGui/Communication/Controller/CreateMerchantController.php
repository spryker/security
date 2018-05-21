<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\MerchantGui\Communication\Controller;

use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Spryker\Zed\MerchantGui\Communication\Table\MerchantTableConstants;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\MerchantGui\Communication\MerchantGuiCommunicationFactory getFactory()
 */
class CreateMerchantController extends AbstractController
{
    protected const PARAM_REDIRECT_URL = 'redirect-url';

    protected const MESSAGE_MERCHANT_CREATE_SUCCESS = 'Merchant has been created.';
    protected const MESSAGE_MERCHANT_CREATE_ERROR = 'Merchant has not been created.';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $redirectUrl = $request->get(static::PARAM_REDIRECT_URL, MerchantTableConstants::URL_MERCHANT_LIST);

        $dataProvider = $this->getFactory()->createMerchantFormDataProvider();
        $merchantForm = $this->getFactory()
            ->getMerchantForm(
                $dataProvider->getData(),
                $dataProvider->getOptions()
            )
            ->handleRequest($request);

        if ($merchantForm->isSubmitted() && $merchantForm->isValid()) {
            $merchantTransfer = $merchantForm->getData();
            $merchantTransfer = $this->getFactory()
                ->getMerchantFacade()
                ->createMerchant($merchantTransfer);

            if (!$merchantTransfer->getIdMerchant()) {
                $this->addErrorMessage(static::MESSAGE_MERCHANT_CREATE_ERROR);

                return $this->viewResponse([
                    'form' => $merchantForm->createView(),
                ]);
            }

            $this->addSuccessMessage(static::MESSAGE_MERCHANT_CREATE_SUCCESS);

            return $this->redirectResponse($redirectUrl);
        }

        return $this->viewResponse([
            'form' => $merchantForm->createView(),
        ]);
    }
}
