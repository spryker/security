<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyBusinessUnitGui\Communication\Controller;

use Generated\Shared\Transfer\CompanyBusinessUnitTransfer;
use Spryker\Zed\Kernel\Communication\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;

/**
 * @method \Spryker\Zed\CompanyBusinessUnitGui\Communication\CompanyBusinessUnitGuiCommunicationFactory getFactory()
 */
class EditCompanyBusinessUnitController extends AbstractController
{
    protected const URL_PARAM_ID_COMPANY_BUSINESS_UNIT = 'id-company-business-unit';
    protected const URL_PARAM_REDIRECT_URL = 'redirect-url';
    protected const REDIRECT_URL_DEFAULT = '/company-business-unit-gui/list-company-business-unit';

    protected const MESSAGE_COMPANY_BUSINESS_UNIT_UPDATE_SUCCESS = 'Company Business Unit has been updated.';
    protected const MESSAGE_COMPANY_BUSINESS_UNIT_UPDATE_ERROR = 'Company Business Unit has not been updated.';

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     *
     * @return array|\Symfony\Component\HttpFoundation\RedirectResponse
     */
    public function indexAction(Request $request)
    {
        $idCompanyBusinessUnit = $this->castId($request->query->get(static::URL_PARAM_ID_COMPANY_BUSINESS_UNIT));
        $redirectUrl = $request->query->get(static::URL_PARAM_REDIRECT_URL, static::REDIRECT_URL_DEFAULT);

        $dataProvider = $this->getFactory()->createCompanyBusinessUnitFormDataProvider();
        $form = $this->getFactory()
            ->createCompanyBusinessUnitForm(
                $dataProvider->getData($idCompanyBusinessUnit),
                $dataProvider->getOptions($idCompanyBusinessUnit)
            )
            ->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $companyBusinessUnitTransfer = $form->getData();
            $companyResponseTransfer = $this->getFactory()
                ->getCompanyBusinessUnitFacde()
                ->update($companyBusinessUnitTransfer);

            if (!$companyResponseTransfer->getIsSuccessful()) {
                $this->addErrorMessage(static::MESSAGE_COMPANY_BUSINESS_UNIT_UPDATE_ERROR);

                return $this->viewResponse([
                    'form' => $form->createView(),
                    'idCompanyBusinessUnit' => $idCompanyBusinessUnit,
                ]);
            }

            $this->addSuccessMessage(static::MESSAGE_COMPANY_BUSINESS_UNIT_UPDATE_SUCCESS);

            return $this->redirectResponse($redirectUrl);
        }

        return $this->viewResponse([
            'form' => $form->createView(),
            'idCompany' => $idCompanyBusinessUnit,
        ]);
    }

    /**
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitTransfer
     */
    protected function createCompanyBusinessUnitTransfer(): CompanyBusinessUnitTransfer
    {
        return new CompanyBusinessUnitTransfer();
    }
}
