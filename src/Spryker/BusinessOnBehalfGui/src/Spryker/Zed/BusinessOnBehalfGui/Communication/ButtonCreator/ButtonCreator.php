<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\BusinessOnBehalfGui\Communication\ButtonCreator;

use Generated\Shared\Transfer\ButtonTransfer;
use Generated\Shared\Transfer\CustomerTransfer;
use Spryker\Service\UtilText\Model\Url\Url;
use Spryker\Zed\BusinessOnBehalfGui\Dependency\Facade\BusinessOnBehalfGuiToCompanyUserFacadeInterface;

class ButtonCreator implements ButtonCreatorInterface
{
    protected const URL_ATTACH_CUSTOMER_TO_COMPANY = 'company-user-gui/create-company-user/attach-customer';
    protected const BUTTON_ATTACH_CUSTOMER_TO_COMPANY_TITLE = 'Attach to company';

    protected const PARAM_ID_CUSTOMER = 'id-customer';

    /**
     * @var \Spryker\Zed\BusinessOnBehalfGui\Dependency\Facade\BusinessOnBehalfGuiToCompanyUserFacadeInterface
     */
    protected $companyUserFacade;

    /**
     * @param \Spryker\Zed\BusinessOnBehalfGui\Dependency\Facade\BusinessOnBehalfGuiToCompanyUserFacadeInterface $companyUserFacade
     */
    public function __construct(
        BusinessOnBehalfGuiToCompanyUserFacadeInterface $companyUserFacade
    ) {
        $this->companyUserFacade = $companyUserFacade;
    }

    /**
     * @param int $idCustomer
     * @param \Generated\Shared\Transfer\ButtonTransfer[] $buttonTransfers
     *
     * @return \Generated\Shared\Transfer\ButtonTransfer[]
     */
    public function addAttachCustomerToCompanyButton(int $idCustomer, array $buttonTransfers): array
    {
        $activeCompanyUsersCount = $this->companyUserFacade->countActiveCompanyUsersByIdCustomer(
            (new CustomerTransfer())->setIdCustomer($idCustomer)
        );

        if ($activeCompanyUsersCount === 0) {
            return $buttonTransfers;
        }

        $buttonTransfers[] = $this->buildAttachCustomerToCompanyButton($idCustomer);

        return $buttonTransfers;
    }

    /**
     * @param int $idCustomer
     *
     * @return \Generated\Shared\Transfer\ButtonTransfer
     */
    protected function buildAttachCustomerToCompanyButton(int $idCustomer): ButtonTransfer
    {
        $defaultOptions = [
            'class' => 'btn-create',
            'icon' => 'fa-plus',
        ];
        $url = Url::generate(static::URL_ATTACH_CUSTOMER_TO_COMPANY, [
            static::PARAM_ID_CUSTOMER => $idCustomer,
        ]);

        return $this->generateButtonTransfer($url, static::BUTTON_ATTACH_CUSTOMER_TO_COMPANY_TITLE, $defaultOptions);
    }

    /**
     * @param string $url
     * @param string $title
     * @param array $defaultOptions
     * @param array|null $customOptions
     *
     * @return \Generated\Shared\Transfer\ButtonTransfer
     */
    protected function generateButtonTransfer(string $url, string $title, array $defaultOptions, ?array $customOptions = null): ButtonTransfer
    {
        return (new ButtonTransfer())
            ->setUrl($url)
            ->setTitle($title)
            ->setDefaultOptions($defaultOptions)
            ->setCustomOptions($customOptions);
    }
}
