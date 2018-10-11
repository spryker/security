<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyRoleGui\Communication\Plugin\CompanyUserGui;

use Generated\Shared\Transfer\CompanyRoleCriteriaFilterTransfer;
use Spryker\Zed\CompanyRoleGui\CompanyRoleGuiConfig;
use Spryker\Zed\CompanyUserGui\CompanyUserGuiConfig;
use Spryker\Zed\CompanyUserGuiExtension\Dependency\Plugin\CompanyUserTablePrepareDataExpanderPluginInterface;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;

/**
 * @method \Spryker\Zed\CompanyRoleGui\Communication\CompanyRoleGuiCommunicationFactory getFactory()
 */
class CompanyRoleCompanyUserTablePrepareDataExpanderPlugin extends AbstractPlugin implements CompanyUserTablePrepareDataExpanderPluginInterface
{
    /**
     * @see \Spryker\Zed\CompanyUserGui\CompanyUserGuiConfig
     */
    protected const COL_ID_COMPANY_USER = CompanyUserGuiConfig::COL_ID_COMPANY_USER;

    /**
     * {@inheritdoc}
     * - Expands table data rows of company user table with company role names.
     *
     * @api
     *
     * @param array $companyUserDataItem
     *
     * @return array
     */
    public function expandDataItem(array $companyUserDataItem): array
    {
        $idCompanyUser = $companyUserDataItem[static::COL_ID_COMPANY_USER];

        $companyRoles = $this->getFactory()->getCompanyRoleFacade()->getCompanyRoleCollection(
            (new CompanyRoleCriteriaFilterTransfer())->setIdCompanyUser($idCompanyUser)
        )
        ->getRoles();

        $companyUserRoleNames = '';
        if ($companyRoles->count() > 0) {
            foreach ($companyRoles as $companyRole) {
                $companyUserRoleNames .= '<p>' . $companyRole->getName() . '</p>';
            }
        }

        return array_merge(
            $companyUserDataItem,
            [
                CompanyRoleGuiConfig::COL_COMPANY_ROLE_NAMES => $companyUserRoleNames,
            ]
        );
    }
}
