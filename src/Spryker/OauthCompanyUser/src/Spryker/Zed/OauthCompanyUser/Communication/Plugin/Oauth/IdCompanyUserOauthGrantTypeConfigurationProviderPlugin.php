<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\OauthCompanyUser\Communication\Plugin\Oauth;

use Generated\Shared\Transfer\OauthGrantTypeConfigurationTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\OauthCompanyUser\Business\League\Grant\IdCompanyUserGrantTypeType;
use Spryker\Zed\OauthCompanyUser\OauthCompanyUserConfig;
use Spryker\Zed\OauthExtension\Dependency\Plugin\OauthGrantTypeConfigurationProviderPluginInterface;

/**
 * @method \Spryker\Zed\OauthCompanyUser\OauthCompanyUserConfig getConfig()
 * @method \Spryker\Zed\OauthCompanyUser\Business\OauthCompanyUserFacadeInterface getFacade()
 */
class IdCompanyUserOauthGrantTypeConfigurationProviderPlugin extends AbstractPlugin implements OauthGrantTypeConfigurationProviderPluginInterface
{
    /**
     * {@inheritdoc}
     *  - Returns configuration of IdCompanyUser GrantType.
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\OauthGrantTypeConfigurationTransfer
     */
    public function getGrantTypeConfiguration(): OauthGrantTypeConfigurationTransfer
    {
        return (new OauthGrantTypeConfigurationTransfer())
            ->setIdentifier(OauthCompanyUserConfig::GRANT_TYPE_ID_COMPANY_USER)
            ->setFullyQualifiedClassName(IdCompanyUserGrantTypeType::class);
    }
}
