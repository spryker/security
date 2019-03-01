<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Oauth\Communication\Plugin\Oauth;

use Generated\Shared\Transfer\OauthGrantConfigurationTransfer;
use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\Oauth\Business\Model\League\Grant\RefreshTokenGrant;
use Spryker\Zed\Oauth\OauthConfig;
use Spryker\Zed\OauthExtension\Dependency\Plugin\OauthGrantConfigurationProviderPluginInterface;

/**
 * @method \Spryker\Zed\OauthCompanyUser\OauthCompanyUserConfig getConfig()
 * @method \Spryker\Zed\OauthCompanyUser\Business\OauthCompanyUserFacadeInterface getFacade()
 */
class RefreshTokenOauthGrantConfigurationProviderPlugin extends AbstractPlugin implements OauthGrantConfigurationProviderPluginInterface
{
    /**
     * {@inheritdoc}
     *  - Returns configuration of RefreshTokenGrant.
     *
     * @api
     *
     * @return \Generated\Shared\Transfer\OauthGrantConfigurationTransfer
     */
    public function getGrantConfiguration(): OauthGrantConfigurationTransfer
    {
        return (new OauthGrantConfigurationTransfer())
            ->setIdentifier(OauthConfig::GRANT_TYPE_REFRESH_TOKEN)
            ->setFullyQualifiedClassName(RefreshTokenGrant::class);
    }
}
