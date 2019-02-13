<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\OauthCompanyUser;

use Spryker\Shared\Kernel\AbstractBundleConfig;

class OauthCompanyUserConfig extends AbstractBundleConfig
{
    /**
     * The client secret used to authenticate Oauth client requests, to create use "password_hash('your password', PASSWORD_BCRYPT)".
     *
     * @return string
     */
    public function getClientSecret(): string
    {
        return $this->get(OauthCompanyUserConstants::OAUTH_CLIENT_SECRET);
    }

    /**
     * The client id as is store in spy_oauth_client database table
     *
     * @return string
     */
    public function getClientId(): string
    {
        return $this->get(OauthCompanyUserConstants::OAUTH_CLIENT_IDENTIFIER);
    }
}
