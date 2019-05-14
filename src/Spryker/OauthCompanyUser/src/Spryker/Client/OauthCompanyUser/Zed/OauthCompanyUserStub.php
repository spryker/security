<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\OauthCompanyUser\Zed;

use Generated\Shared\Transfer\CompanyUserAccessTokenRequestTransfer;
use Generated\Shared\Transfer\CustomerTransfer;
use Spryker\Client\OauthCompanyUser\Dependency\Client\OauthCompanyUserToZedRequestClientInterface;

class OauthCompanyUserStub implements OauthCompanyUserStubInterface
{
    /**
     * @var \Spryker\Client\OauthCompanyUser\Dependency\Client\OauthCompanyUserToZedRequestClientInterface
     */
    protected $zedRequestClient;

    /**
     * @param \Spryker\Client\OauthCompanyUser\Dependency\Client\OauthCompanyUserToZedRequestClientInterface $zedRequestClient
     */
    public function __construct(OauthCompanyUserToZedRequestClientInterface $zedRequestClient)
    {
        $this->zedRequestClient = $zedRequestClient;
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyUserAccessTokenRequestTransfer $companyUserAccessTokenRequestTransfer
     *
     * @return \Generated\Shared\Transfer\CustomerTransfer
     */
    public function getCustomerByAccessToken(CompanyUserAccessTokenRequestTransfer $companyUserAccessTokenRequestTransfer): CustomerTransfer
    {
        /** @var \Generated\Shared\Transfer\CustomerTransfer $customerTransfer */
        $customerTransfer = $this->zedRequestClient->call(
            '/oauth-company-user/gateway/get-customer-by-access-token',
            $companyUserAccessTokenRequestTransfer
        );

        return $customerTransfer;
    }
}
