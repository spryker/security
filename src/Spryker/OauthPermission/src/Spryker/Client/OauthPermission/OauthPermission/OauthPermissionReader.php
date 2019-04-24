<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\OauthPermission\OauthPermission;

use Generated\Shared\Transfer\CustomerIdentifierTransfer;
use Generated\Shared\Transfer\OauthAccessTokenDataTransfer;
use Generated\Shared\Transfer\PermissionCollectionTransfer;
use Spryker\Client\OauthPermission\Dependency\Service\OauthPermissionToOauthServiceInterface;
use Spryker\Client\OauthPermission\Dependency\Service\OauthPermissionToUtilEncodingServiceInterface;
use Spryker\Client\OauthPermission\OauthPermissionConfig;
use Spryker\Glue\Kernel\Application;

class OauthPermissionReader implements OauthPermissionReaderInterface
{
    /**
     * @var \Spryker\Glue\Kernel\Application
     */
    protected $glueApplication;

    /**
     * @var \Spryker\Client\OauthPermission\Dependency\Service\OauthPermissionToOauthServiceInterface
     */
    protected $oauthService;

    /**
     * @var \Spryker\Client\OauthPermission\Dependency\Service\OauthPermissionToUtilEncodingServiceInterface
     */
    protected $utilEncodingService;

    /**
     * @param \Spryker\Client\OauthPermission\Dependency\Service\OauthPermissionToOauthServiceInterface $oauthService
     * @param \Spryker\Client\OauthPermission\Dependency\Service\OauthPermissionToUtilEncodingServiceInterface $utilEncodingService
     * @param \Spryker\Glue\Kernel\Application|null $glueApplication
     */
    public function __construct(
        OauthPermissionToOauthServiceInterface $oauthService,
        OauthPermissionToUtilEncodingServiceInterface $utilEncodingService,
        ?Application $glueApplication = null
    ) {
        $this->glueApplication = $glueApplication;
        $this->oauthService = $oauthService;
        $this->utilEncodingService = $utilEncodingService;
    }

    /**
     * @return \Generated\Shared\Transfer\PermissionCollectionTransfer
     */
    public function getPermissionsFromOauthToken(): PermissionCollectionTransfer
    {
        if ($this->glueApplication === null) {
            return new PermissionCollectionTransfer();
        }

        /** @var \Symfony\Component\HttpFoundation\Request $request */
        $request = $this->glueApplication->get('request');
        $authorizationToken = $request->headers->get(OauthPermissionConfig::HEADER_AUTHORIZATION);

        if (!$authorizationToken) {
            return new PermissionCollectionTransfer();
        }

        [$type, $accessToken] = $this->extractToken($authorizationToken);

        $oauthAccessTokenDataTransfer = $this->oauthService->extractAccessTokenData($accessToken);

        $customerPermissions = $this->extractPermissionsFromOauthToken($oauthAccessTokenDataTransfer);

        if (!$customerPermissions) {
            return new PermissionCollectionTransfer();
        }

        return $customerPermissions;
    }

    /**
     * @param \Generated\Shared\Transfer\OauthAccessTokenDataTransfer $oauthAccessTokenDataTransfer
     *
     * @return \Generated\Shared\Transfer\PermissionCollectionTransfer|null
     */
    protected function extractPermissionsFromOauthToken(OauthAccessTokenDataTransfer $oauthAccessTokenDataTransfer): ?PermissionCollectionTransfer
    {
        $customerIdentifier = (new CustomerIdentifierTransfer())
            ->fromArray($this->utilEncodingService->decodeJson($oauthAccessTokenDataTransfer->getOauthUserId(), true));

        return $customerIdentifier->getPermissions();
    }

    /**
     * @param string $authorizationToken
     *
     * @return array
     */
    protected function extractToken(string $authorizationToken): array
    {
        return preg_split('/\s+/', $authorizationToken);
    }
}
