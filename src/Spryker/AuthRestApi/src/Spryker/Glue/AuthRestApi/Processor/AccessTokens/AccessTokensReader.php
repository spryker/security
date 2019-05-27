<?php

/**
 * Copyright © 2017-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\AuthRestApi\Processor\AccessTokens;

use Generated\Shared\Transfer\OauthRequestTransfer;
use Generated\Shared\Transfer\RestAccessTokensAttributesTransfer;
use Generated\Shared\Transfer\RestErrorMessageTransfer;
use Generated\Shared\Transfer\RestTokenResponseAttributesTransfer;
use Spryker\Glue\AuthRestApi\AuthRestApiConfig;
use Spryker\Glue\AuthRestApi\Dependency\Client\AuthRestApiToOauthClientInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class AccessTokensReader implements AccessTokensReaderInterface
{
    /**
     * @var \Spryker\Glue\AuthRestApi\Dependency\Client\AuthRestApiToOauthClientInterface
     */
    protected $oauthClient;

    /**
     * @var \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface
     */
    protected $restResourceBuilder;

    /**
     * @var \Spryker\Glue\AuthRestApi\AuthRestApiConfig
     */
    protected $authRestApiConfig;

    /**
     * @param \Spryker\Glue\AuthRestApi\Dependency\Client\AuthRestApiToOauthClientInterface $oauthClient
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface $restResourceBuilder
     * @param \Spryker\Glue\AuthRestApi\AuthRestApiConfig $authRestApiConfig
     */
    public function __construct(
        AuthRestApiToOauthClientInterface $oauthClient,
        RestResourceBuilderInterface $restResourceBuilder,
        AuthRestApiConfig $authRestApiConfig
    ) {
        $this->oauthClient = $oauthClient;
        $this->restResourceBuilder = $restResourceBuilder;
        $this->authRestApiConfig = $authRestApiConfig;
    }

    /**
     * @param \Generated\Shared\Transfer\RestAccessTokensAttributesTransfer $restAccessTokensAttributesTransfer
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function processAccessTokenRequest(RestAccessTokensAttributesTransfer $restAccessTokensAttributesTransfer): RestResponseInterface
    {
        $oauthRequestTransfer = new OauthRequestTransfer();
        $oauthRequestTransfer->fromArray($restAccessTokensAttributesTransfer->toArray(), true);

        $oauthRequestTransfer
            ->setGrantType(AuthRestApiConfig::CLIENT_GRANT_PASSWORD);

        $oauthResponseTransfer = $this->oauthClient->processAccessTokenRequest($oauthRequestTransfer);

        if (!$oauthResponseTransfer->getIsValid()) {
            $restErrorTransfer = (new RestErrorMessageTransfer())
                ->setCode(AuthRestApiConfig::RESPONSE_INVALID_LOGIN)
                ->setStatus(Response::HTTP_UNAUTHORIZED)
                ->setDetail('Failed to authenticate user.');

            $response = $this->restResourceBuilder->createRestResponse();
            $response->addError($restErrorTransfer);

            return $response;
        }

        $restTokenAttributesTransfer = new RestTokenResponseAttributesTransfer();
        $restTokenAttributesTransfer->fromArray($oauthResponseTransfer->toArray(), true);

        $accessTokenResource = $this->restResourceBuilder
            ->createRestResource(
                AuthRestApiConfig::RESOURCE_ACCESS_TOKENS,
                null,
                $restTokenAttributesTransfer
            );

        $response = $this->restResourceBuilder->createRestResponse();
        $response->addResource($accessTokenResource);

        return $response;
    }
}
