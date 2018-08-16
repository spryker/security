<?php
/**
 * Copyright © 2017-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\AuthRestApi\Processor\AccessTokens;

use Generated\Shared\Transfer\OauthAccessTokenValidationRequestTransfer;
use Generated\Shared\Transfer\OauthAccessTokenValidationResponseTransfer;
use Generated\Shared\Transfer\RestErrorCollectionTransfer;
use Generated\Shared\Transfer\RestErrorMessageTransfer;
use Spryker\Glue\AuthRestApi\AuthRestApiConfig;
use Spryker\Glue\AuthRestApi\Dependency\Client\AuthRestApiToOauthClientInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class AccessTokenValidator implements AccessTokenValidatorInterface
{
    /**
     * @var \Spryker\Glue\AuthRestApi\Dependency\Client\AuthRestApiToOauthClientInterface
     */
    protected $oauthClient;

    /**
     * @param \Spryker\Glue\AuthRestApi\Dependency\Client\AuthRestApiToOauthClientInterface $oauthClient
     */
    public function __construct(AuthRestApiToOauthClientInterface $oauthClient)
    {
        $this->oauthClient = $oauthClient;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $request
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Generated\Shared\Transfer\RestErrorCollectionTransfer|null
     */
    public function validate(Request $request, RestRequestInterface $restRequest): ?RestErrorCollectionTransfer
    {
        $isProtected = $request->attributes->get('is-protected', false);

        if ($isProtected === false) {
            return null;
        }

        $authorizationToken = $request->headers->get('Authorization');
        if (!$authorizationToken) {
            return (new RestErrorCollectionTransfer())
                ->addRestErrors(
                    $this->createErrorMessageTransfer(
                        'Missing access token.',
                        Response::HTTP_FORBIDDEN,
                        AuthRestApiConfig::RESPONSE_CODE_FORBIDDEN
                    )
                );
        }

        $authAccessTokenValidationResponseTransfer = $this->validateAccessToken((string)$authorizationToken);

        if (!$authAccessTokenValidationResponseTransfer->getIsValid()) {
            return (new RestErrorCollectionTransfer())
                ->addRestErrors(
                    $this->createErrorMessageTransfer(
                        'Invalid access token.',
                        Response::HTTP_UNAUTHORIZED,
                        AuthRestApiConfig::RESPONSE_CODE_ACCESS_CODE_INVALID
                    )
                );
        }
        $this->setCustomerData($restRequest, $authAccessTokenValidationResponseTransfer);

        return null;
    }

    /**
     * @param string $detail
     * @param int $status
     * @param string $code
     *
     * @return \Generated\Shared\Transfer\RestErrorMessageTransfer
     */
    protected function createErrorMessageTransfer(
        string $detail,
        int $status,
        string $code
    ): RestErrorMessageTransfer {

        return (new RestErrorMessageTransfer())
            ->setDetail($detail)
            ->setStatus($status)
            ->setCode($code);
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

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     * @param \Generated\Shared\Transfer\OauthAccessTokenValidationResponseTransfer $authAccessTokenValidationResponseTransfer
     *
     * @return void
     */
    protected function setCustomerData(
        RestRequestInterface $restRequest,
        OauthAccessTokenValidationResponseTransfer $authAccessTokenValidationResponseTransfer
    ): void {

        $customerIdentifier = json_decode($authAccessTokenValidationResponseTransfer->getOauthUserId(), true);
        $restRequest->setUser(
            $customerIdentifier['id_customer'],
            $customerIdentifier['customer_reference'],
            $authAccessTokenValidationResponseTransfer->getOauthScopes()
        );
    }

    /**
     * @param string $authorizationToken
     *
     * @return \Generated\Shared\Transfer\OauthAccessTokenValidationResponseTransfer
     */
    protected function validateAccessToken(string $authorizationToken): OauthAccessTokenValidationResponseTransfer
    {
        [$type, $accessToken] = $this->extractToken($authorizationToken);

        $authAccessTokenValidationRequestTransfer = new OauthAccessTokenValidationRequestTransfer();
        $authAccessTokenValidationRequestTransfer
            ->setAccessToken($accessToken)
            ->setType($type);

        $authAccessTokenValidationResponseTransfer = $this->oauthClient->validateAccessToken(
            $authAccessTokenValidationRequestTransfer
        );

        return $authAccessTokenValidationResponseTransfer;
    }
}
