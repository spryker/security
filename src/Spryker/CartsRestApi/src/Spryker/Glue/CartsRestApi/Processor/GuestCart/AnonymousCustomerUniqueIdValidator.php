<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CartsRestApi\Processor\GuestCart;

use Generated\Shared\Transfer\RestErrorMessageTransfer;
use Spryker\Glue\CartsRestApi\CartsRestApiConfig;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class AnonymousCustomerUniqueIdValidator implements AnonymousCustomerUniqueIdValidatorInterface
{
    /**
     * @var \Spryker\Glue\CartsRestApi\CartsRestApiConfig
     */
    protected $config;

    /**
     * @param \Spryker\Glue\CartsRestApi\CartsRestApiConfig $config
     */
    public function __construct(CartsRestApiConfig $config)
    {
        $this->config = $config;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $httpRequest
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Generated\Shared\Transfer\RestErrorMessageTransfer|null
     */
    public function validate(Request $httpRequest, RestRequestInterface $restRequest): ?RestErrorMessageTransfer
    {
        if (!$this->isAnonymousHeaderSet($httpRequest) && $this->isAnonymousHeaderRequired($restRequest)) {
            return (new RestErrorMessageTransfer())
                ->setStatus(Response::HTTP_BAD_REQUEST)
                ->setCode(CartsRestApiConfig::RESPONSE_CODE_ANONYMOUS_CUSTOMER_UNIQUE_ID_EMPTY)
                ->setDetail(CartsRestApiConfig::EXCEPTION_MESSAGE_ANONYMOUS_CUSTOMER_UNIQUE_ID_EMPTY);
        }

        return null;
    }

    /**
     * @param \Symfony\Component\HttpFoundation\Request $httpRequest
     *
     * @return bool
     */
    protected function isAnonymousHeaderSet(Request $httpRequest): bool
    {
        return $httpRequest->headers->has(CartsRestApiConfig::HEADER_ANONYMOUS_CUSTOMER_UNIQUE_ID)
            && $httpRequest->headers->get(CartsRestApiConfig::HEADER_ANONYMOUS_CUSTOMER_UNIQUE_ID);
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return bool
     */
    protected function isAnonymousHeaderRequired(RestRequestInterface $restRequest): bool
    {
        if (in_array($restRequest->getResource()->getType(), $this->config->getGuestCartResources(), true)) {
            return true;
        }

        foreach ($this->config->getGuestCartResources() as $resource) {
            if ($restRequest->findParentResourceByType($resource)) {
                return true;
            }
        }

        return false;
    }
}
