<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CheckoutRestApi\Processor\Checkout;

use ArrayObject;
use Generated\Shared\Transfer\RestCheckoutErrorTransfer;
use Generated\Shared\Transfer\RestCheckoutRequestAttributesTransfer;
use Generated\Shared\Transfer\RestCheckoutResponseAttributesTransfer;
use Generated\Shared\Transfer\RestErrorMessageTransfer;
use Spryker\Client\CheckoutRestApi\CheckoutRestApiClientInterface;
use Spryker\Glue\CheckoutRestApi\CheckoutRestApiConfig;
use Spryker\Glue\CheckoutRestApi\Dependency\Client\CheckoutRestApiToGlossaryStorageClientInterface;
use Spryker\Glue\CheckoutRestApi\Processor\Customer\CustomerMapperInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Symfony\Component\HttpFoundation\Response;

class CheckoutProcessor implements CheckoutProcessorInterface
{
    /**
     * @var \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface
     */
    protected $restResourceBuilder;

    /**
     * @var \Spryker\Glue\CheckoutRestApi\Dependency\Client\CheckoutRestApiToGlossaryStorageClientInterface
     */
    protected $glossaryStorageClient;

    /**
     * @var \Spryker\Client\CheckoutRestApi\CheckoutRestApiClientInterface
     */
    protected $checkoutRestApiClient;

    /**
     * @var \Spryker\Glue\CheckoutRestApi\Processor\Customer\CustomerMapperInterface
     */
    protected $customerMapper;

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface $restResourceBuilder
     * @param \Spryker\Client\CheckoutRestApi\CheckoutRestApiClientInterface $checkoutRestApiClient
     * @param \Spryker\Glue\CheckoutRestApi\Dependency\Client\CheckoutRestApiToGlossaryStorageClientInterface $glossaryStorageClient
     * @param \Spryker\Glue\CheckoutRestApi\Processor\Customer\CustomerMapperInterface $customerMapper
     */
    public function __construct(
        RestResourceBuilderInterface $restResourceBuilder,
        CheckoutRestApiClientInterface $checkoutRestApiClient,
        CheckoutRestApiToGlossaryStorageClientInterface $glossaryStorageClient,
        CustomerMapperInterface $customerMapper
    ) {
        $this->restResourceBuilder = $restResourceBuilder;
        $this->checkoutRestApiClient = $checkoutRestApiClient;
        $this->glossaryStorageClient = $glossaryStorageClient;
        $this->customerMapper = $customerMapper;
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     * @param \Generated\Shared\Transfer\RestCheckoutRequestAttributesTransfer $restCheckoutRequestAttributesTransfer
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function placeOrder(RestRequestInterface $restRequest, RestCheckoutRequestAttributesTransfer $restCheckoutRequestAttributesTransfer): RestResponseInterface
    {
        $customerValidationError = $this->validateCustomer($restRequest);
        if ($customerValidationError !== null) {
            return $this->restResourceBuilder
                ->createRestResponse()
                ->addError($customerValidationError);
        }

        $restCustomerTransfer = $this->customerMapper->mapRestCustomerTransferFromRestCheckoutRequest($restRequest, $restCheckoutRequestAttributesTransfer);
        $restCheckoutRequestAttributesTransfer->setCustomer($restCustomerTransfer);

        $restCheckoutResponseTransfer = $this->checkoutRestApiClient->placeOrder($restCheckoutRequestAttributesTransfer);
        if (!$restCheckoutResponseTransfer->getIsSuccess()) {
            return $this->createPlaceOrderFailedErrorResponse($restCheckoutResponseTransfer->getErrors(), $restRequest->getMetadata()->getLocale());
        }

        return $this->createOrderPlacedResponse($restCheckoutResponseTransfer->getOrderReference());
    }

    /**
     * @param \Generated\Shared\Transfer\RestCheckoutErrorTransfer[]|\ArrayObject $errors
     * @param string $localeName
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    protected function createPlaceOrderFailedErrorResponse(ArrayObject $errors, string $localeName): RestResponseInterface
    {
        $restResponse = $this->restResourceBuilder->createRestResponse();

        foreach ($errors as $restCheckoutErrorTransfer) {
            $restResponse->addError((new RestErrorMessageTransfer())
                ->setCode($restCheckoutErrorTransfer->getCode())
                ->setStatus($restCheckoutErrorTransfer->getStatus())
                ->setDetail($this->translateCheckoutErrorMessage($restCheckoutErrorTransfer, $localeName)));
        }

        return $restResponse;
    }

    /**
     * @param \Generated\Shared\Transfer\RestCheckoutErrorTransfer $restCheckoutErrorTransfer
     * @param string $localeName
     *
     * @return string
     */
    protected function translateCheckoutErrorMessage(RestCheckoutErrorTransfer $restCheckoutErrorTransfer, string $localeName): string
    {
        $checkoutErrorMessage = $restCheckoutErrorTransfer->getDetail();

        return $this->glossaryStorageClient->translate(
            $checkoutErrorMessage,
            $localeName,
            $restCheckoutErrorTransfer->getParameters()
        ) ?: $checkoutErrorMessage;
    }

    /**
     * @param string $orderReference
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    protected function createOrderPlacedResponse(string $orderReference): RestResponseInterface
    {
        $restResource = $this->restResourceBuilder->createRestResource(
            CheckoutRestApiConfig::RESOURCE_CHECKOUT,
            null,
            (new RestCheckoutResponseAttributesTransfer())->setOrderReference($orderReference)
        );

        return $this->restResourceBuilder
            ->createRestResponse()
            ->addResource($restResource);
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Generated\Shared\Transfer\RestErrorMessageTransfer|null
     */
    protected function validateCustomer(RestRequestInterface $restRequest): ?RestErrorMessageTransfer
    {
        if ($restRequest->getUser() === null) {
            return (new RestErrorMessageTransfer())
                ->setStatus(Response::HTTP_BAD_REQUEST)
                ->setCode(CheckoutRestApiConfig::RESPONSE_CODE_USER_IS_NOT_SPECIFIED)
                ->setDetail(CheckoutRestApiConfig::RESPONSE_DETAILS_USER_IS_NOT_SPECIFIED);
        }

        return null;
    }
}
