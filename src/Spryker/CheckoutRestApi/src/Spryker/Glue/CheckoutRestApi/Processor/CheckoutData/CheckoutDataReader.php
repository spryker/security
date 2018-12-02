<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CheckoutRestApi\Processor\CheckoutData;

use Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer;
use Generated\Shared\Transfer\RestCheckoutDataResponseTransfer;
use Generated\Shared\Transfer\RestCheckoutRequestAttributesTransfer;
use Generated\Shared\Transfer\RestErrorCollectionTransfer;
use Generated\Shared\Transfer\RestErrorMessageTransfer;
use Spryker\Client\CheckoutRestApi\CheckoutRestApiClientInterface;
use Spryker\Glue\CheckoutRestApi\CheckoutRestApiConfig;
use Spryker\Glue\CheckoutRestApi\Processor\Customer\CustomerMapperInterface;
use Spryker\Glue\CheckoutRestApi\Processor\Validator\CheckoutRequestValidatorInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Symfony\Component\HttpFoundation\Response;

class CheckoutDataReader implements CheckoutDataReaderInterface
{
    /**
     * @var \Spryker\Client\CheckoutRestApi\CheckoutRestApiClientInterface
     */
    protected $checkoutRestApiClient;

    /**
     * @var \Spryker\Glue\CheckoutRestApi\Processor\CheckoutData\CheckoutDataMapperInterface
     */
    protected $checkoutDataMapper;

    /**
     * @var \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface
     */
    protected $restResourceBuilder;

    /**
     * @var \Spryker\Glue\CheckoutRestApi\Processor\Customer\CustomerMapperInterface
     */
    protected $customerMapper;

    /**
     * @var \Spryker\Glue\CheckoutRestApi\Processor\Validator\CheckoutRequestValidatorInterface
     */
    protected $checkoutRequestValidator;

    /**
     * @param \Spryker\Client\CheckoutRestApi\CheckoutRestApiClientInterface $checkoutRestApiClient
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface $restResourceBuilder
     * @param \Spryker\Glue\CheckoutRestApi\Processor\CheckoutData\CheckoutDataMapperInterface $checkoutDataMapper
     * @param \Spryker\Glue\CheckoutRestApi\Processor\Customer\CustomerMapperInterface $customerMapper
     * @param \Spryker\Glue\CheckoutRestApi\Processor\Validator\CheckoutRequestValidatorInterface $checkoutRequestValidator
     */
    public function __construct(
        CheckoutRestApiClientInterface $checkoutRestApiClient,
        RestResourceBuilderInterface $restResourceBuilder,
        CheckoutDataMapperInterface $checkoutDataMapper,
        CustomerMapperInterface $customerMapper,
        CheckoutRequestValidatorInterface $checkoutRequestValidator
    ) {
        $this->checkoutRestApiClient = $checkoutRestApiClient;
        $this->restResourceBuilder = $restResourceBuilder;
        $this->checkoutDataMapper = $checkoutDataMapper;
        $this->customerMapper = $customerMapper;
        $this->checkoutRequestValidator = $checkoutRequestValidator;
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     * @param \Generated\Shared\Transfer\RestCheckoutRequestAttributesTransfer $restCheckoutRequestAttributesTransfer
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function getCheckoutData(RestRequestInterface $restRequest, RestCheckoutRequestAttributesTransfer $restCheckoutRequestAttributesTransfer): RestResponseInterface
    {
        $restErrorCollectionTransfer = $this->checkoutRequestValidator->validateCheckoutRequest($restRequest, $restCheckoutRequestAttributesTransfer);
        if ($restErrorCollectionTransfer->getRestErrors()->count()) {
            return $this->createValidationErrorResponse($restErrorCollectionTransfer);
        }

        $restCustomerTransfer = $this->customerMapper->mapRestCustomerTransferFromRestCheckoutRequest($restRequest, $restCheckoutRequestAttributesTransfer);
        $restCheckoutRequestAttributesTransfer->setCustomer($restCustomerTransfer);

        $restCheckoutDataResponseTransfer = $this->checkoutRestApiClient->getCheckoutData($restCheckoutRequestAttributesTransfer);
        if (!$restCheckoutDataResponseTransfer->getIsSuccess()) {
            return $this->createCheckoutDataErrorResponse($restCheckoutDataResponseTransfer);
        }

        $restCheckoutResponseAttributesTransfer = $this->checkoutDataMapper
            ->mapRestCheckoutDataTransferToRestCheckoutDataResponseAttributesTransfer($restCheckoutDataResponseTransfer->getCheckoutData(), $restCheckoutRequestAttributesTransfer);

        return $this->createRestResponse($restCheckoutResponseAttributesTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer $restCheckoutResponseAttributesTransfer
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    protected function createRestResponse(RestCheckoutDataResponseAttributesTransfer $restCheckoutResponseAttributesTransfer): RestResponseInterface
    {
        $checkoutDataResource = $this->restResourceBuilder->createRestResource(
            CheckoutRestApiConfig::RESOURCE_CHECKOUT_DATA,
            null,
            $restCheckoutResponseAttributesTransfer
        );

        $restResponse = $this->restResourceBuilder
            ->createRestResponse()
            ->addResource($checkoutDataResource)
            ->setStatus(Response::HTTP_OK);

        return $restResponse;
    }

    /**
     * @param \Generated\Shared\Transfer\RestCheckoutDataResponseTransfer $restCheckoutDataResponseTransfer
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    protected function createCheckoutDataErrorResponse(RestCheckoutDataResponseTransfer $restCheckoutDataResponseTransfer): RestResponseInterface
    {
        $restResponse = $this->restResourceBuilder->createRestResponse();
        foreach ($restCheckoutDataResponseTransfer->getErrors() as $restCheckoutErrorTransfer) {
            $restResponse->addError(
                (new RestErrorMessageTransfer())
                    ->fromArray($restCheckoutErrorTransfer->toArray(), true)
            );
        }

        return $restResponse;
    }

    /**
     * @param \Generated\Shared\Transfer\RestErrorCollectionTransfer $restErrorCollectionTransfer
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    protected function createValidationErrorResponse(RestErrorCollectionTransfer $restErrorCollectionTransfer)
    {
        $restResponse = $this->restResourceBuilder->createRestResponse();
        foreach ($restErrorCollectionTransfer->getRestErrors() as $restErrorTransfer) {
            $restResponse->addError($restErrorTransfer);
        }

        return $restResponse;
    }
}
