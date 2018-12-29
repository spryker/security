<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CompanyUsersRestApi\Processor\CompanyUser;

use Generated\Shared\Transfer\CompanyUserCollectionTransfer;
use Generated\Shared\Transfer\CustomerTransfer;
use Generated\Shared\Transfer\RestCompanyUserAttributesTransfer;
use Spryker\Glue\CompanyUsersRestApi\CompanyUsersRestApiConfig;
use Spryker\Glue\CompanyUsersRestApi\Dependency\Client\CompanyUsersRestApiToCompanyUserClientInterface;
use Spryker\Glue\CompanyUsersRestApi\Processor\Mapper\CompanyUserMapperInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;

class CompanyUserReader implements CompanyUserReaderInterface
{
    /**
     * @var \Spryker\Glue\CompanyUsersRestApi\Dependency\Client\CompanyUsersRestApiToCompanyUserClientInterface
     */
    protected $companyUserClient;

    /**
     * @var \Spryker\Glue\CompanyUsersRestApi\Processor\Mapper\CompanyUserMapperInterface
     */
    protected $companyUserMapper;

    /**
     * @var \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface
     */
    protected $restResourceBuilder;

    /**
     * @param \Spryker\Glue\CompanyUsersRestApi\Dependency\Client\CompanyUsersRestApiToCompanyUserClientInterface $companyUserClient
     * @param \Spryker\Glue\CompanyUsersRestApi\Processor\Mapper\CompanyUserMapperInterface $companyUserMapper
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface $restResourceBuilder
     */
    public function __construct(
        CompanyUsersRestApiToCompanyUserClientInterface $companyUserClient,
        CompanyUserMapperInterface $companyUserMapper,
        RestResourceBuilderInterface $restResourceBuilder
    ) {
        $this->companyUserClient = $companyUserClient;
        $this->companyUserMapper = $companyUserMapper;
        $this->restResourceBuilder = $restResourceBuilder;
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function getCompanyUsersByCustomerReference(RestRequestInterface $restRequest): RestResponseInterface
    {
        $customerTransfer = (new CustomerTransfer())->setCustomerReference($restRequest->getUser()->getNaturalIdentifier());
        $companyUserCollectionTransfer = $this->companyUserClient->getActiveCompanyUsersByCustomerReference($customerTransfer);

        return $this->buildCompanyUserCollectionResponse($companyUserCollectionTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyUserCollectionTransfer $companyUserCollectionTransfer
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    protected function buildCompanyUserCollectionResponse(CompanyUserCollectionTransfer $companyUserCollectionTransfer): RestResponseInterface
    {
        $restResponse = $this->restResourceBuilder->createRestResponse();
        foreach ($companyUserCollectionTransfer->getCompanyUsers() as $companyUserTransfer) {
            $restCompanyUserAttributesTransfer = $this->companyUserMapper
                ->mapCompanyUserTransferToRestCompanyUserAttributesTransfer($companyUserTransfer, new RestCompanyUserAttributesTransfer());

            $restResource = $this->restResourceBuilder->createRestResource(
                CompanyUsersRestApiConfig::RESOURCE_COMPANY_USERS,
                $companyUserTransfer->getUuid(),
                $restCompanyUserAttributesTransfer
            );

            $restResponse->addResource($restResource);
        }

        return $restResponse;
    }
}
