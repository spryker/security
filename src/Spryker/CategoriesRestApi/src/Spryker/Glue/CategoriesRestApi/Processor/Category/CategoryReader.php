<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CategoriesRestApi\Processor\Category;

use Generated\Shared\Transfer\RestErrorMessageTransfer;
use Spryker\Glue\CategoriesRestApi\CategoriesRestApiConfig;
use Spryker\Glue\CategoriesRestApi\Dependency\Client\CategoriesRestApiToCategoryStorageClientInterface;
use Spryker\Glue\CategoriesRestApi\Processor\Mapper\CategoryMapperInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface;
use Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class CategoryReader implements CategoryReaderInterface
{
    /**
     * @var \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface
     */
    protected $restResourceBuilder;

    /**
     * @var \Spryker\Glue\CategoriesRestApi\Dependency\Client\CategoriesRestApiToCategoryStorageClientInterface
     */
    protected $categoryStorageClient;

    /**
     * @var \Spryker\Glue\CategoriesRestApi\Processor\Mapper\CategoryMapperInterface
     */
    protected $categoryMapper;

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceBuilderInterface $restResourceBuilder
     * @param \Spryker\Glue\CategoriesRestApi\Dependency\Client\CategoriesRestApiToCategoryStorageClientInterface $categoryStorageClient
     * @param \Spryker\Glue\CategoriesRestApi\Processor\Mapper\CategoryMapperInterface $categoriesResourceMapper
     */
    public function __construct(
        RestResourceBuilderInterface $restResourceBuilder,
        CategoriesRestApiToCategoryStorageClientInterface $categoryStorageClient,
        CategoryMapperInterface $categoriesResourceMapper
    ) {
        $this->restResourceBuilder = $restResourceBuilder;
        $this->categoryStorageClient = $categoryStorageClient;
        $this->categoryMapper = $categoriesResourceMapper;
    }

    /**
     * @param string $locale
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function getCategoryTree(string $locale): RestResponseInterface
    {
        $categoryTree = $this->categoryStorageClient->getCategories($locale);
        $restCategoriesTreeTransfer = $this->categoryMapper
            ->mapCategoryTreeToRestCategoryTreesTransfer((array)$categoryTree);

        $restResponse = $this->restResourceBuilder->createRestResponse();
        $restResource = $this
            ->restResourceBuilder
            ->createRestResource(
                CategoriesRestApiConfig::RESOURCE_CATEGORY_TREES,
                null,
                $restCategoriesTreeTransfer
            );

        return $restResponse->addResource($restResource);
    }

    /**
     * @param string $nodeId
     * @param string $locale
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    public function getCategoryNode(string $nodeId, string $locale): RestResponseInterface
    {
        $restResponse = $this->restResourceBuilder->createRestResponse();
        if (!$this->validateNodeId($nodeId)) {
            return $this->createInvalidNodeIdResponse($restResponse);
        }
        $categoryNodeStorageTransfer = $this->categoryStorageClient->getCategoryNodeById((int)$nodeId, $locale);

        if (!$categoryNodeStorageTransfer->getNodeId()) {
            return $this->createErrorResponse($restResponse);
        }

        $restCategoryNodesAttributesTransfer = $this->categoryMapper
            ->mapCategoryNodeToRestCategoryNodesTransfer($categoryNodeStorageTransfer);

        $restResource = $this
            ->restResourceBuilder
            ->createRestResource(
                CategoriesRestApiConfig::RESOURCE_CATEGORY_NODES,
                (string)$restCategoryNodesAttributesTransfer->getNodeId(),
                $restCategoryNodesAttributesTransfer
            );

        return $restResponse->addResource($restResource);
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface $restResponse
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    protected function createErrorResponse(RestResponseInterface $restResponse): RestResponseInterface
    {
        $restErrorTransfer = (new RestErrorMessageTransfer())
            ->setCode(CategoriesRestApiConfig::RESPONSE_CODE_CATEGORY_NOT_FOUND)
            ->setStatus(Response::HTTP_NOT_FOUND)
            ->setDetail(CategoriesRestApiConfig::RESPONSE_DETAILS_CATEGORY_NOT_FOUND);

        return $restResponse->addError($restErrorTransfer);
    }

    /**
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface $restResponse
     *
     * @return \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResponseInterface
     */
    protected function createInvalidNodeIdResponse(RestResponseInterface $restResponse): RestResponseInterface
    {
        $restErrorTransfer = (new RestErrorMessageTransfer())
            ->setCode(CategoriesRestApiConfig::RESPONSE_CODE_INVALID_CATEGORY_ID)
            ->setStatus(Response::HTTP_BAD_REQUEST)
            ->setDetail(CategoriesRestApiConfig::RESPONSE_DETAILS_INVALID_CATEGORY_ID);

        return $restResponse->addError($restErrorTransfer);
    }

    /**
     * @param string $nodeId
     *
     * @return bool
     */
    protected function validateNodeId(string $nodeId): bool
    {
        return strcmp($nodeId, (int)$nodeId) === 0;
    }
}
