<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\DocumentationGeneratorRestApi\Business\Stub\Plugin;

use Spryker\Glue\GlueApplicationExtension\Dependency\Plugin\ResourceRouteCollectionInterface;
use Spryker\Glue\GlueApplicationExtension\Dependency\Plugin\ResourceRoutePluginInterface;
use SprykerTest\Zed\DocumentationGeneratorRestApi\Business\Stub\RestTestAttributesTransfer;

class TestResourceRouteWithGetResourceByIdPlugin implements ResourceRoutePluginInterface
{
    /**
     * @param \Spryker\Glue\GlueApplicationExtension\Dependency\Plugin\ResourceRouteCollectionInterface $resourceRouteCollection
     *
     * @return \Spryker\Glue\GlueApplicationExtension\Dependency\Plugin\ResourceRouteCollectionInterface
     */
    public function configure(ResourceRouteCollectionInterface $resourceRouteCollection): ResourceRouteCollectionInterface
    {
        $resourceRouteCollection->addGet('get', false);

        return $resourceRouteCollection;
    }

    /**
     * @return string
     */
    public function getResourceType(): string
    {
        return 'test-resource-with-get-resource-by-id';
    }

    /**
     * @return string
     */
    public function getController(): string
    {
        return 'test-resource-with-get-resource-by-id';
    }

    /**
     * @return string
     */
    public function getResourceAttributesClassName(): string
    {
        return RestTestAttributesTransfer::class;
    }

    /**
     * @return string
     */
    public function getModuleName(): string
    {
        return 'DocumentationGeneratorRestApi';
    }
}
