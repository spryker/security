<?php

/**
 * Copyright © 2017-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\ProductTaxSetsRestApi\Plugin\GlueApplication;

use Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface;
use Spryker\Glue\GlueApplicationExtension\Dependency\Plugin\ResourceRelationshipPluginInterface;
use Spryker\Glue\Kernel\AbstractPlugin;
use Spryker\Glue\ProductTaxSetsRestApi\ProductTaxSetsRestApiConfig;

/**
 * @method \Spryker\Glue\ProductTaxSetsRestApi\ProductTaxSetsRestApiFactory getFactory()
 */
class ProductTaxSetRelationshipByProductAbstractSkuPlugin extends AbstractPlugin implements ResourceRelationshipPluginInterface
{
    /**
     * {@inheritdoc}
     *  - Adds product-tax-sets resource as a relationship by the resource id.
     *  - Identifier of passed resources should contain abstract product sku.
     *
     * @api
     *
     * @param \Spryker\Glue\GlueApplication\Rest\JsonApi\RestResourceInterface[] $resources
     * @param \Spryker\Glue\GlueApplication\Rest\Request\Data\RestRequestInterface $restRequest
     *
     * @return void
     */
    public function addResourceRelationships(array $resources, RestRequestInterface $restRequest): void
    {
        $this->getFactory()
            ->createProductTaxSetsRelationshipExpander()
            ->addResourceRelationshipsByResourceId($resources, $restRequest);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @return string
     */
    public function getRelationshipResourceType(): string
    {
        return ProductTaxSetsRestApiConfig::RESOURCE_TAX_SETS;
    }
}
