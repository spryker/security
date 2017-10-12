<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductSearch\Business\Map;

use Generated\Shared\Transfer\PageMapTransfer;
use Spryker\Zed\ProductSearch\Business\Map\Collector\ProductSearchAttributeMapCollectorInterface;
use Spryker\Zed\Search\Business\Model\Elasticsearch\DataMapper\PageMapBuilderInterface;

class ProductSearchAttributeMapper implements ProductSearchAttributeMapperInterface
{
    /**
     * @var \Spryker\Zed\ProductSearch\Business\Map\Collector\ProductSearchAttributeMapCollectorInterface[]
     */
    protected $attributeMapCollectors;

    /**
     * @param \Spryker\Zed\ProductSearch\Business\Map\Collector\ProductSearchAttributeMapCollectorInterface[] $attributeMapCollectors
     */
    public function __construct(array $attributeMapCollectors)
    {
        $this->attributeMapCollectors = $attributeMapCollectors;
    }

    /**
     * @param \Spryker\Zed\Search\Business\Model\Elasticsearch\DataMapper\PageMapBuilderInterface $pageMapBuilder
     * @param \Generated\Shared\Transfer\PageMapTransfer $pageMapTransfer
     * @param array $attributes
     *
     * @return \Generated\Shared\Transfer\PageMapTransfer
     */
    public function mapDynamicProductAttributes(PageMapBuilderInterface $pageMapBuilder, PageMapTransfer $pageMapTransfer, array $attributes)
    {
        foreach ($this->attributeMapCollectors as $attributeMapCollector) {
            $pageMapTransfer = $this->runAttributeMapCollector($attributeMapCollector, $pageMapBuilder, $pageMapTransfer, $attributes);
        }

        return $pageMapTransfer;
    }

    /**
     * @param \Spryker\Zed\ProductSearch\Business\Map\Collector\ProductSearchAttributeMapCollectorInterface $attributeMapCollector
     * @param \Spryker\Zed\Search\Business\Model\Elasticsearch\DataMapper\PageMapBuilderInterface $pageMapBuilder
     * @param \Generated\Shared\Transfer\PageMapTransfer $pageMapTransfer
     * @param array $attributes
     *
     * @return \Generated\Shared\Transfer\PageMapTransfer
     */
    protected function runAttributeMapCollector(
        ProductSearchAttributeMapCollectorInterface $attributeMapCollector,
        PageMapBuilderInterface $pageMapBuilder,
        PageMapTransfer $pageMapTransfer,
        array $attributes
    ) {
        $attributeMap = $attributeMapCollector->getProductSearchAttributeMap();

        foreach ($attributeMap as $attributeMapTransfer) {
            $attributeName = $attributeMapTransfer->getAttributeName();

            if (!isset($attributes[$attributeName])) {
                continue;
            }

            foreach ($attributeMapTransfer->getTargetFields() as $targetFieldName) {
                $pageMapBuilder->add($pageMapTransfer, $targetFieldName, $attributeName, $attributes[$attributeName]);
            }
        }

        return $pageMapTransfer;
    }
}
