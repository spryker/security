<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\ProductListStorage;

use Spryker\Shared\Kernel\AbstractBundleConfig;

class ProductListStorageConfig extends AbstractBundleConfig
{
    /**
     * Specification:
     * - Queue name as used for processing price messages
     *
     * @api
     */
    public const PRODUCT_LIST_ABSTRACT_SYNC_STORAGE_QUEUE = 'sync.storage.product';

    /**
     * Specification:
     * - Queue name as used for processing price messages
     *
     * @api
     */
    public const PRODUCT_LIST_CONCRETE_SYNC_STORAGE_QUEUE = 'sync.storage.product';

    /**
     * Specification:
     * - Key generation resource name of product abstract lists.
     *
     * @api
     */
    public const PRODUCT_LIST_ABSTRACT_RESOURCE_NAME = 'product_abstract_product_lists';

    /**
     * Specification:
     * - Key generation resource name of product concrete lists.
     *
     * @api
     */
    public const PRODUCT_LIST_CONCRETE_RESOURCE_NAME = 'product_concrete_product_lists';

    /**
     * @uses \Spryker\Shared\Product\ProductConfig::VARIANT_LEAF_NODE_ID
     */
    public const VARIANT_LEAF_NODE_ID = 'id_product_concrete';

    /**
     * @uses \Spryker\Shared\Product\ProductConfig::ATTRIBUTE_MAP_PATH_DELIMITER
     */
    public const ATTRIBUTE_MAP_PATH_DELIMITER = ':';
}
