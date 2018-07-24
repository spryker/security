<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\ProductPageSearch;

/**
 * Declares global environment configuration keys. Do not use it for other class constants.
 */
class ProductPageSearchConstants
{
    /**
     * Specification:
     * - Queue name as used for processing Product messages
     *
     * @api
     */
    const PRODUCT_SYNC_SEARCH_QUEUE = 'sync.search.product';

    /**
     * Specification:
     * - Queue name as used for processing Product messages
     *
     * @api
     */
    const PRODUCT_SYNC_SEARCH_ERROR_QUEUE = 'sync.search.product.error';

    /**
     * Specification:
     * - Resource name, this will use for key generating
     *
     * @api
     */
    const PRODUCT_ABSTRACT_RESOURCE_NAME = 'product_abstract';

    /**
     * Specification:
     * - PageLoad data plugin key, this will use for plugins to extract data form array data
     *
     * @api
     */
    const PRODUCT_ABSTRACT_PAGE_LOAD_DATA = 'PAGE_LOAD_DATA';
}
