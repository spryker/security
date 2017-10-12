<?php

/**
 * Copyright © 2017-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */
namespace SprykerTest\Zed\AvailabilityGui\PageObject;

class AvailabilityPage
{
    const AVAILABILITY_ID = 107;
    const AVAILABILITY_SKU = '828188-1';
    const AVAILABILITY_ABSTRACT_PRODUCT_ID = 107;

    const AVAILABILITY_LIST_URL = '/availability-gui';
    const AVAILABILITY_VIEW_URL = '/availability-gui/index/view?id-product=%d';
    const AVAILABILITY_EDIT_STOCK_URL = 'availability-gui/index/edit?id-product=%d&sku=%s&id-abstract=%d';

    const SUCCESS_MESSAGE = 'Stock successfully updated';

    const PAGE_AVAILABILITY_VIEW_HEADER = 'Product availability';
    const PAGE_AVAILABILITY_LIST_HEADER = 'Availability list';
    const PAGE_AVAILABILITY_EDIT_HEADER = 'Edit Stock';
}
