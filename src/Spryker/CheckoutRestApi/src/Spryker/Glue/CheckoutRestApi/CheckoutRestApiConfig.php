<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CheckoutRestApi;

use Spryker\Glue\Kernel\AbstractBundleConfig;

class CheckoutRestApiConfig extends AbstractBundleConfig
{
    public const RESOURCE_CHECKOUT_DATA = 'checkout-data';
    public const RESOURCE_CHECKOUT = 'checkout';

    public const CONTROLLER_CHECKOUT_DATA = 'checkout-data-resource';
    public const CONTROLLER_CHECKOUT = 'checkout-resource';

    public const ACTION_CHECKOUT_DATA_POST = 'post';
    public const ACTION_CHECKOUT_POST = 'post';

    public const RESPONSE_CODE_CHECKOUT_DATA_INVALID = '1101';
    public const RESPONSE_CODE_ORDER_NOT_PLACED = '1102';
    public const RESPONSE_CODE_CART_NOT_FOUND = '1103';
    public const RESPONSE_CODE_CART_IS_EMPTY = '1104';
    public const RESPONSE_CODE_AUTH_MISSING = '1105';

    public const RESPONSE_DETAILS_CHECKOUT_DATA_INVALID = 'Checkout data is invalid.';
    public const RESPONSE_DETAILS_ORDER_NOT_PLACED = 'Order could not be placed.';
    public const RESPONSE_DETAILS_CART_NOT_FOUND = 'Cart not found.';
    public const RESPONSE_DETAILS_CART_IS_EMPTY = 'Cart is empty.';
    public const RESPONSE_DETAILS_AUTH_MISSING = 'Authorization is missing.';

    protected const PAYMENT_REQUIRED_FIELDS = [];
    protected const PAYMENT_METHOD_REQUIRED_FIELDS = [];

    /**
     * @param string $methodName
     *
     * @return array
     */
    public function getRequiredRequestDataForMethod(string $methodName): array
    {
        if (!isset(static::PAYMENT_METHOD_REQUIRED_FIELDS[$methodName])) {
            return static::PAYMENT_REQUIRED_FIELDS;
        }

        return array_merge(static::PAYMENT_REQUIRED_FIELDS, static::PAYMENT_METHOD_REQUIRED_FIELDS[$methodName]);
    }
}
