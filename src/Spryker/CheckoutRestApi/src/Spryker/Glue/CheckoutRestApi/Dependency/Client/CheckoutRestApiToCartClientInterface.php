<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CheckoutRestApi\Dependency\Client;

interface CheckoutRestApiToCartClientInterface
{
    /**
     * @return void
     */
    public function clearQuote();
}
