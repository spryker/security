<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PaymentsRestApi\Business;

use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;
use Spryker\Zed\PaymentsRestApi\Business\Quote\QuoteMapper;
use Spryker\Zed\PaymentsRestApi\Business\Quote\QuoteMapperInterface;

/**
 * @method \Spryker\Zed\PaymentsRestApi\PaymentsRestApiConfig getConfig()
 */
class PaymentsRestApiBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\PaymentsRestApi\Business\Quote\QuoteMapperInterface
     */
    public function createQuoteMapper(): QuoteMapperInterface
    {
        return new QuoteMapper();
    }
}
