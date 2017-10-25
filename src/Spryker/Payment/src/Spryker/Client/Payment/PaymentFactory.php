<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Payment;

use Spryker\Client\Kernel\AbstractFactory;
use Spryker\Client\Payment\Zed\PaymentStub;

class PaymentFactory extends AbstractFactory
{
    /**
     * @return \Spryker\Client\Payment\Zed\PaymentStubInterface
     */
    public function createZedStub()
    {
        $zedStub = $this->getProvidedDependency(PaymentDependencyProvider::SERVICE_ZED);
        $cartStub = new PaymentStub($zedStub);

        return $cartStub;
    }
}
