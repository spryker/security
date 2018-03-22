<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Shared\ZedRequest\Client;

interface ObjectInterface
{
    /**
     * @param array $values
     *
     * @return void
     */
    public function fromArray(array $values);

    /**
     * @return array
     */
    public function toArray();
}
