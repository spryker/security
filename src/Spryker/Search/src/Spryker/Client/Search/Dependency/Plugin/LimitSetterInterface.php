<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Search\Dependency\Plugin;

interface LimitSetterInterface
{
    /**
     * @api
     *
     * @param int $limit
     *
     * @return void
     */
    public function setLimit(int $limit): void;
}
