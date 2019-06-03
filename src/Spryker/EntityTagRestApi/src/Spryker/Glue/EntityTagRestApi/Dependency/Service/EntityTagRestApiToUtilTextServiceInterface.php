<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\EntityTagRestApi\Dependency\Service;

interface EntityTagRestApiToUtilTextServiceInterface
{
    /**
     * @param string $algorithm
     * @param mixed $value
     *
     * @return string
     */
    public function hashValue($algorithm, $value);
}
