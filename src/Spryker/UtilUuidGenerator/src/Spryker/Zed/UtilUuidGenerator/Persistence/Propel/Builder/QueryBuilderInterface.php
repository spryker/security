<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\UtilUuidGenerator\Persistence\Propel\Builder;

use Propel\Runtime\ActiveQuery\ModelCriteria;

interface QueryBuilderInterface
{
    /**
     * @param string $tableAlias
     *
     * @return \Propel\Runtime\ActiveQuery\ModelCriteria
     */
    public function buildQuery(string $tableAlias): ModelCriteria;
}
