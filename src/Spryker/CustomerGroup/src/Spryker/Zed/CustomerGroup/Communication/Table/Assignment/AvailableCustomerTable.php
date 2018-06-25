<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CustomerGroup\Communication\Table\Assignment;

class AvailableCustomerTable extends AbstractAssignmentTable
{
    /**
     * @var string
     */
    protected $defaultUrl = 'available-customer-table';

    /**
     * @return \Orm\Zed\Customer\Persistence\SpyCustomerQuery
     */
    protected function getQuery()
    {
        return $this->tableQueryBuilder->buildNotAssignedQuery($this->idCustomerGroup);
    }

    /**
     * @return string
     */
    protected function getCheckboxCheckedAttribute()
    {
        return '';
    }
}
