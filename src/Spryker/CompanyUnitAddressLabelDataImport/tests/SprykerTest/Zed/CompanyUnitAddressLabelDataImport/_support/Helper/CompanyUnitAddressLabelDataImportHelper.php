<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace SprykerTest\Zed\CompanyUnitAddressLabelDataImport\Helper;

use Codeception\Module;
use Orm\Zed\CompanyUnitAddressLabel\Persistence\SpyCompanyUnitAddressLabelQuery;

class CompanyUnitAddressLabelDataImportHelper extends Module
{
    /**
     * @return void
     */
    public function ensureDatabaseTableIsEmpty(): void
    {
        $this->getCompanyUnitAddressLabelQuery()
            ->deleteAll();
    }

    /**
     * @return void
     */
    public function assertDatabaseTableIsEmpty(): void
    {
        $companyUnitAddressLabelQuery = $this->getCompanyUnitAddressLabelQuery();
        $this->assertCount(0, $companyUnitAddressLabelQuery, 'Found at least one entry in the database table but database table was expected to be empty.');
    }

    /**
     * @return void
     */
    public function assertDatabaseTableContainsData(): void
    {
        $companyUnitAddressLabelQuery = $this->getCompanyUnitAddressLabelQuery();
        $this->assertTrue(($companyUnitAddressLabelQuery->count() > 0), 'Expected at least one entry in the database table but database table is empty.');
    }

    /**
     * @return \Orm\Zed\CompanyUnitAddressLabel\Persistence\SpyCompanyUnitAddressLabelQuery
     */
    protected function getCompanyUnitAddressLabelQuery(): SpyCompanyUnitAddressLabelQuery
    {
        return SpyCompanyUnitAddressLabelQuery::create();
    }
}
