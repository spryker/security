<?php

/**
 * MIT License
 * For full license information, please view the LICENSE file that was distributed with this source code.
 */

namespace SprykerTest\Zed\CompanyUnitAddressDataImport\Helper;

use Codeception\Module;
use Orm\Zed\CompanyUnitAddress\Persistence\SpyCompanyUnitAddressQuery;

class CompanyUnitAddressDataImportHelper extends Module
{
    /**
     * @return void
     */
    public function ensureDatabaseTableIsEmpty(): void
    {
        $this->getCompanyUnitAddressQuery()
            ->deleteAll();
    }

    /**
     * @return void
     */
    public function assertDatabaseTableIsEmpty(): void
    {
        $companyUnitAddressQuery = $this->getCompanyUnitAddressQuery();
        $this->assertCount(0, $companyUnitAddressQuery, 'Found at least one entry in the database table but database table was expected to be empty.');
    }

    /**
     * @return void
     */
    public function assertDatabaseTableContainsData(): void
    {
        $companyUnitAddressQuery = $this->getCompanyUnitAddressQuery();
        $this->assertTrue(($companyUnitAddressQuery->count() > 0), 'Expected at least one entry in the database table but database table is empty.');
    }

    /**
     * @return \Orm\Zed\CompanyUnitAddress\Persistence\SpyCompanyUnitAddressQuery
     */
    protected function getCompanyUnitAddressQuery(): SpyCompanyUnitAddressQuery
    {
        return SpyCompanyUnitAddressQuery::create();
    }
}
