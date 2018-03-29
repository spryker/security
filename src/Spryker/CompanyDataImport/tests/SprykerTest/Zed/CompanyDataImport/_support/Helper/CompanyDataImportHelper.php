<?php

/**
 * Copyright © 2018-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\CompanyDataImport\Helper;

use Codeception\Module;
use Orm\Zed\Company\Persistence\SpyCompanyQuery;

class CompanyDataImportHelper extends Module
{
    /**
     * @return void
     */
    public function ensureDatabaseTableIsEmpty(): void
    {
        $companyQuery = $this->getCompanyQuery();
        foreach ($companyQuery->find() as $companyEntity) {
            $companyEntity->getCompanyBusinessUnits()->delete();
            $companyEntity->getCompanyUnitAddresses()->delete();
            $companyEntity->delete();
        }
    }

    /**
     * @return void
     */
    public function assertDatabaseTableIsEmpty(): void
    {
        $companyQuery = $this->getCompanyQuery();
        $this->assertCount(0, $companyQuery, 'Found at least one entry in the database table but database table was expected to be empty.');
    }

    /**
     * @return void
     */
    public function assertDatabaseTableContainsData(): void
    {
        $companyQuery = $this->getCompanyQuery();
        $this->assertTrue(($companyQuery->count() > 0), 'Expected at least one entry in the database table but database table is empty.');
    }

    /**
     * @return \Orm\Zed\Company\Persistence\SpyCompanyQuery
     */
    protected function getCompanyQuery(): SpyCompanyQuery
    {
        return SpyCompanyQuery::create();
    }
}
