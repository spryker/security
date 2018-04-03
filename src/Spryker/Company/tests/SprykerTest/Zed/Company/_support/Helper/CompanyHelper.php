<?php

namespace SprykerTest\Zed\Company\Helper;

use Codeception\Module;
use Generated\Shared\DataBuilder\CompanyBuilder;
use Generated\Shared\Transfer\CompanyTransfer;
use Orm\Zed\Company\Persistence\SpyCompanyQuery;
use SprykerTest\Shared\Testify\Helper\LocatorHelperTrait;

class CompanyHelper extends Module
{
    use LocatorHelperTrait;

    /**
     * @param int $idCompany
     *
     * @return \Generated\Shared\Transfer\CompanyTransfer|null
     */
    public function findCompanyById(int $idCompany)
    {
        $entity = SpyCompanyQuery::create()
            ->filterByIdCompany($idCompany)
            ->findOne();

        if ($entity !== null) {
            return (new CompanyTransfer())->fromArray($entity->toArray(), true);
        }

        return null;
    }

    /**
     * @param array $seedData
     *
     * @return \Generated\Shared\Transfer\CompanyTransfer
     */
    public function haveCompany(array $seedData = [])
    {
        $companyTransfer = (new CompanyBuilder($seedData))->build();
        $companyTransfer->setIdCompany(null);

        return $this->getLocator()->company()->facade()->create($companyTransfer)->getCompanyTransfer();
    }

    /**
     * @param string $companyTypeName
     *
     * @return \Generated\Shared\Transfer\SpyCompanyTypeEntityTransfer
     */
    public function getCompanyTypeTransfer($companyTypeName = ''): SpyCompanyTypeEntityTransfer
    {
        $companyTypeName = $companyTypeName ?: static::COMPANY_TYPE_CUSTOMER;
        $companyTypeQuery = new SpyCompanyTypeQuery();
        $companyTypeQuery->filterByName($companyTypeName);
        $companyType = $companyTypeQuery->findOneOrCreate();
        $companyType->save();

        return (new SpyCompanyTypeEntityTransfer())->fromArray($companyType->toArray(), true);
    }
}
