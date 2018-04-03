<?php

namespace SprykerTest\Zed\Company\Business;

use Codeception\TestCase\Test;
use Generated\Shared\DataBuilder\CompanyBuilder;
use Generated\Shared\DataBuilder\StoreRelationBuilder;
use Generated\Shared\Transfer\CompanyTransfer;
use Orm\Zed\Company\Persistence\Map\SpyCompanyTableMap;
use Spryker\Zed\Company\Persistence\CompanyRepository;

/**
 * Auto-generated group annotations
 *
 * @group SprykerTest
 * @group Zed
 * @group Company
 * @group Business
 * @group Facade
 * @group CompanyFacadeTest
 * Add your own group annotations below this line
 */
class CompanyFacadeTest extends Test
{
    /**
     * @var \SprykerTest\Zed\Company\CompanyBusinessTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function testGetCompanyByIdShouldReturnTransfer()
    {
        $companyTransfer = $this->createCompanyTransfer();
        $foundCompanyTransfer = $this->getFacade()->getCompanyById($companyTransfer);
        $this->assertNotNull($foundCompanyTransfer->getIdCompany());
    }

    /**
     * @return void
     */
    public function testCreateShouldPersistCompany()
    {
        $companyTransfer = (new CompanyBuilder([
            'fk_company_type' => $this->tester->getCompanyTypeTransfer()->getIdCompanyType(),
        ]))->build();
        $createdCompanyTransfer = $this->getFacade()->create($companyTransfer)->getCompanyTransfer();

        $this->assertNotNull($createdCompanyTransfer->getIdCompany());
    }

    /**
     * @return void
     */
    public function testUpdateShouldPersistCompanyChanges()
    {
        $companyTransfer = $this->createCompanyTransfer();

        $companyTransfer->setIsActive(true);
        $companyTransfer->setStatus(SpyCompanyTableMap::COL_STATUS_APPROVED);
        $this->getFacade()->update($companyTransfer)->getCompanyTransfer();

        $updatedCompanyTransfer = $this->tester->findCompanyById($companyTransfer->getIdCompany());

        $this->assertEquals($companyTransfer->getIsActive(), $updatedCompanyTransfer->getIsActive());
        $this->assertEquals($companyTransfer->getStatus(), $updatedCompanyTransfer->getStatus());
    }

    /**
     * @return void
     */
    public function testDeleteShouldRemoveCompanyFromStorage()
    {
        $companyTransfer = $this->createCompanyTransfer();
        $this->getFacade()->delete($companyTransfer);
        $this->assertNull($this->tester->findCompanyById($companyTransfer->getIdCompany()));
    }

    /**
     * @return void
     */
    public function testCreateOrUpdateCompanyShouldPersistStoreRelation()
    {
        $storeIds = [];
        foreach ($this->getAllStores() as $store) {
            $storeIds[] = $store->getIdStore();
        }
        $seed = [
            'idStores' => $storeIds,
        ];

        $storeRelation = (new StoreRelationBuilder($seed))->build();
        $companyTransfer = (new CompanyBuilder([
            'is_active' => false,
            'fk_company_type' => $this->tester->getCompanyTypeTransfer()->getIdCompanyType(),
        ]))->build();
        $companyTransfer->setStoreRelation($storeRelation);
        $companyTransfer = $this->getFacade()->create($companyTransfer)->getCompanyTransfer();
        $relatesStores = (new CompanyRepository())->getRelatedStoresByCompanyId($companyTransfer->getIdCompany());
        $this->assertCount(count($storeIds), $relatesStores);

        $seed = [
            'idStores' => [$this->getCurrentStore()->getIdStore()],
        ];

        $storeRelation = (new StoreRelationBuilder($seed))->build();
        $companyTransfer->setStoreRelation($storeRelation);
        $companyTransfer = $this->getFacade()->update($companyTransfer)->getCompanyTransfer();
        $relatesStores = (new CompanyRepository())->getRelatedStoresByCompanyId($companyTransfer->getIdCompany());
        $this->assertCount(1, $relatesStores);
    }

    /**
     * @return void
     */
    public function testGetCompanyTypesReturnsNotEmptyCollection(): void
    {
        $this->createCompanyTransfer();
        $companyTypesCollection = $this->getFacade()->getCompanyTypes();
        $this->assertGreaterThan(0, $companyTypesCollection->getCompanyTypes()->count());
    }

    /**
     * @return void
     */
    public function testGetCompaniesReturnsNotEmptyCollection(): void
    {
        $this->createCompanyTransfer();
        $companyTypesCollection = $this->getFacade()->getCompanies();
        $this->assertGreaterThan(0, $companyTypesCollection->getCompanies()->count());
    }

    /**
     * @return \Generated\Shared\Transfer\StoreTransfer
     */
    protected function getCurrentStore()
    {
        return $this->tester->getLocator()->store()->facade()->getCurrentStore();
    }

    /**
     * @return \Generated\Shared\Transfer\StoreTransfer[]
     */
    protected function getAllStores()
    {
        return $this->tester->getLocator()->store()->facade()->getAllStores();
    }

    /**
     * @return \Spryker\Zed\Company\Business\CompanyFacadeInterface|\Spryker\Zed\Kernel\Business\AbstractFacade
     */
    protected function getFacade()
    {
        return $this->tester->getFacade();
    }

    /**
     * @return \Generated\Shared\Transfer\CompanyTransfer
     */
    protected function createCompanyTransfer(): CompanyTransfer
    {
        return $this->tester->haveCompany([
            'is_active' => false,
        ]);
    }
}
