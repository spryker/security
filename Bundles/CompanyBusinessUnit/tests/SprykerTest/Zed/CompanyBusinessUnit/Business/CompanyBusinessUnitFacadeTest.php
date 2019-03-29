<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\CompanyBusinessUnit\Business;

use Codeception\TestCase\Test;
use Generated\Shared\DataBuilder\CompanyUserBuilder;
use Generated\Shared\Transfer\CompanyUserResponseTransfer;
use Generated\Shared\Transfer\CompanyUserTransfer;
use Spryker\Zed\CompanyBusinessUnit\Business\CompanyBusinessUnitFacadeInterface;
use TypeError;

/**
 * Auto-generated group annotations
 *
 * @group SprykerTest
 * @group Zed
 * @group CompanyBusinessUnit
 * @group Business
 * @group Facade
 * @group CompanyBusinessUnitFacadeTest
 * Add your own group annotations below this line
 */
class CompanyBusinessUnitFacadeTest extends Test
{
    /**
     * @var \SprykerTest\Zed\CompanyBusinessUnit\CompanyBusinessUnitTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function testCreateShouldPersistCompanyBusinessUnit()
    {
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();

        $createdTransfer = $this->getFacade()
            ->create($businessUnitTransfer)
            ->getCompanyBusinessUnitTransfer();

        $this->assertNotNull($createdTransfer->getIdCompanyBusinessUnit());
    }

    /**
     * @return void
     */
    public function testGetCompanyBusinessUnitByIdShouldReturnTransferObject()
    {
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();

        $createdBusinessUnitTransfer = $this->getFacade()
            ->create($businessUnitTransfer)
            ->getCompanyBusinessUnitTransfer();

        $foundBusinessUnitTransfer = $this->getFacade()->getCompanyBusinessUnitById($createdBusinessUnitTransfer);
        $this->assertSame($createdBusinessUnitTransfer->getName(), $foundBusinessUnitTransfer->getName());
    }

    /**
     * @return void
     */
    public function testFindCompanyBusinessUnitByIdShouldReturnTransferObject(): void
    {
        //Arrange
        $companyBusinessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();

        //Act
        $expectedCompanyBusinessUnitTransfer = $this->getFacade()
            ->create($companyBusinessUnitTransfer)
            ->getCompanyBusinessUnitTransfer();
        $actualCompanyBusinessUnitTransfer = $this->getFacade()
            ->findCompanyBusinessUnitById($expectedCompanyBusinessUnitTransfer->getIdCompanyBusinessUnit());

        //Assert
        $this->assertSame($expectedCompanyBusinessUnitTransfer->getName(), $actualCompanyBusinessUnitTransfer->getName());
    }

    /**
     * @return void
     */
    public function testFindCompanyBusinessUnitByIdShouldReturnNull(): void
    {
        //Act
        $companyBusinessUnitTransfer = $this->getFacade()->findCompanyBusinessUnitById(-1);

        //Assert
        $this->assertNull($companyBusinessUnitTransfer);
    }

    /**
     * @return void
     */
    public function testGetCustomerCompanyBusinessUnitTreeShouldReturnNodesCollection()
    {
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();
        $this->getFacade()->create($businessUnitTransfer);

        $customerTransfer = $this->tester->haveCustomer();
        $companyUserTransfer = $this->tester->haveCompanyUser(
            [
                CompanyUserTransfer::CUSTOMER => $customerTransfer,
                CompanyUserTransfer::FK_COMPANY => $businessUnitTransfer->getFkCompany(),
            ]
        );
        $customerTransfer->setCompanyUserTransfer($companyUserTransfer);

        $companyBusinessUnitTreeNodeCollectionTransfer = $this->getFacade()->getCustomerCompanyBusinessUnitTree($customerTransfer);

        $this->assertEquals(1, count($companyBusinessUnitTreeNodeCollectionTransfer->getCompanyBusinessUnitTreeNodes()));
    }

    /**
     * @return void
     */
    public function testUpdateShouldPersistCompanyBusinessUnitChanges()
    {
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();

        $createdBusinessUnitTransfer = $this->getFacade()
            ->create(clone $businessUnitTransfer)
            ->getCompanyBusinessUnitTransfer();

        $createdBusinessUnitTransfer->setName($createdBusinessUnitTransfer->getName() . 'TEST');
        $updatedBusinessUnitTransfer = $this->getFacade()
            ->update($createdBusinessUnitTransfer)
            ->getCompanyBusinessUnitTransfer();

        $this->assertNotSame($businessUnitTransfer->getName(), $updatedBusinessUnitTransfer->getName());
    }

    /**
     * @return void
     */
    public function testDeleteShouldRemoveCompanyBusinessUnitFromStorage()
    {
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();

        $createdBusinessUnitTransfer = $this->getFacade()
            ->create(clone $businessUnitTransfer)
            ->getCompanyBusinessUnitTransfer();

        $this->getFacade()->delete($createdBusinessUnitTransfer);
        $this->expectException(TypeError::class);
        $this->getFacade()->getCompanyBusinessUnitById($createdBusinessUnitTransfer);
    }

    /**
     * @return void
     */
    public function testAssignDefaultBusinessUnitToCompanyUserShouldAssignFkCompanyBusinessUnitIfIsNotSet()
    {
        $companyBusinessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();
        $idCompany = $companyBusinessUnitTransfer->getFkCompany();

        $companyUser = (new CompanyUserTransfer())->setFkCompany($idCompany);
        $companyUserResponseTransfer = (new CompanyUserResponseTransfer())->setCompanyUser($companyUser);

        $companyUserResponseTransfer = $this->getFacade()->assignDefaultBusinessUnitToCompanyUser($companyUserResponseTransfer);

        $this->assertEquals(
            $companyBusinessUnitTransfer->getIdCompanyBusinessUnit(),
            $companyUserResponseTransfer->getCompanyUser()->getFkCompanyBusinessUnit()
        );
    }

    /**
     * @return void
     */
    public function testBusinessUnitParentIsSaved()
    {
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();

        $seedData = [
            'fkCompany' => $businessUnitTransfer->getFkCompany(),
            'idCompanyBusinessUnit' => null,
            'fkParentCompanyBusinessUnit' => $businessUnitTransfer->getIdCompanyBusinessUnit(),
        ];
        $childBusinessUnitTransfer = $this->tester->haveCompanyBusinessUnit($seedData);

        // Act
        $loadedChildBusinessUnitTransfer = $this->getFacade()
            ->getCompanyBusinessUnitById($childBusinessUnitTransfer);

        // Assert
        $this->assertSame(
            $loadedChildBusinessUnitTransfer->getParentCompanyBusinessUnit()->getIdCompanyBusinessUnit(),
            $businessUnitTransfer->getIdCompanyBusinessUnit()
        );
    }

    /**
     * @return void
     */
    public function testBusinessUnitCanBeUpdated()
    {
        // Arrange
        $companyTransfer = $this->tester->haveCompany();
        $seedData = [
            'fkCompany' => $companyTransfer->getIdCompany(),
            'idCompanyBusinessUnit' => null,
        ];
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnit($seedData);
        $businessUnitTransfer->setCompany($companyTransfer);

        // Act
        $this->getFacade()->update($businessUnitTransfer);
        $loadedChildBusinessUnitTransfer = $this->getFacade()
            ->getCompanyBusinessUnitById($businessUnitTransfer);

        // Assert
        $this->assertSame(
            $loadedChildBusinessUnitTransfer->getIdCompanyBusinessUnit(),
            $businessUnitTransfer->getIdCompanyBusinessUnit()
        );
        $this->assertSame(
            $loadedChildBusinessUnitTransfer->getFkCompany(),
            $businessUnitTransfer->getFkCompany()
        );
    }

    /**
     * @return void
     */
    public function testBusinessUnitRelationCanBeAddedToExistingUnit()
    {
        // Arrange
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();

        $seedData = [
            'fkCompany' => $businessUnitTransfer->getFkCompany(),
            'idCompanyBusinessUnit' => null,
        ];
        $childBusinessUnitTransfer = $this->tester->haveCompanyBusinessUnit($seedData);
        $childBusinessUnitTransfer = $this->getFacade()
            ->getCompanyBusinessUnitById($childBusinessUnitTransfer);

        // Act
        $childBusinessUnitTransfer->setFkParentCompanyBusinessUnit($businessUnitTransfer->getIdCompanyBusinessUnit());
        $this->getFacade()->update($childBusinessUnitTransfer);
        $loadedChildBusinessUnitTransfer = $this->getFacade()
            ->getCompanyBusinessUnitById($childBusinessUnitTransfer);

        // Assert
        $this->assertSame(
            $loadedChildBusinessUnitTransfer->getParentCompanyBusinessUnit()->getIdCompanyBusinessUnit(),
            $businessUnitTransfer->getIdCompanyBusinessUnit()
        );
    }

    /**
     * @group Propel
     *
     * @return void
     */
    public function testParentBusinessUnitRelationCanBeSaved()
    {
        // Arrange
        $parentBusinessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();
        $parentBusinessUnitTransfer = $this->getFacade()
            ->getCompanyBusinessUnitById($parentBusinessUnitTransfer);

        $seedData = [
            'fkCompany' => $parentBusinessUnitTransfer->getFkCompany(),
            'idCompanyBusinessUnit' => null,
            'fkParentCompanyBusinessUnit' => $parentBusinessUnitTransfer->getIdCompanyBusinessUnit(),
        ];
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnit($seedData);
        $businessUnitTransfer = $this->getFacade()
            ->getCompanyBusinessUnitById($businessUnitTransfer);

        // Act
        $this->getFacade()->update($businessUnitTransfer);
        $loadedChildBusinessUnitTransfer = $this->getFacade()
            ->getCompanyBusinessUnitById($businessUnitTransfer);

        // Assert
        $this->assertSame(
            $loadedChildBusinessUnitTransfer->getParentCompanyBusinessUnit()->getIdCompanyBusinessUnit(),
            $loadedChildBusinessUnitTransfer->getFkParentCompanyBusinessUnit()
        );
        $this->assertSame(
            $loadedChildBusinessUnitTransfer->getFkParentCompanyBusinessUnit(),
            $parentBusinessUnitTransfer->getIdCompanyBusinessUnit()
        );
    }

    /**
     * @return void
     */
    public function testDeleteShouldClearParentForChildrenBusinessUnit()
    {
        // Arrange
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();
        $seedData = [
            'fkCompany' => $businessUnitTransfer->getFkCompany(),
            'idCompanyBusinessUnit' => null,
            'fkParentCompanyBusinessUnit' => $businessUnitTransfer->getIdCompanyBusinessUnit(),
        ];
        $childBusinessUnitTransfer = $this->tester->haveCompanyBusinessUnit($seedData);

        // Act
        $this->getFacade()->delete($businessUnitTransfer);
        $loadedChildBusinessUnitTransfer = $this->getFacade()
            ->getCompanyBusinessUnitById($childBusinessUnitTransfer);

        // Assert
        $this->assertNull(
            $loadedChildBusinessUnitTransfer->getFkParentCompanyBusinessUnit()
        );
    }

    /**
     * @return void
     */
    public function testIsUniqueCompanyUserByCustomerShouldReturnFalseIfCompanyUserRelationAlreadyExists()
    {
        // Arrange
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();
        $customerTransfer = $this->tester->haveCustomer();
        $companyUserTransfer = $this->tester->haveCompanyUser(
            [
                CompanyUserTransfer::CUSTOMER => $customerTransfer,
                CompanyUserTransfer::COMPANY_BUSINESS_UNIT => $businessUnitTransfer,
                CompanyUserTransfer::FK_COMPANY => $businessUnitTransfer->getFkCompany(),
                CompanyUserTransfer::FK_COMPANY_BUSINESS_UNIT => $businessUnitTransfer->getIdCompanyBusinessUnit(),
                CompanyUserTransfer::FK_CUSTOMER => $customerTransfer->getIdCustomer(),
            ]
        );

        $companyUserTransfer->setIdCompanyUser(null);

        // Act
        $existsCompanyUser = $this->getFacade()
            ->isUniqueCompanyUserByCustomer($companyUserTransfer);

        // Assert
        $this->assertFalse($existsCompanyUser->getIsSuccessful());
    }

    /**
     * @return void
     */
    public function testIsUniqueCompanyUserByCustomerShouldReturnTrueToUpdateItself()
    {
        // Arrange
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();
        $customerTransfer = $this->tester->haveCustomer();
        $companyUserTransfer = $this->tester->haveCompanyUser(
            [
                CompanyUserTransfer::CUSTOMER => $customerTransfer,
                CompanyUserTransfer::COMPANY_BUSINESS_UNIT => $businessUnitTransfer,
                CompanyUserTransfer::FK_COMPANY => $businessUnitTransfer->getFkCompany(),
                CompanyUserTransfer::FK_COMPANY_BUSINESS_UNIT => $businessUnitTransfer->getIdCompanyBusinessUnit(),
                CompanyUserTransfer::FK_CUSTOMER => $customerTransfer->getIdCustomer(),
            ]
        );

        // Act
        $existsCompanyUser = $this->getFacade()
            ->isUniqueCompanyUserByCustomer($companyUserTransfer);

        // Assert
        $this->assertTrue($existsCompanyUser->getIsSuccessful());
    }

    /**
     * @return void
     */
    public function testIsUniqueCompanyUserByCustomerShouldReturnTrueIfFkCompanyBusinessUnitIsEmpty()
    {
        // Arrange
        $customerTransfer = $this->tester->haveCustomer();

        $notExistentCompanyUserTransfer = (new CompanyUserBuilder())
            ->build()
            ->setFkCustomer($customerTransfer->getIdCustomer());

        // Act
        $existsCompanyUser = $this->getFacade()
            ->isUniqueCompanyUserByCustomer($notExistentCompanyUserTransfer);

        // Assert
        $this->assertTrue($existsCompanyUser->getIsSuccessful());
    }

    /**
     * @return void
     */
    public function testIsUniqueCompanyUserByCustomerShouldReturnTrueIfFkCustomerIsEmpty()
    {
        // Arrange
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();

        $notExistentCompanyUserTransfer = (new CompanyUserBuilder())
            ->build()
            ->setFkCompanyBusinessUnit($businessUnitTransfer->getFkCompany());

        // Act
        $existsCompanyUser = $this->getFacade()
            ->isUniqueCompanyUserByCustomer($notExistentCompanyUserTransfer);

        // Assert
        $this->assertTrue($existsCompanyUser->getIsSuccessful());
    }

    /**
     * @return void
     */
    public function testIsUniqueCompanyUserByCustomerShouldReturnTrueIfCompanyUserRelationDoesNotExists()
    {
        // Arrange
        $businessUnitTransfer = $this->tester->haveCompanyBusinessUnitWithCompany();
        $customerTransfer = $this->tester->haveCustomer();

        $notExistentCompanyUserTransfer = (new CompanyUserBuilder())
            ->build()
            ->setFkCustomer($customerTransfer->getIdCustomer())
            ->setFkCompanyBusinessUnit($businessUnitTransfer->getFkCompany());

        // Act
        $existsCompanyUser = $this->getFacade()
            ->isUniqueCompanyUserByCustomer($notExistentCompanyUserTransfer);

        // Assert
        $this->assertTrue($existsCompanyUser->getIsSuccessful());
    }

    /**
     * @return void
     */
    public function testGetCompanyBusinessUnitCollectionShouldReturnTransferObject()
    {
    }

    /**
     * @return \Spryker\Zed\CompanyBusinessUnit\Business\CompanyBusinessUnitFacadeInterface
     */
    protected function getFacade(): CompanyBusinessUnitFacadeInterface
    {
        return $this->tester->getFacade();
    }
}
