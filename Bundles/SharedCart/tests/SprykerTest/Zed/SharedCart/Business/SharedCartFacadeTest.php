<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\SharedCart\Business;

use Codeception\TestCase\Test;
use Generated\Shared\Transfer\CompanyUserTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Generated\Shared\Transfer\ResourceShareDataTransfer;
use Generated\Shared\Transfer\ResourceShareRequestTransfer;
use Spryker\Shared\Kernel\Transfer\Exception\RequiredTransferPropertyException;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group SharedCart
 * @group Business
 * @group Facade
 * @group SharedCartFacadeTest
 * Add your own group annotations below this line
 */
class SharedCartFacadeTest extends Test
{
    /**
     * @uses \Spryker\Zed\SharedCart\Business\ResourceShare\ResourceShareQuoteShare::GLOSSARY_KEY_CART_ACCESS_DENIED
     */
    protected const GLOSSARY_KEY_CART_ACCESS_DENIED = 'shared_cart.resource_share.strategy.error.cart_access_denied';

    /**
     * @uses \Spryker\Zed\SharedCart\Business\ResourceShare\ResourceShareQuoteShare::GLOSSARY_KEY_UNABLE_TO_SHARE_CART
     */
    protected const GLOSSARY_KEY_UNABLE_TO_SHARE_CART = 'shared_cart.resource_share.strategy.error.unable_to_share_cart';

    /**
     * @uses \Spryker\Zed\SharedCart\Business\ResourceShare\ResourceShareQuoteShare::GLOSSARY_KEY_QUOTE_IS_NOT_AVAILABLE
     */
    protected const GLOSSARY_KEY_QUOTE_IS_NOT_AVAILABLE = 'persistent_cart_share.error.quote_is_not_available';

    /**
     * @uses \Spryker\Shared\SharedCart\SharedCartConfig::PERMISSION_GROUP_READ_ONLY
     */
    public const PERMISSION_GROUP_READ_ONLY = 'READ_ONLY';

    /**
     * @uses \Spryker\Shared\SharedCart\SharedCartConfig::PERMISSION_GROUP_FULL_ACCESS
     */
    public const PERMISSION_GROUP_FULL_ACCESS = 'FULL_ACCESS';

    protected const VALUE_NOT_EXISTING_ID_COMPANY_USER = 0;
    protected const VALUE_NOT_EXISTING_SHARE_OPTION = 'VALUE_NIT_EXISTING_SHARE_OPTION';
    protected const VALUE_IS_QUOTE_LOCKED_FALSE = false;

    /**
     * @var \SprykerTest\Zed\SharedCart\SharedCartBusinessTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function testShareCartByResourceShareRequestShouldThrowExceptionWhenRequiredCustomerPropertyIsMissingInResourceShareRequestTransfer(): void
    {
        // Arrange
        $resourceShareRequestTransfer = (new ResourceShareRequestTransfer())
            ->setCustomer(null)
            ->setResourceShare($this->tester->createResourceShare());

        // Assert
        $this->expectException(RequiredTransferPropertyException::class);

        // Act
        $this->tester->getFacade()->shareCartByResourceShareRequest($resourceShareRequestTransfer);
    }

    /**
     * @return void
     */
    public function testShareCartByResourceShareRequestShouldThrowExceptionWhenRequiredResourceSharePropertyIsMissingInResourceShareRequestTransfer(): void
    {
        // Arrange
        $resourceShareRequestTransfer = (new ResourceShareRequestTransfer())
            ->setCustomer($this->tester->haveCustomer())
            ->setResourceShare(null);

        // Assert
        $this->expectException(RequiredTransferPropertyException::class);

        // Act
        $this->tester->getFacade()->shareCartByResourceShareRequest($resourceShareRequestTransfer);
    }

    /**
     * @return void
     */
    public function testShareCartByResourceShareRequestShouldReturnErrorMessageWhenCompanyUserIsFromDifferentBusinessUnit(): void
    {
        // Arrange
        $firstCompanyUserTransfer = $this->tester->createCompanyUserTransfer();
        $secondCompanyUserTransfer = $this->tester->createCompanyUserTransfer();

        $resourceShareTransfer = $this->tester->createResourceShare([
            ResourceShareDataTransfer::OWNER_COMPANY_USER_ID => $secondCompanyUserTransfer->getIdCompanyUser(),
            ResourceShareDataTransfer::OWNER_COMPANY_BUSINESS_UNIT_ID => $secondCompanyUserTransfer->getFkCompanyBusinessUnit(),
        ]);

        $resourceShareRequestTransfer = (new ResourceShareRequestTransfer())
            ->setCustomer($firstCompanyUserTransfer->getCustomer())
            ->setResourceShare($resourceShareTransfer);

        // Act
        $resourceShareResponseTransfer = $this->tester->getFacade()->shareCartByResourceShareRequest($resourceShareRequestTransfer);

        // Assert
        $this->assertFalse($resourceShareResponseTransfer->getIsSuccessful());
        $this->tester->hasResourceShareResponseTransferErrorMessage(
            $resourceShareResponseTransfer,
            static::GLOSSARY_KEY_CART_ACCESS_DENIED
        );
    }

    /**
     * @return void
     */
    public function testShareCartByResourceShareRequestShouldReturnErrorMessageWhenCompanyUserIsNotFoundByIdCompanyUser(): void
    {
        // Arrange
        $firstCompanyUserTransfer = $this->tester->createCompanyUserTransfer();
        $secondCompanyUserTransfer = $this->tester->createCompanyUserTransfer([
            ResourceShareDataTransfer::OWNER_COMPANY_USER_ID => static::VALUE_NOT_EXISTING_ID_COMPANY_USER,
        ]);

        $resourceShareTransfer = $this->tester->createResourceShare([
            ResourceShareDataTransfer::OWNER_COMPANY_USER_ID => $secondCompanyUserTransfer->getIdCompanyUser(),
            ResourceShareDataTransfer::OWNER_COMPANY_BUSINESS_UNIT_ID => $secondCompanyUserTransfer->getFkCompanyBusinessUnit(),
        ]);

        $resourceShareRequestTransfer = (new ResourceShareRequestTransfer())
            ->setCustomer($firstCompanyUserTransfer->getCustomer())
            ->setResourceShare($resourceShareTransfer);

        // Act
        $resourceShareResponseTransfer = $this->tester->getFacade()->shareCartByResourceShareRequest($resourceShareRequestTransfer);

        // Assert
        $this->assertFalse($resourceShareResponseTransfer->getIsSuccessful());
        $this->tester->hasResourceShareResponseTransferErrorMessage(
            $resourceShareResponseTransfer,
            static::GLOSSARY_KEY_UNABLE_TO_SHARE_CART
        );
    }

    /**
     * @return void
     */
    public function testShareCartByResourceShareRequestShouldReturnErrorMessageWhenQuotePermissionGroupIsNotFoundByShareOption(): void
    {
        // Arrange
        $firstCompanyUserTransfer = $this->tester->createCompanyUserTransfer();
        $secondCompanyUserTransfer = $this->tester->createCompanyUserTransfer([
            ResourceShareDataTransfer::SHARE_OPTION => static::VALUE_NOT_EXISTING_SHARE_OPTION,
        ]);

        $resourceShareTransfer = $this->tester->createResourceShare([
            ResourceShareDataTransfer::OWNER_COMPANY_USER_ID => $secondCompanyUserTransfer->getIdCompanyUser(),
            ResourceShareDataTransfer::OWNER_COMPANY_BUSINESS_UNIT_ID => $secondCompanyUserTransfer->getFkCompanyBusinessUnit(),
        ]);

        $resourceShareRequestTransfer = (new ResourceShareRequestTransfer())
            ->setCustomer($firstCompanyUserTransfer->getCustomer())
            ->setResourceShare($resourceShareTransfer);

        // Act
        $resourceShareResponseTransfer = $this->tester->getFacade()->shareCartByResourceShareRequest($resourceShareRequestTransfer);

        // Assert
        $this->assertFalse($resourceShareResponseTransfer->getIsSuccessful());
        $this->tester->hasResourceShareResponseTransferErrorMessage(
            $resourceShareResponseTransfer,
            static::GLOSSARY_KEY_UNABLE_TO_SHARE_CART
        );
    }

    /**
     * @return void
     */
    public function testShareCartByResourceShareRequestShouldShareCartWithReadOnlyAccessWhenAllParametersAreCorrect(): void
    {
        // Arrange
        $firstCompanyUserTransfer = $this->tester->createCompanyUserTransfer();
        $secondCompanyUserTransfer = $this->tester->createCompanyUserTransfer([
            CompanyUserTransfer::FK_COMPANY => $firstCompanyUserTransfer->getFkCompany(),
            CompanyUserTransfer::FK_COMPANY_BUSINESS_UNIT => $firstCompanyUserTransfer->getFkCompanyBusinessUnit(),
        ]);

        $customerTransfer = $this->tester->haveCustomer();
        $quoteTransfer = $this->tester->havePersistentQuote([
            QuoteTransfer::CUSTOMER => $customerTransfer,
            QuoteTransfer::IS_LOCKED => static::VALUE_IS_QUOTE_LOCKED_FALSE,
        ]);
        $resourceShareTransfer = $this->tester->createResourceShare([
            ResourceShareDataTransfer::SHARE_OPTION => static::PERMISSION_GROUP_READ_ONLY,
            ResourceShareDataTransfer::OWNER_COMPANY_USER_ID => $secondCompanyUserTransfer->getIdCompanyUser(),
            ResourceShareDataTransfer::OWNER_COMPANY_BUSINESS_UNIT_ID => $secondCompanyUserTransfer->getFkCompanyBusinessUnit(),
            ResourceShareDataTransfer::ID_QUOTE => $quoteTransfer->getIdQuote(),
        ]);

        $resourceShareRequestTransfer = (new ResourceShareRequestTransfer())
            ->setCustomer($firstCompanyUserTransfer->getCustomer())
            ->setResourceShare($resourceShareTransfer);

        // Act
        $resourceShareResponseTransfer = $this->tester->getFacade()->shareCartByResourceShareRequest($resourceShareRequestTransfer);

        // Assert
        $this->assertTrue($resourceShareResponseTransfer->getIsSuccessful());
        $this->assertNotNull($resourceShareResponseTransfer->getResourceShare());
    }

    /**
     * @return void
     */
    public function testShareCartByResourceShareRequestShouldShareCartWithFullAccessWhenAllParametersAreCorrect(): void
    {
        // Arrange
        $firstCompanyUserTransfer = $this->tester->createCompanyUserTransfer();
        $secondCompanyUserTransfer = $this->tester->createCompanyUserTransfer([
            CompanyUserTransfer::FK_COMPANY => $firstCompanyUserTransfer->getCompany()->getIdCompany(),
            CompanyUserTransfer::FK_COMPANY_BUSINESS_UNIT => $firstCompanyUserTransfer->getCompanyBusinessUnit()->getIdCompanyBusinessUnit(),
        ]);

        $customerTransfer = $this->tester->haveCustomer();
        $quoteTransfer = $this->tester->havePersistentQuote([
            QuoteTransfer::CUSTOMER => $customerTransfer,
            QuoteTransfer::IS_LOCKED => static::VALUE_IS_QUOTE_LOCKED_FALSE,
        ]);

        $resourceShareTransfer = $this->tester->createResourceShare([
            ResourceShareDataTransfer::SHARE_OPTION => static::PERMISSION_GROUP_FULL_ACCESS,
            ResourceShareDataTransfer::OWNER_COMPANY_USER_ID => $secondCompanyUserTransfer->getIdCompanyUser(),
            ResourceShareDataTransfer::OWNER_COMPANY_BUSINESS_UNIT_ID => $secondCompanyUserTransfer->getFkCompanyBusinessUnit(),
            ResourceShareDataTransfer::ID_QUOTE => $quoteTransfer->getIdQuote(),
        ]);

        $resourceShareRequestTransfer = (new ResourceShareRequestTransfer())
            ->setCustomer($firstCompanyUserTransfer->getCustomer())
            ->setResourceShare($resourceShareTransfer);

        // Act
        $resourceShareResponseTransfer = $this->tester->getFacade()->shareCartByResourceShareRequest($resourceShareRequestTransfer);

        // Assert
        $this->assertTrue($resourceShareResponseTransfer->getIsSuccessful());
        $this->assertNotNull($resourceShareResponseTransfer->getResourceShare());
    }

    /**
     * @return void
     */
    public function testShareCartByResourceShareRequestShouldReturnErrorMessageWhenWhenQuoteDoesNotExistsAnyMore(): void
    {
        // Arrange
        $firstCompanyUserTransfer = $this->tester->createCompanyUserTransfer();
        $secondCompanyUserTransfer = $this->tester->createCompanyUserTransfer([
            CompanyUserTransfer::FK_COMPANY => $firstCompanyUserTransfer->getCompany()->getIdCompany(),
            CompanyUserTransfer::FK_COMPANY_BUSINESS_UNIT => $firstCompanyUserTransfer->getCompanyBusinessUnit()->getIdCompanyBusinessUnit(),
        ]);

        $resourceShareTransfer = $this->tester->createResourceShare([
            ResourceShareDataTransfer::SHARE_OPTION => static::PERMISSION_GROUP_FULL_ACCESS,
            ResourceShareDataTransfer::OWNER_COMPANY_USER_ID => $secondCompanyUserTransfer->getIdCompanyUser(),
            ResourceShareDataTransfer::OWNER_COMPANY_BUSINESS_UNIT_ID => $secondCompanyUserTransfer->getFkCompanyBusinessUnit(),
            ResourceShareDataTransfer::ID_QUOTE => 0,
        ]);

        $resourceShareRequestTransfer = (new ResourceShareRequestTransfer())
            ->setCustomer($firstCompanyUserTransfer->getCustomer())
            ->setResourceShare($resourceShareTransfer);

        // Act
        $resourceShareResponseTransfer = $this->tester->getFacade()->shareCartByResourceShareRequest($resourceShareRequestTransfer);

        // Assert
        $this->assertFalse($resourceShareResponseTransfer->getIsSuccessful());
        $this->tester->hasResourceShareResponseTransferErrorMessage(
            $resourceShareResponseTransfer,
            static::GLOSSARY_KEY_QUOTE_IS_NOT_AVAILABLE
        );
    }
}
