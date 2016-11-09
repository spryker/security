<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Unit\Spryker\Zed\Customer\Business\Customer;

use Codeception\TestCase\Test;
use Generated\Shared\Transfer\CustomerTransfer;
use Spryker\Zed\Customer\Business\Customer\Customer;
use Spryker\Zed\Customer\Business\Exception\CustomerNotFoundException;
use Spryker\Zed\Customer\Business\ReferenceGenerator\CustomerReferenceGeneratorInterface;
use Spryker\Zed\Customer\CustomerConfig;
use Spryker\Zed\Customer\Persistence\CustomerQueryContainer;

/**
 * @group Unit
 * @group Spryker
 * @group Zed
 * @group Customer
 * @group Business
 * @group Customer
 * @group CustomerTest
 */
class CustomerTest extends Test
{

    /**
     * @var \Spryker\Zed\Customer\Business\Customer\Customer
     */
    protected $customer;

    /**
     * @return void
     */
    public function setUp()
    {
        $queryContainer = new CustomerQueryContainer();
        $customerReferenceGenerator = $this->createCustomerReferenceGeneratorMock();
        $customerConfig = new CustomerConfig();
        $this->customer = new Customer($queryContainer, $customerReferenceGenerator, $customerConfig);
    }

    /**
     * @return void
     */
    public function testUpdatePasswordException()
    {
        $customerTransfer = new CustomerTransfer();

        $this->expectException(CustomerNotFoundException::class);
        $this->expectExceptionMessage('Customer not found by either ID ``, email `` or restore password key ``.');

        $this->customer->updatePassword($customerTransfer);
    }

    /**
     * @return \Spryker\Zed\Customer\Business\ReferenceGenerator\CustomerReferenceGeneratorInterface|\PHPUnit_Framework_MockObject_MockObject
     */
    protected function createCustomerReferenceGeneratorMock()
    {
        return $this->getMockBuilder(CustomerReferenceGeneratorInterface::class)->getMock();
    }

}