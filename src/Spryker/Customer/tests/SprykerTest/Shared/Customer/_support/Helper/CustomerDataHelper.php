<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Shared\Customer\Helper;

use Codeception\Module;
use Codeception\Util\Stub;
use Generated\Shared\DataBuilder\CustomerBuilder;
use Generated\Shared\Transfer\CustomerTransfer;
use Orm\Zed\Customer\Persistence\SpyCustomerQuery;
use Spryker\Zed\Customer\Business\CustomerFacadeInterface;
use Spryker\Zed\Customer\CustomerDependencyProvider;
use Spryker\Zed\Customer\Dependency\Facade\CustomerToMailBridge;
use Spryker\Zed\Mail\Business\MailFacadeInterface;
use SprykerTest\Shared\Testify\Helper\DataCleanupHelperTrait;
use SprykerTest\Shared\Testify\Helper\DependencyHelperTrait;
use SprykerTest\Shared\Testify\Helper\LocatorHelperTrait;

class CustomerDataHelper extends Module
{
    use DependencyHelperTrait;
    use LocatorHelperTrait;
    use DataCleanupHelperTrait;

    /**
     * @param array $override
     *
     * @return \Generated\Shared\Transfer\CustomerTransfer
     */
    public function haveCustomer(array $override = []): CustomerTransfer
    {
        $customerTransfer = (new CustomerBuilder($override))
            ->withBillingAddress()
            ->withShippingAddress()
            ->build();

        $customerResponseTransfer = $this->getCustomerFacade()->registerCustomer($customerTransfer);

        $this->getDataCleanupHelper()->_addCleanup(function () use ($customerResponseTransfer) {
            $this->createCustomerQuery()
                ->filterByIdCustomer($customerResponseTransfer->getCustomerTransfer()->getIdCustomer())
                ->delete();
        });

        return $customerTransfer;
    }

    /**
     * @return \Spryker\Zed\Customer\Business\CustomerFacadeInterface
     */
    protected function getCustomerFacade(): CustomerFacadeInterface
    {
        $customerToMailBridge = new CustomerToMailBridge($this->getMailFacadeMock());
        $this->getDependencyHelper()->setDependency(CustomerDependencyProvider::FACADE_MAIL, $customerToMailBridge);

        return $this->getLocatorHelper()->getLocator()->customer()->facade();
    }

    /**
     * @return \Spryker\Zed\Mail\Business\MailFacadeInterface
     */
    protected function getMailFacadeMock()
    {
        /** @var \Spryker\Zed\Mail\Business\MailFacadeInterface $mailFacadeMock */
        $mailFacadeMock = Stub::makeEmpty(MailFacadeInterface::class);

        return $mailFacadeMock;
    }

    /**
     * @return \Orm\Zed\Customer\Persistence\SpyCustomerQuery
     */
    protected function createCustomerQuery(): SpyCustomerQuery
    {
        return SpyCustomerQuery::create();
    }
}
