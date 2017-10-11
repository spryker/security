<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */
namespace Spryker\Zed\CustomerUserConnectorGui\Dependency\QueryContainer;

class CustomerUserConnectorGuiToCustomerQueryContainerBridge implements CustomerUserConnectorGuiToCustomerQueryContainerInterface
{

    /**
     * @var \Spryker\Zed\Customer\Persistence\CustomerQueryContainerInterface
     */
    protected $customerQueryContainer;

    /**
     * @param \Spryker\Zed\Customer\Persistence\CustomerQueryContainerInterface $customerQueryContainer
     */
    public function __construct($customerQueryContainer)
    {
        $this->customerQueryContainer = $customerQueryContainer;
    }

    /**
     * @param int $id
     *
     * @return \Orm\Zed\Customer\Persistence\SpyCustomerQuery
     */
    public function queryCustomerById($id)
    {
        return $this->customerQueryContainer->queryCustomerById($id);
    }

    /**
     * @return \Orm\Zed\Customer\Persistence\SpyCustomerQuery
     */
    public function queryCustomers()
    {
        return $this->customerQueryContainer->queryCustomers();
    }

}
