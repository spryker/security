<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Company\Business;

use Spryker\Zed\Company\Business\Model\Company;
use Spryker\Zed\Company\Business\Model\CompanyInterface;
use Spryker\Zed\Company\Business\Model\CompanyPluginExecutor;
use Spryker\Zed\Company\Business\Model\CompanyPluginExecutorInterface;
use Spryker\Zed\Company\Business\Model\CompanyStoreRelationReader;
use Spryker\Zed\Company\Business\Model\CompanyStoreRelationReaderInterface;
use Spryker\Zed\Company\Business\Model\CompanyStoreRelationWriter;
use Spryker\Zed\Company\Business\Model\CompanyStoreRelationWriterInterface;
use Spryker\Zed\Company\CompanyDependencyProvider;
use Spryker\Zed\Company\Dependency\Facade\CompanyToStoreFacadeInterface;
use Spryker\Zed\Kernel\Business\AbstractBusinessFactory;

/**
 * @method \Spryker\Zed\Company\Persistence\CompanyRepositoryInterface getRepository()
 * @method \Spryker\Zed\Company\Persistence\CompanyEntityManagerInterface getEntityManager()
 */
class CompanyBusinessFactory extends AbstractBusinessFactory
{
    /**
     * @return \Spryker\Zed\Company\Business\Model\CompanyInterface
     */
    public function createCompany(): CompanyInterface
    {
        return new Company(
            $this->getRepository(),
            $this->getEntityManager(),
            $this->createPluginExecutor(),
            $this->createStoreRelationWriter()
        );
    }

    /**
     * @return \Spryker\Zed\Company\Dependency\Facade\CompanyToStoreFacadeInterface
     */
    public function getStoreFacade(): CompanyToStoreFacadeInterface
    {
        return $this->getProvidedDependency(CompanyDependencyProvider::FACADE_STORE);
    }

    /**
     * @return \Spryker\Zed\Company\Business\Model\CompanyStoreRelationWriterInterface
     */
    protected function createStoreRelationWriter(): CompanyStoreRelationWriterInterface
    {
        return new CompanyStoreRelationWriter(
            $this->getEntityManager(),
            $this->createCompanyStoreRelationReader()
        );
    }

    /**
     * @return \Spryker\Zed\Company\Business\Model\CompanyStoreRelationReaderInterface
     */
    protected function createCompanyStoreRelationReader(): CompanyStoreRelationReaderInterface
    {
        return new CompanyStoreRelationReader($this->getRepository());
    }

    /**
     * @return \Spryker\Zed\Company\Business\Model\CompanyPluginExecutorInterface
     */
    protected function createPluginExecutor(): CompanyPluginExecutorInterface
    {
        return new CompanyPluginExecutor(
            $this->getCompanyPreSavePlugins(),
            $this->getCompanyPostCreatePlugins()
        );
    }

    /**
     * @return \Spryker\Zed\Company\Dependency\Plugin\CompanyPreSavePluginInterface[]
     */
    protected function getCompanyPreSavePlugins(): array
    {
        return $this->getProvidedDependency(CompanyDependencyProvider::COMPANY_PRE_SAVE_PLUGINS);
    }

    /**
     * @return \Spryker\Zed\Company\Dependency\Plugin\CompanyPostCreatePluginInterface[]
     */
    protected function getCompanyPostCreatePlugins(): array
    {
        return $this->getProvidedDependency(CompanyDependencyProvider::COMPANY_POST_CREATE_PLUGINS);
    }
}
