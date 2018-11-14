<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyUserInvitation\Persistence;

use Orm\Zed\CompanyUserInvitation\Persistence\SpyCompanyUserInvitationQuery;
use Orm\Zed\CompanyUserInvitation\Persistence\SpyCompanyUserInvitationStatusQuery;
use Spryker\Zed\CompanyUserInvitation\Persistence\Mapper\CompanyUserInvitationMapper;
use Spryker\Zed\CompanyUserInvitation\Persistence\Mapper\CompanyUserInvitationMapperInterface;
use Spryker\Zed\Kernel\Persistence\AbstractPersistenceFactory;

/**
 * @method \Spryker\Zed\CompanyUserInvitation\CompanyUserInvitationConfig getConfig()
 * @method \Spryker\Zed\CompanyUserInvitation\Persistence\CompanyUserInvitationEntityManagerInterface getEntityManager()
 * @method \Spryker\Zed\CompanyUserInvitation\Persistence\CompanyUserInvitationRepositoryInterface getRepository()
 */
class CompanyUserInvitationPersistenceFactory extends AbstractPersistenceFactory
{
    /**
     * @return \Orm\Zed\CompanyUserInvitation\Persistence\SpyCompanyUserInvitationQuery
     */
    public function createCompanyUserInvitationQuery()
    {
        return SpyCompanyUserInvitationQuery::create();
    }

    /**
     * @return \Orm\Zed\CompanyUserInvitation\Persistence\SpyCompanyUserInvitationStatusQuery
     */
    public function createCompanyUserInvitationStatusQuery()
    {
        return SpyCompanyUserInvitationStatusQuery::create();
    }

    /**
     * @return \Spryker\Zed\CompanyUserInvitation\Persistence\Mapper\CompanyUserInvitationMapperInterface
     */
    public function createCompanyUserInvitationMapper(): CompanyUserInvitationMapperInterface
    {
        return new CompanyUserInvitationMapper();
    }
}
