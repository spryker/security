<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyBusinessUnit\Business\CompanyBusinessUnitCreator;

use Generated\Shared\Transfer\CompanyBusinessUnitResponseTransfer;
use Generated\Shared\Transfer\CompanyBusinessUnitTransfer;
use Generated\Shared\Transfer\CompanyResponseTransfer;
use Generated\Shared\Transfer\ResponseMessageTransfer;
use Spryker\Zed\CompanyBusinessUnit\Business\CompanyBusinessUnitPluginExecutor\CompanyBusinessUnitPluginExecutorInterface;
use Spryker\Zed\CompanyBusinessUnit\CompanyBusinessUnitConfig;
use Spryker\Zed\CompanyBusinessUnit\Persistence\CompanyBusinessUnitEntityManagerInterface;
use Spryker\Zed\Kernel\Persistence\EntityManager\TransactionTrait;

class CompanyBusinessUnitCreator implements CompanyBusinessUnitCreatorInterface
{
    use TransactionTrait;

    protected const MESSAGE_BUSINESS_UNIT_CREATE_SUCCESS = 'message.business_unit.create';

    /**
     * @var \Spryker\Zed\CompanyBusinessUnit\Persistence\CompanyBusinessUnitEntityManagerInterface
     */
    protected $companyBusinessUnitEntityManager;

    /**
     * @var \Spryker\Zed\CompanyBusinessUnit\CompanyBusinessUnitConfig
     */
    protected $companyBusinessUnitConfig;

    /**
     * @var \Spryker\Zed\CompanyBusinessUnit\Business\CompanyBusinessUnitPluginExecutor\CompanyBusinessUnitPluginExecutorInterface
     */
    protected $companyBusinessUnitPluginExecutor;

    /**
     * @param \Spryker\Zed\CompanyBusinessUnit\Persistence\CompanyBusinessUnitEntityManagerInterface $companyBusinessUnitEntityManager
     * @param \Spryker\Zed\CompanyBusinessUnit\CompanyBusinessUnitConfig $companyBusinessUnitConfig
     * @param \Spryker\Zed\CompanyBusinessUnit\Business\CompanyBusinessUnitPluginExecutor\CompanyBusinessUnitPluginExecutorInterface $pluginExecutor
     */
    public function __construct(
        CompanyBusinessUnitEntityManagerInterface $companyBusinessUnitEntityManager,
        CompanyBusinessUnitConfig $companyBusinessUnitConfig,
        CompanyBusinessUnitPluginExecutorInterface $pluginExecutor
    ) {
        $this->companyBusinessUnitEntityManager = $companyBusinessUnitEntityManager;
        $this->companyBusinessUnitConfig = $companyBusinessUnitConfig;
        $this->companyBusinessUnitPluginExecutor = $pluginExecutor;
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitTransfer $companyBusinessUnitTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitResponseTransfer
     */
    public function create(CompanyBusinessUnitTransfer $companyBusinessUnitTransfer): CompanyBusinessUnitResponseTransfer
    {
        $companyBusinessUnitResponseTransfer = (new CompanyBusinessUnitResponseTransfer())
            ->setCompanyBusinessUnitTransfer($companyBusinessUnitTransfer)
            ->setIsSuccessful(true)
            ->addMessage((new ResponseMessageTransfer())->setText(static::MESSAGE_BUSINESS_UNIT_CREATE_SUCCESS));

        return $this->getTransactionHandler()->handleTransaction(function () use ($companyBusinessUnitResponseTransfer) {
            return $this->executeCreateTransaction($companyBusinessUnitResponseTransfer);
        });
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyResponseTransfer $companyResponseTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyResponseTransfer
     */
    public function createByCompany(CompanyResponseTransfer $companyResponseTransfer): CompanyResponseTransfer
    {
        $companyTransfer = $companyResponseTransfer->getCompanyTransfer();

        $companyBusinessUnitTransfer = (new CompanyBusinessUnitTransfer())
                ->setFkCompany($companyTransfer->getIdCompany())
                ->setName($this->companyBusinessUnitConfig->getCompanyBusinessUnitDefaultName());

        $companyBusinessUnitResponseTransfer = $this->create($companyBusinessUnitTransfer);

        if ($companyBusinessUnitResponseTransfer->getIsSuccessful()) {
            return $companyResponseTransfer;
        }

        foreach ($companyBusinessUnitResponseTransfer->getMessages() as $messageTransfer) {
            $companyResponseTransfer->addMessage($messageTransfer);
        }

        return $companyResponseTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\CompanyBusinessUnitResponseTransfer $companyBusinessUnitResponseTransfer
     *
     * @return \Generated\Shared\Transfer\CompanyBusinessUnitResponseTransfer
     */
    protected function executeCreateTransaction(CompanyBusinessUnitResponseTransfer $companyBusinessUnitResponseTransfer): CompanyBusinessUnitResponseTransfer
    {
        $companyBusinessUnitTransfer = $companyBusinessUnitResponseTransfer->getCompanyBusinessUnitTransfer();
        $companyBusinessUnitTransfer = $this->companyBusinessUnitEntityManager->saveCompanyBusinessUnit($companyBusinessUnitTransfer);
        $companyBusinessUnitTransfer = $this->companyBusinessUnitPluginExecutor->executePostSavePlugins($companyBusinessUnitTransfer);
        $companyBusinessUnitResponseTransfer->setCompanyBusinessUnitTransfer($companyBusinessUnitTransfer);

        return $companyBusinessUnitResponseTransfer;
    }
}
