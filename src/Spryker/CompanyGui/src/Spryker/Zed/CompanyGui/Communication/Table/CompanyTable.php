<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\CompanyGui\Communication\Table;

use Orm\Zed\Company\Persistence\Map\SpyCompanyTableMap;
use Orm\Zed\Company\Persistence\SpyCompanyQuery;
use Spryker\Service\UtilText\Model\Url\Url;
use Spryker\Zed\CompanyGui\Communication\Table\PluginExecutor\CompanyTablePluginExecutorInterface;
use Spryker\Zed\Gui\Communication\Table\AbstractTable;
use Spryker\Zed\Gui\Communication\Table\TableConfiguration;

class CompanyTable extends AbstractTable
{
    public const COL_ID_COMPANY = SpyCompanyTableMap::COL_ID_COMPANY;
    public const COL_NAME = SpyCompanyTableMap::COL_NAME;
    public const COL_IS_ACTIVE = SpyCompanyTableMap::COL_IS_ACTIVE;
    public const COL_STATUS = SpyCompanyTableMap::COL_STATUS;
    public const COL_ACTIONS = 'actions';

    public const REQUEST_ID_COMPANY = 'id-company';

    public const URL_COMPANY_DEACTIVATE = '/company-gui/edit-company/deactivate';
    public const URL_COMPANY_ACTIVATE = '/company-gui/edit-company/activate';
    public const URL_COMPANY_DENY = '/company-gui/edit-company/deny';
    public const URL_COMPANY_APPROVE = '/company-gui/edit-company/approve';
    public const URL_COMPANY_EDIT = '/company-gui/edit-company/index?id-company=%d';

    /**
     * @var \Orm\Zed\Company\Persistence\SpyCompanyQuery
     */
    protected $companyQuery;

    /**
     * @var \Spryker\Zed\CompanyGui\Communication\Table\PluginExecutor\CompanyTablePluginExecutorInterface
     */
    protected $companyTablePluginsExecutor;

    /**
     * @param \Orm\Zed\Company\Persistence\SpyCompanyQuery $companyQuery
     * @param \Spryker\Zed\CompanyGui\Communication\Table\PluginExecutor\CompanyTablePluginExecutorInterface $companyTablePluginsExecutor
     */
    public function __construct(
        SpyCompanyQuery $companyQuery,
        CompanyTablePluginExecutorInterface $companyTablePluginsExecutor
    ) {
        $this->companyQuery = $companyQuery;
        $this->companyTablePluginsExecutor = $companyTablePluginsExecutor;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return \Spryker\Zed\Gui\Communication\Table\TableConfiguration
     */
    protected function configure(TableConfiguration $config)
    {
        $config = $this->setHeader($config);

        $config->addRawColumn(static::COL_IS_ACTIVE);
        $config->addRawColumn(static::COL_STATUS);
        $config->addRawColumn(static::COL_ACTIONS);

        $config->setSortable([
            static::COL_ID_COMPANY,
            static::COL_NAME,
            static::COL_STATUS,
            static::COL_IS_ACTIVE,
        ]);

        $config->setDefaultSortField(static::COL_ID_COMPANY, TableConfiguration::SORT_DESC);

        $config->setSearchable([
            static::COL_ID_COMPANY,
            static::COL_NAME,
        ]);
        $config = $this->companyTablePluginsExecutor->executeTableConfigExpanderPlugins($config);

        return $config;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return \Spryker\Zed\Gui\Communication\Table\TableConfiguration
     */
    protected function setHeader(TableConfiguration $config): TableConfiguration
    {
        $baseData = [
            static::COL_ID_COMPANY => 'Company Id',
            static::COL_NAME => 'Name',
            static::COL_IS_ACTIVE => 'Active',
            static::COL_STATUS => 'Status',
        ];

        $externalData = $this->companyTablePluginsExecutor->executeTableHeaderExpanderPlugins();

        $actions = [static::COL_ACTIONS => 'Actions'];

        $config->setHeader($baseData + $externalData + $actions);

        return $config;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return array
     */
    protected function prepareData(TableConfiguration $config)
    {
        $queryResults = $this->runQuery($this->companyQuery, $config);
        $results = [];

        foreach ($queryResults as $item) {
            $rowData = [
                static::COL_ID_COMPANY => $item[SpyCompanyTableMap::COL_ID_COMPANY],
                static::COL_NAME => $item[SpyCompanyTableMap::COL_NAME],
                static::COL_IS_ACTIVE => $this->generateStatusLabels($item),
                static::COL_STATUS => $this->generateCompanyStatusLabels($item),
                static::COL_ACTIONS => $this->buildLinks($item),
            ];
            $rowData += $this->companyTablePluginsExecutor->executeTableDataExpanderPlugins($item);
            $results[] = $rowData;
        }
        unset($queryResults);

        return $results;
    }

    /**
     * @param array $item
     *
     * @return string
     */
    protected function buildLinks(array $item)
    {
        $buttons = [];

        $buttons[] = $this->generateEditButton(
            sprintf(static::URL_COMPANY_EDIT, $item[static::COL_ID_COMPANY]),
            'Edit'
        );
        $buttons[] = $this->generateStatusChangeButton($item);
        $buttons = array_merge($buttons, $this->generateCompanyStatusChangeButton($item));

        $expandedButtons = $this->companyTablePluginsExecutor->executeTableActionExpanderPlugins($item);
        foreach ($expandedButtons as $button) {
            if (!$button->getUrl()) {
                continue;
            }
            $buttons[] = $this->generateButton(
                $button->getUrl(),
                $button->getTitle(),
                $button->getDefaultOptions(),
                $button->getCustomOptions()
            );
        }

        return implode(' ', $buttons);
    }

    /**
     * @param array $item
     *
     * @return string
     */
    protected function generateStatusChangeButton(array $item)
    {
        if ($item[SpyCompanyTableMap::COL_IS_ACTIVE]) {
            return $this->generateRemoveButton(
                Url::generate(static::URL_COMPANY_DEACTIVATE, [
                    static::REQUEST_ID_COMPANY => $item[SpyCompanyTableMap::COL_ID_COMPANY],
                ]),
                'Deactivate'
            );
        } else {
            return $this->generateViewButton(
                Url::generate(static::URL_COMPANY_ACTIVATE, [
                    static::REQUEST_ID_COMPANY => $item[SpyCompanyTableMap::COL_ID_COMPANY],
                ]),
                'Activate'
            );
        }
    }

    /**
     * @param array $item
     *
     * @return array
     */
    protected function generateCompanyStatusChangeButton(array $item)
    {
        $buttons = [];
        switch ($item[SpyCompanyTableMap::COL_STATUS]) {
            case SpyCompanyTableMap::COL_STATUS_PENDING:
                $buttons[] = $this->generateViewButton(
                    Url::generate(static::URL_COMPANY_APPROVE, [
                        static::REQUEST_ID_COMPANY => $item[SpyCompanyTableMap::COL_ID_COMPANY],
                    ]),
                    'Approve'
                );
                $buttons[] = $this->generateRemoveButton(
                    Url::generate(static::URL_COMPANY_DENY, [
                        static::REQUEST_ID_COMPANY => $item[SpyCompanyTableMap::COL_ID_COMPANY],
                    ]),
                    'Deny'
                );
                break;
            case SpyCompanyTableMap::COL_STATUS_APPROVED:
                $buttons[] = $this->generateRemoveButton(
                    Url::generate(static::URL_COMPANY_DENY, [
                        static::REQUEST_ID_COMPANY => $item[SpyCompanyTableMap::COL_ID_COMPANY],
                    ]),
                    'Deny'
                );
                break;
            case SpyCompanyTableMap::COL_STATUS_DENIED:
                $buttons[] = $this->generateViewButton(
                    Url::generate(static::URL_COMPANY_APPROVE, [
                        static::REQUEST_ID_COMPANY => $item[SpyCompanyTableMap::COL_ID_COMPANY],
                    ]),
                    'Approve'
                );
                break;
        }

        return $buttons;
    }

    /**
     * @param array $item
     *
     * @return string
     */
    protected function generateStatusLabels(array $item)
    {
        if ($item[SpyCompanyTableMap::COL_IS_ACTIVE]) {
            return '<span class="label label-info">Active</span>';
        }

        return '<span class="label label-danger">Inactive</span>';
    }

    /**
     * @param array $item
     *
     * @return string
     */
    protected function generateCompanyStatusLabels(array $item)
    {
        switch ($item[SpyCompanyTableMap::COL_STATUS]) {
            case SpyCompanyTableMap::COL_STATUS_APPROVED:
                return '<span class="label label-info">Approved</span>';
            case SpyCompanyTableMap::COL_STATUS_PENDING:
                return '<span class="label label-warning">Pending</span>';
            case SpyCompanyTableMap::COL_STATUS_DENIED:
                return '<span class="label label-danger">Denied</span>';
        }
    }
}
