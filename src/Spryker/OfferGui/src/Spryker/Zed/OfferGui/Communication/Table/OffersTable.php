<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\OfferGui\Communication\Table;

use Orm\Zed\Sales\Persistence\Map\SpySalesOrderTableMap;
use Spryker\Service\UtilText\Model\Url\Url;
use Spryker\Zed\Gui\Communication\Table\AbstractTable;
use Spryker\Zed\Gui\Communication\Table\TableConfiguration;
use Spryker\Zed\OfferGui\Dependency\Facade\OfferGuiToCustomerFacadeInterface;
use Spryker\Zed\OfferGui\Dependency\Facade\OfferGuiToMoneyFacadeInterface;
use Spryker\Zed\OfferGui\Dependency\Service\OfferGuiToUtilDateTimeServiceInterface;
use Spryker\Zed\OfferGui\Dependency\Service\OfferGuiToUtilSanitizeServiceInterface;

class OffersTable extends AbstractTable
{
    const URL = 'URL';
    const ID_ORDER_ITEM_PROCESS = 'id-order-item-process';
    const ID_ORDER_ITEM_STATE = 'id-order-item-state';
    const FILTER = 'filter';
    const URL_OFFER_GUI_EDIT = '/offer-gui/edit/';
    const URL_OFFER_GUI_VIEW_DETAILS = '/offer-gui/view/details';
    const URL_OFFER_GUI_PRINT_VERSION = '/offer-gui/offer';
    const PARAM_ID_SALES_ORDER = 'id-sales-order';
    const GRAND_TOTAL = 'GrandTotal';
    const ITEM_STATE_NAMES_CSV = 'item_state_names_csv';
    const NUMBER_OF_ORDER_ITEMS = 'number_of_order_items';

    /**
     * @var \Spryker\Zed\OfferGui\Communication\Table\OffersTableQueryBuilderInterface
     */
    protected $queryBuilder;

    /**
     * @var \Spryker\Zed\OfferGui\Dependency\Service\OfferGuiToUtilDateTimeServiceInterface
     */
    protected $utilDateTimeService;

    /**
     * @var \Spryker\Zed\OfferGui\Dependency\Facade\OfferGuiToMoneyFacadeInterface
     */
    protected $moneyFacade;

    /**
     * @var \Spryker\Zed\OfferGui\Dependency\Service\OfferGuiToUtilSanitizeServiceInterface
     */
    protected $sanitizeService;

    /**
     * @var \Spryker\Zed\OfferGui\Dependency\Facade\OfferGuiToCustomerFacadeInterface
     */
    protected $customerFacade;

    /**
     * @param \Spryker\Zed\OfferGui\Communication\Table\OffersTableQueryBuilderInterface $queryBuilder
     * @param \Spryker\Zed\OfferGui\Dependency\Facade\OfferGuiToMoneyFacadeInterface $moneyFacade
     * @param \Spryker\Zed\OfferGui\Dependency\Facade\OfferGuiToCustomerFacadeInterface $customerFacade
     * @param \Spryker\Zed\OfferGui\Dependency\Service\OfferGuiToUtilSanitizeServiceInterface $sanitizeService
     * @param \Spryker\Zed\OfferGui\Dependency\Service\OfferGuiToUtilDateTimeServiceInterface $utilDateTimeService
     */
    public function __construct(
        OffersTableQueryBuilderInterface $queryBuilder,
        OfferGuiToMoneyFacadeInterface $moneyFacade,
        OfferGuiToCustomerFacadeInterface $customerFacade,
        OfferGuiToUtilSanitizeServiceInterface $sanitizeService,
        OfferGuiToUtilDateTimeServiceInterface $utilDateTimeService
    ) {
        $this->queryBuilder = $queryBuilder;
        $this->moneyFacade = $moneyFacade;
        $this->sanitizeService = $sanitizeService;
        $this->utilDateTimeService = $utilDateTimeService;
        $this->customerFacade = $customerFacade;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return \Spryker\Zed\Gui\Communication\Table\TableConfiguration
     */
    protected function configure(TableConfiguration $config)
    {
        $config->setHeader($this->getHeaderFields());
        $config->setSearchable($this->getSearchableFields());
        $config->setSortable($this->getSortableFields());

        $config->addRawColumn(static::URL);
        $config->addRawColumn(SpySalesOrderTableMap::COL_CUSTOMER_REFERENCE);
        $config->addRawColumn(SpySalesOrderTableMap::COL_EMAIL);

        $config->setDefaultSortField(SpySalesOrderTableMap::COL_ID_SALES_ORDER, TableConfiguration::SORT_DESC);

        $this->persistFilters($config);

        return $config;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return array
     */
    protected function prepareData(TableConfiguration $config)
    {
        $query = $this->queryBuilder->buildQuery();
        $queryResults = $this->runQuery($query, $config);

        return $this->formatQueryData($queryResults);
    }

    /**
     * @param array $item
     *
     * @return int
     */
    protected function getGrandTotal(array $item)
    {
        $currencyIsoCode = $item[SpySalesOrderTableMap::COL_CURRENCY_ISO_CODE];
        if (!isset($item[OffersTableQueryBuilder::FIELD_ORDER_GRAND_TOTAL])) {
            return $this->formatPrice(0, true, $currencyIsoCode);
        }

        return $this->formatPrice((int)$item[OffersTableQueryBuilder::FIELD_ORDER_GRAND_TOTAL], true, $currencyIsoCode);
    }

    /**
     * @param array $item
     *
     * @return string
     */
    protected function formatCustomer(array $item)
    {
        $salutation = $item[SpySalesOrderTableMap::COL_SALUTATION];

        $customer = sprintf(
            '%s%s %s',
            $salutation ? $salutation . ' ' : '',
            $item[SpySalesOrderTableMap::COL_FIRST_NAME],
            $item[SpySalesOrderTableMap::COL_LAST_NAME]
        );

        $customer = $this->sanitizeService->escapeHtml($customer);

        if (isset($item[SpySalesOrderTableMap::COL_CUSTOMER_REFERENCE])) {
            $customerTransfer = $this->customerFacade->findCustomerByReference(
                $item[SpySalesOrderTableMap::COL_CUSTOMER_REFERENCE]
            );

            if (!$customerTransfer) {
                return $customer;
            }
            $url = Url::generate('/customer/view', [
                'id-customer' => $customerTransfer->getIdCustomer(),
            ]);
            $customer = '<a href="' . $url . '">' . $customer . '</a>';
        }

        return $customer;
    }

    /**
     * @param string $emailAddress
     *
     * @return string
     */
    protected function formatEmailAddress($emailAddress)
    {
        $escapedEmailAddress = $this->sanitizeService->escapeHtml($emailAddress);
        $emailAddressLink = sprintf('<a href="mailto:%1$s">%1$s</a>', $escapedEmailAddress);

        return $emailAddressLink;
    }

    /**
     * @param string $itemStateNamesCsv
     *
     * @return string
     */
    protected function groupItemStateNames($itemStateNamesCsv)
    {
        $itemStateNames = explode(',', $itemStateNamesCsv);
        $itemStateNames = array_map('trim', $itemStateNames);
        $distinctItemStateNames = array_unique($itemStateNames);
        $distinctItemStateNamesCsv = implode(', ', $distinctItemStateNames);

        return $distinctItemStateNamesCsv;
    }

    /**
     * @param int $value
     * @param bool $includeSymbol
     * @param null|string $currencyIsoCode
     *
     * @return string
     */
    protected function formatPrice($value, $includeSymbol = true, $currencyIsoCode = null)
    {
        $moneyTransfer = $this->moneyFacade->fromInteger($value, $currencyIsoCode);

        if ($includeSymbol) {
            return $this->moneyFacade->formatWithSymbol($moneyTransfer);
        }

        return $this->moneyFacade->formatWithoutSymbol($moneyTransfer);
    }

    /**
     * @param array $item
     *
     * @return array
     */
    protected function createActionUrls(array $item)
    {
        $urls = [];

        $urls[] = $this->generateEditButton(
            Url::generate(static::URL_OFFER_GUI_EDIT, [
                static::PARAM_ID_SALES_ORDER => $item[SpySalesOrderTableMap::COL_ID_SALES_ORDER],
            ]),
            'Edit'
        );

        $urls[] = $this->generateViewButton(
            Url::generate(static::URL_OFFER_GUI_VIEW_DETAILS, [
                static::PARAM_ID_SALES_ORDER => $item[SpySalesOrderTableMap::COL_ID_SALES_ORDER],
            ]),
            'View'
        );

        $urls[] = $this->generateViewButton(
            Url::generate(static::URL_OFFER_GUI_PRINT_VERSION, [
                static::PARAM_ID_SALES_ORDER => $item[SpySalesOrderTableMap::COL_ID_SALES_ORDER],
            ]),
            'Print version',
            ['target' => '_blank']
        );

        return $urls;
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return void
     */
    protected function persistFilters(TableConfiguration $config)
    {
        $idOrderItemProcess = $this->request->query->getInt(static::ID_ORDER_ITEM_PROCESS);
        if ($idOrderItemProcess) {
            $idOrderItemState = $this->request->query->getInt(static::ID_ORDER_ITEM_STATE);
            $filter = $this->request->query->get(static::FILTER);

            $config->setUrl(
                sprintf(
                    'table?id-order-item-process=%s&id-order-item-state=%s&filter=%s',
                    $idOrderItemProcess,
                    $idOrderItemState,
                    $filter
                )
            );
        }
    }

    /**
     * @return array
     */
    protected function getHeaderFields()
    {
        return [
            SpySalesOrderTableMap::COL_ID_SALES_ORDER => '#',
            SpySalesOrderTableMap::COL_ORDER_REFERENCE => 'Order Reference',
            SpySalesOrderTableMap::COL_CREATED_AT => 'Created',
            SpySalesOrderTableMap::COL_CUSTOMER_REFERENCE => 'Customer Full Name',
            SpySalesOrderTableMap::COL_EMAIL => 'Email',
            static::ITEM_STATE_NAMES_CSV => 'Order State',
            static::GRAND_TOTAL => 'GrandTotal',
            static::NUMBER_OF_ORDER_ITEMS => 'Number of Items',
            static::URL => 'Actions',
        ];
    }

    /**
     * @return array
     */
    protected function getSearchableFields()
    {
        return [
            SpySalesOrderTableMap::COL_ID_SALES_ORDER,
            SpySalesOrderTableMap::COL_ORDER_REFERENCE,
            SpySalesOrderTableMap::COL_CREATED_AT,
            SpySalesOrderTableMap::COL_EMAIL,
        ];
    }

    /**
     * @return array
     */
    protected function getSortableFields()
    {
        return [
            SpySalesOrderTableMap::COL_ID_SALES_ORDER,
            SpySalesOrderTableMap::COL_ORDER_REFERENCE,
            SpySalesOrderTableMap::COL_CREATED_AT,
            SpySalesOrderTableMap::COL_EMAIL,
            static::NUMBER_OF_ORDER_ITEMS,
        ];
    }

    /**
     * @param array $queryResults
     *
     * @return array
     */
    protected function formatQueryData(array $queryResults)
    {
        $results = [];
        foreach ($queryResults as $item) {
            $results[] = [
                SpySalesOrderTableMap::COL_ID_SALES_ORDER => $item[SpySalesOrderTableMap::COL_ID_SALES_ORDER],
                SpySalesOrderTableMap::COL_ORDER_REFERENCE => $item[SpySalesOrderTableMap::COL_ORDER_REFERENCE],
                SpySalesOrderTableMap::COL_CREATED_AT => $this->utilDateTimeService->formatDateTime($item[SpySalesOrderTableMap::COL_CREATED_AT]),
                SpySalesOrderTableMap::COL_CUSTOMER_REFERENCE => $this->formatCustomer($item),
                SpySalesOrderTableMap::COL_EMAIL => $this->formatEmailAddress($item[SpySalesOrderTableMap::COL_EMAIL]),
                static::ITEM_STATE_NAMES_CSV => $this->groupItemStateNames($item[OffersTableQueryBuilder::FIELD_ITEM_STATE_NAMES_CSV]),
                static::GRAND_TOTAL => $this->getGrandTotal($item),
                static::NUMBER_OF_ORDER_ITEMS => $item[OffersTableQueryBuilder::FIELD_NUMBER_OF_ORDER_ITEMS],
                static::URL => implode(' ', $this->createActionUrls($item)),
            ];
        }

        return $results;
    }
}
