<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\PriceProductScheduleGui\Communication\Table;

use Orm\Zed\PriceProductSchedule\Persistence\SpyPriceProductScheduleQuery;
use Spryker\Service\UtilText\Model\Url\Url;
use Spryker\Zed\Gui\Communication\Table\TableConfiguration;
use Spryker\Zed\PriceProductScheduleGui\Communication\Controller\IndexController;
use Spryker\Zed\PriceProductScheduleGui\Dependency\Facade\PriceProductScheduleGuiToStoreFacadeInterface;

class PriceProductScheduleAbstractTable extends AbstractScheduledPriceTable
{
    protected const TABLE_IDENTIFIER = 'price-product-schedule-abstract:';

    /**
     * @var int
     */
    protected $fkProductAbstract;

    /**
     * @var int
     */
    protected $fkPriceType;

    /**
     * @param int $fkProductAbstract
     * @param int $fkPriceType
     * @param \Spryker\Zed\PriceProductScheduleGui\Dependency\Facade\PriceProductScheduleGuiToStoreFacadeInterface $storeFacade
     */
    public function __construct(int $fkProductAbstract, int $fkPriceType, PriceProductScheduleGuiToStoreFacadeInterface $storeFacade)
    {
        parent::__construct($storeFacade);
        $this->fkProductAbstract = $fkProductAbstract;
        $this->fkPriceType = $fkPriceType;
        $this->baseUrl = '/';
        $this->defaultUrl = Url::generate('price-product-schedule-gui/index/table', [
            IndexController::REQUEST_KEY_ID_PRODUCT_ABSTRACT => $fkProductAbstract,
            IndexController::REQUEST_KEY_ID_PRICE_TYPE => $fkPriceType,
        ])->build();
    }

    /**
     * @param \Spryker\Zed\Gui\Communication\Table\TableConfiguration $config
     *
     * @return \Spryker\Zed\Gui\Communication\Table\TableConfiguration
     */
    protected function configure(TableConfiguration $config): TableConfiguration
    {
        $config = parent::configure($config);
        $this->setTableIdentifier(static::TABLE_IDENTIFIER . $this->fkProductAbstract . ':' . $this->fkPriceType);

        return $config;
    }

    /**
     * @return \Orm\Zed\PriceProductSchedule\Persistence\SpyPriceProductScheduleQuery
     */
    protected function prepareQuery(): SpyPriceProductScheduleQuery
    {
        return (new SpyPriceProductScheduleQuery())
            ->leftJoinWithCurrency()
            ->leftJoinWithStore()
            ->filterByFkProductAbstract($this->fkProductAbstract)
            ->filterByFkPriceType($this->fkPriceType);
    }
}
